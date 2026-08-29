from __future__ import annotations

import argparse
import json
import os
import sys
import time
from contextlib import nullcontext
from pathlib import Path
from typing import TextIO

from aegisflow.detectors import (
    C2BeaconDetector,
    C2Config,
    DNSConfig,
    DNSDetector,
    DDoSConfig,
    DDoSDetector,
    ExfiltrationConfig,
    ExfiltrationDetector,
    ReconConfig,
    ReconDetector,
)
from aegisflow.detectors.base import Detector
from aegisflow.dns_model import DNSNgramModel
from aegisflow.dns_training import train_and_evaluate
from aegisflow.health import ReplayHealth
from aegisflow.incidents import FeedbackStore, IncidentStore, alert_from_dict
from aegisflow.ingestion.zeek_dns import read_dns_jsonl
from aegisflow.ingestion.zeek_encrypted import build_encrypted_metadata_index, read_encrypted_jsonl
from aegisflow.ingestion.zeek_jsonl import ZeekRecordError, read_conn_jsonl
from aegisflow.ingestion.zeek_runner import (
    WSLZeekRunner,
    ZeekExecutionError,
    ZeekRunner,
    ZeekUnavailableError,
)
from aegisflow.pipeline import run_dns_pipeline, run_pipeline


def _add_detection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path, help="optional JSONL alert output; defaults to stdout")
    parser.add_argument("--health-output", type=Path, help="optional JSON replay-health report")
    parser.add_argument("--detectors", default="recon,ddos", help="comma-separated: recon,ddos")
    parser.add_argument("--recon-window", "--window", dest="recon_window", type=float, default=10.0)
    parser.add_argument("--port-threshold", type=int, default=20)
    parser.add_argument("--host-threshold", type=int, default=20)
    parser.add_argument("--ddos-window", type=float, default=5.0)
    parser.add_argument("--syn-threshold", type=int, default=100)
    parser.add_argument("--min-incomplete-ratio", type=float, default=0.80)
    parser.add_argument("--udp-packet-threshold", type=int, default=1000)
    parser.add_argument("--cooldown", type=float, default=30.0)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegisflow", description="AegisFlow passive traffic replay")
    subparsers = parser.add_subparsers(dest="command", required=True)

    replay = subparsers.add_parser("replay", help="replay an existing Zeek conn.log JSONL file")
    replay.add_argument("--input", required=True, type=Path)
    _add_detection_arguments(replay)

    pcap = subparsers.add_parser("pcap", help="convert a PCAP with Zeek and run detectors")
    pcap.add_argument("--input", required=True, type=Path)
    pcap.add_argument("--zeek-output", required=True, type=Path)
    pcap.add_argument("--zeek-mode", choices=("auto", "native", "wsl"), default="auto")
    pcap.add_argument("--zeek-binary")
    pcap.add_argument("--wsl-distro")
    _add_detection_arguments(pcap)

    readiness = subparsers.add_parser("check-zeek", help="check whether Zeek is available")
    readiness.add_argument("--zeek-mode", choices=("auto", "native", "wsl"), default="auto")
    readiness.add_argument("--zeek-binary")
    readiness.add_argument("--wsl-distro")

    dns = subparsers.add_parser("dns-replay", help="replay a Zeek dns.log JSONL file")
    dns.add_argument("--input", required=True, type=Path)
    dns.add_argument("--model", type=Path)
    dns.add_argument("--output", type=Path, help="optional JSONL DNS alert output")
    dns.add_argument("--report-output", type=Path, help="optional JSON summary")
    dns.add_argument("--allow-domain", action="append", default=[])
    dns.add_argument("--window", type=float, default=60.0)
    dns.add_argument("--query-threshold", type=int, default=20)
    dns.add_argument("--unique-subdomain-threshold", type=int, default=15)
    dns.add_argument("--label-length-threshold", type=float, default=18.0)
    dns.add_argument("--entropy-threshold", type=float, default=3.5)
    dns.add_argument("--dga-threshold", type=float, default=0.50)
    dns.add_argument("--cooldown", type=float, default=120.0)

    training = subparsers.add_parser("train-dns", help="train and evaluate the DNS DGA model")
    training.add_argument("--dataset", required=True, type=Path)
    training.add_argument("--model-output", required=True, type=Path)
    training.add_argument("--metrics-output", required=True, type=Path)
    training.add_argument("--model-card-output", required=True, type=Path)

    c2 = subparsers.add_parser("c2-replay", help="replay conn.log for periodic C2-like beacons")
    c2.add_argument("--input", required=True, type=Path)
    c2.add_argument("--encrypted-input", type=Path, help="optional Zeek ssl.log or quic.log JSONL")
    c2.add_argument("--encrypted-transport", choices=("tls", "quic"), default="tls")
    c2.add_argument("--output", type=Path)
    c2.add_argument("--report-output", type=Path)
    c2.add_argument("--allow-destination", action="append", default=[])
    c2.add_argument("--window", type=float, default=300.0)
    c2.add_argument("--minimum-connections", type=int, default=6)
    c2.add_argument("--minimum-interval", type=float, default=2.0)
    c2.add_argument("--maximum-interval", type=float, default=120.0)
    c2.add_argument("--maximum-interval-cv", type=float, default=0.15)
    c2.add_argument("--maximum-size-cv", type=float, default=0.20)
    c2.add_argument("--cooldown", type=float, default=300.0)

    exfil = subparsers.add_parser("exfil-replay", help="replay conn.log for outbound exfiltration behaviour")
    exfil.add_argument("--input", required=True, type=Path)
    exfil.add_argument("--output", type=Path)
    exfil.add_argument("--report-output", type=Path)
    exfil.add_argument("--approved-backup-destination", action="append", default=[])
    exfil.add_argument("--window", type=float, default=300.0)
    exfil.add_argument("--minimum-flows", type=int, default=3)
    exfil.add_argument("--minimum-outbound-bytes", type=int, default=1_000_000)
    exfil.add_argument("--minimum-outbound-ratio", type=float, default=8.0)
    exfil.add_argument("--baseline-multiplier", type=float, default=4.0)
    exfil.add_argument("--cooldown", type=float, default=600.0)

    correlate = subparsers.add_parser("correlate-alerts", help="combine detector alerts into incidents")
    correlate.add_argument("--input", required=True, action="append", type=Path)
    correlate.add_argument("--output", required=True, type=Path)
    correlate.add_argument("--report-output", type=Path)
    correlate.add_argument("--window", type=float, default=900.0)

    feedback = subparsers.add_parser("record-feedback", help="create a validated analyst-feedback record")
    feedback.add_argument("--incident-id", required=True)
    feedback.add_argument(
        "--disposition", required=True,
        choices=("confirmed_malicious", "benign", "needs_review"),
    )
    feedback.add_argument("--analyst", required=True)
    feedback.add_argument("--notes", default="")
    feedback.add_argument("--timestamp", type=float)
    feedback.add_argument("--output", required=True, type=Path)
    return parser


def _build_zeek_runner(args: argparse.Namespace) -> ZeekRunner | WSLZeekRunner:
    mode = args.zeek_mode
    if mode == "auto":
        mode = "wsl" if os.name == "nt" else "native"
    if mode == "wsl":
        return WSLZeekRunner(
            executable=args.zeek_binary or "/opt/zeek/bin/zeek",
            distribution=args.wsl_distro,
        )
    return ZeekRunner(args.zeek_binary or "zeek")


def _build_detectors(args: argparse.Namespace) -> list[Detector]:
    requested = {item.strip().lower() for item in args.detectors.split(",") if item.strip()}
    unknown = requested - {"recon", "ddos"}
    if unknown:
        raise ValueError(f"unknown detector(s): {', '.join(sorted(unknown))}")
    detectors: list[Detector] = []
    if "recon" in requested:
        detectors.append(ReconDetector(ReconConfig(
            window_seconds=args.recon_window,
            unique_port_threshold=args.port_threshold,
            unique_host_threshold=args.host_threshold,
            cooldown_seconds=args.cooldown,
        )))
    if "ddos" in requested:
        detectors.append(DDoSDetector(DDoSConfig(
            window_seconds=args.ddos_window,
            syn_attempt_threshold=args.syn_threshold,
            min_incomplete_ratio=args.min_incomplete_ratio,
            udp_packet_threshold=args.udp_packet_threshold,
            cooldown_seconds=args.cooldown,
        )))
    if not detectors:
        raise ValueError("at least one detector must be selected")
    return detectors


def _run_jsonl(input_path: Path, args: argparse.Namespace) -> int:
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.health_output:
        args.health_output.parent.mkdir(parents=True, exist_ok=True)

    health = ReplayHealth()
    health.start()

    def observed_events():
        for event in read_conn_jsonl(input_path):
            health.record_event(event)
            yield event

    output_context = args.output.open("w", encoding="utf-8") if args.output else nullcontext(sys.stdout)
    with output_context as stream:
        output: TextIO = stream
        for alert in run_pipeline(observed_events(), _build_detectors(args)):
            output.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")
            health.record_alert(alert)
    health.finish()
    report = health.to_dict()
    if args.health_output:
        args.health_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"processed {input_path}; events={report['events_processed']}; "
        f"alerts={report['alerts_emitted']}; rate={report['processing_events_per_second']} events/s",
        file=sys.stderr,
    )
    return 0


def _run_dns(input_path: Path, args: argparse.Namespace) -> int:
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
    model = DNSNgramModel.load(args.model) if args.model else None
    detector = DNSDetector(
        DNSConfig(
            window_seconds=args.window,
            tunnel_query_threshold=args.query_threshold,
            tunnel_unique_subdomain_threshold=args.unique_subdomain_threshold,
            tunnel_label_length_threshold=args.label_length_threshold,
            tunnel_entropy_threshold=args.entropy_threshold,
            dga_probability_threshold=args.dga_threshold,
            cooldown_seconds=args.cooldown,
        ),
        model=model,
        allowlisted_base_domains=set(args.allow_domain),
    )
    events = alerts = 0

    def observed_events():
        nonlocal events
        for event in read_dns_jsonl(input_path):
            events += 1
            yield event

    output_context = args.output.open("w", encoding="utf-8") if args.output else nullcontext(sys.stdout)
    with output_context as stream:
        output: TextIO = stream
        for alert in run_dns_pipeline(observed_events(), [detector]):
            output.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")
            alerts += 1
    report = {
        "events_processed": events,
        "alerts_emitted": alerts,
        "dga_model_loaded": model is not None,
        "encrypted_dns_visibility": "not_available_from_zeek_dns_log",
    }
    if args.report_output:
        args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"processed {input_path}; dns_events={events}; alerts={alerts}", file=sys.stderr)
    return 0


def _run_c2(input_path: Path, args: argparse.Namespace) -> int:
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
    metadata_events = (
        list(read_encrypted_jsonl(args.encrypted_input, args.encrypted_transport))
        if args.encrypted_input else []
    )
    detector = C2BeaconDetector(
        C2Config(
            window_seconds=args.window,
            minimum_connections=args.minimum_connections,
            minimum_mean_interval_seconds=args.minimum_interval,
            maximum_mean_interval_seconds=args.maximum_interval,
            maximum_interval_cv=args.maximum_interval_cv,
            maximum_size_cv=args.maximum_size_cv,
            cooldown_seconds=args.cooldown,
        ),
        encrypted_metadata=build_encrypted_metadata_index(metadata_events),
        allowlisted_destinations=set(args.allow_destination),
    )
    events = alerts = 0

    def observed_events():
        nonlocal events
        for event in read_conn_jsonl(input_path):
            events += 1
            yield event

    output_context = args.output.open("w", encoding="utf-8") if args.output else nullcontext(sys.stdout)
    with output_context as stream:
        output: TextIO = stream
        for alert in run_pipeline(observed_events(), [detector]):
            output.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")
            alerts += 1
    report = {
        "events_processed": events,
        "alerts_emitted": alerts,
        "encrypted_metadata_records": len(metadata_events),
        "payload_decryption": False,
        "fingerprint_only_alerting": False,
    }
    if args.report_output:
        args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"processed {input_path}; c2_events={events}; alerts={alerts}", file=sys.stderr)
    return 0


def _run_exfil(input_path: Path, args: argparse.Namespace) -> int:
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
    detector = ExfiltrationDetector(
        ExfiltrationConfig(
            window_seconds=args.window,
            minimum_flows=args.minimum_flows,
            minimum_outbound_bytes=args.minimum_outbound_bytes,
            minimum_outbound_ratio=args.minimum_outbound_ratio,
            baseline_multiplier=args.baseline_multiplier,
            cooldown_seconds=args.cooldown,
        ),
        approved_backup_destinations=set(args.approved_backup_destination),
    )
    events = alerts = 0

    def observed_events():
        nonlocal events
        for event in read_conn_jsonl(input_path):
            events += 1
            yield event

    output_context = args.output.open("w", encoding="utf-8") if args.output else nullcontext(sys.stdout)
    with output_context as stream:
        output: TextIO = stream
        for alert in run_pipeline(observed_events(), [detector]):
            output.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")
            alerts += 1
    report = {
        "events_processed": events,
        "alerts_emitted": alerts,
        "approved_backup_destinations": sorted(set(args.approved_backup_destination)),
        "baseline_scope": "in_memory_per_source",
    }
    if args.report_output:
        args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"processed {input_path}; exfil_events={events}; alerts={alerts}", file=sys.stderr)
    return 0


def _correlate_alerts(args: argparse.Namespace) -> int:
    store = IncidentStore(args.window)
    alert_count = 0
    for path in args.input:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                    store.process(alert_from_dict(record))
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError(f"{path}: line {line_number}: invalid alert: {exc}") from exc
                alert_count += 1
    incidents = store.all()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as stream:
        for incident in incidents:
            stream.write(json.dumps(incident.to_dict(), sort_keys=True) + "\n")
    report = {
        "alerts_processed": alert_count,
        "incidents_created": len(incidents),
        "highest_risk_score": max((incident.risk_score for incident in incidents), default=0),
        "scoring": "deterministic_policy_v1",
    }
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"correlated alerts={alert_count}; incidents={len(incidents)}", file=sys.stderr)
    return 0


def _record_feedback(args: argparse.Namespace) -> int:
    store = FeedbackStore()
    feedback = store.record(
        args.incident_id,
        args.disposition,
        args.analyst,
        args.timestamp if args.timestamp is not None else time.time(),
        args.notes,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(feedback.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded feedback={feedback.feedback_id} for incident={feedback.incident_id}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "check-zeek":
            resolved = _build_zeek_runner(args).check_available()
            print(f"Zeek available: {resolved}")
            return 0
        if args.command == "replay":
            return _run_jsonl(args.input, args)
        if args.command == "dns-replay":
            return _run_dns(args.input, args)
        if args.command == "c2-replay":
            return _run_c2(args.input, args)
        if args.command == "exfil-replay":
            return _run_exfil(args.input, args)
        if args.command == "correlate-alerts":
            return _correlate_alerts(args)
        if args.command == "record-feedback":
            return _record_feedback(args)
        if args.command == "train-dns":
            metrics = train_and_evaluate(
                args.dataset, args.model_output, args.metrics_output, args.model_card_output
            )
            print(json.dumps(metrics, sort_keys=True))
            return 0
        if args.command == "pcap":
            result = _build_zeek_runner(args).process_pcap(args.input, args.zeek_output)
            return _run_jsonl(result.conn_log, args)
    except (OSError, ValueError, ZeekRecordError, ZeekUnavailableError, ZeekExecutionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
