from __future__ import annotations

import argparse
import json
import os
import sys
import time
from aegisflow.analysis_session import AnalysisProfile, AnalysisSession, DEPLOYMENT_BASELINE, UPLOAD_DEMO, STREAM_DEMO
from aegisflow.ingestion.passive_replay import prepare_replay, event_order
from aegisflow.replay_service import analyse_replay_file
from contextlib import nullcontext
from pathlib import Path
from typing import TextIO

from aegisflow.api_store import repository_from_url
from aegisflow.context_policy import load_context_policy
from aegisflow.detectors import (
    C2Config,
    DNSConfig,
    DDoSConfig,
    ExfiltrationConfig,
    ReconConfig,
)
from aegisflow.demo import demo_preflight, prepare_demo, rehearse_demo
from aegisflow.dns_model import DNSNgramModel
from aegisflow.dns_training import train_and_evaluate
from aegisflow.evaluation import evaluate_demo
from aegisflow.health import ReplayHealth
from aegisflow.incidents import FeedbackStore, IncidentStore, alert_from_dict
from aegisflow.ingestion.zeek_jsonl import ZeekRecordError
from aegisflow.ingestion.zeek_runner import (
    WSLZeekRunner,
    ZeekExecutionError,
    ZeekRunner,
    ZeekUnavailableError,
)
from aegisflow.validate_replay import validation_summary, validate_replay_file


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
    parser = argparse.ArgumentParser(prog="drastha", description="Drastha passive traffic replay")
    subparsers = parser.add_subparsers(dest="command", required=True)

    replay = subparsers.add_parser("replay", help="replay an existing Zeek conn.log JSONL file")
    replay.add_argument("--input", required=True, type=Path)
    _add_detection_arguments(replay)

    analyse = subparsers.add_parser("analyse", help="analyse mixed replay or a Zeek log directory through the shared pipeline")
    analyse.add_argument("--input", required=True, type=Path)
    analyse.add_argument("--root", type=Path, default=Path.cwd())
    analyse.add_argument("--profile", choices=("upload-demo", "stream-demo", "deployment-baseline"), default="deployment-baseline")
    analyse.add_argument("--model", type=Path)
    analyse.add_argument("--database")
    analyse.add_argument("--report-output", type=Path)

    validate = subparsers.add_parser(
        "validate-replay", help="validate replay format, schema and telemetry quality"
    )
    validate.add_argument("--input", required=True, type=Path)

    pcap = subparsers.add_parser("pcap", help="convert a PCAP with Zeek and run detectors")
    pcap.add_argument("--input", required=True, type=Path)
    pcap.add_argument("--zeek-output", required=True, type=Path)
    pcap.add_argument("--zeek-mode", choices=("auto", "native", "wsl"), default="auto")
    pcap.add_argument("--zeek-binary")
    pcap.add_argument("--wsl-distro")
    _add_detection_arguments(pcap)
    pcap.add_argument("--all-threats", action="store_true", help="analyse conn, DNS and TLS/QUIC logs through shared pipeline")
    pcap.add_argument("--profile", choices=("upload-demo", "stream-demo", "deployment-baseline"), default="deployment-baseline")
    pcap.add_argument("--model", type=Path)
    pcap.add_argument("--database")
    pcap.add_argument("--root", type=Path, default=Path.cwd())

    readiness = subparsers.add_parser("check-zeek", help="check whether Zeek is available")
    readiness.add_argument("--zeek-mode", choices=("auto", "native", "wsl"), default="auto")
    readiness.add_argument("--zeek-binary")
    readiness.add_argument("--wsl-distro")

    preflight = subparsers.add_parser(
        "demo-preflight", help="verify required files and dependencies before an SIH demo"
    )
    preflight.add_argument("--root", type=Path, default=Path.cwd())
    preflight.add_argument("--report-output", type=Path)

    prepare = subparsers.add_parser(
        "demo-prepare", help="prepare the offline SQLite demonstration database"
    )
    prepare.add_argument("--root", type=Path, default=Path.cwd())
    prepare.add_argument("--database", type=Path, default=Path("output/drastha-demo.db"))
    prepare.add_argument("--fresh", action="store_true")
    prepare.add_argument("--report-output", type=Path)

    serve = subparsers.add_parser(
        "demo-serve", help="prepare and serve the complete offline demonstration"
    )
    serve.add_argument("--root", type=Path, default=Path.cwd())
    serve.add_argument("--database", type=Path, default=Path("output/drastha-demo.db"))
    serve.add_argument("--fresh", action="store_true")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--skip-prepare", action="store_true")

    evaluation = subparsers.add_parser(
        "evaluate-demo", help="run per-threat fixture validation and detector benchmarks"
    )
    evaluation.add_argument("--root", type=Path, default=Path.cwd())
    evaluation.add_argument("--iterations", type=int, default=100)
    evaluation.add_argument(
        "--report-output", type=Path, default=Path("output/drastha_evaluation_report.json")
    )

    rehearsal = subparsers.add_parser(
        "demo-rehearse", help="verify the complete SIH demo twice from a clean local state"
    )
    rehearsal.add_argument("--root", type=Path, default=Path.cwd())
    rehearsal.add_argument(
        "--database", type=Path, default=Path("output/drastha-rehearsal.db")
    )
    rehearsal.add_argument("--evaluation-iterations", type=int, default=25)
    rehearsal.add_argument(
        "--report-output", type=Path, default=Path("output/drastha_demo_rehearsal.json")
    )

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
    exfil.add_argument(
        "--database",
        default=os.getenv("DRASTHA_DB") or os.getenv("AEGISFLOW_DB"),
        help="optional repository used to restore and save detector state",
    )
    exfil.add_argument("--state-key", default="detector.exfiltration.outbound")
    exfil.add_argument("--reset-state", action="store_true")

    correlate = subparsers.add_parser("correlate-alerts", help="combine detector alerts into incidents")
    correlate.add_argument("--input", required=True, action="append", type=Path)
    correlate.add_argument("--output", required=True, type=Path)
    correlate.add_argument("--report-output", type=Path)
    correlate.add_argument("--window", type=float, default=900.0)
    correlate.add_argument(
        "--database",
        default=os.getenv("DRASTHA_DB") or os.getenv("AEGISFLOW_DB"),
        help="optional SQLite path or PostgreSQL URL; defaults to DRASTHA_DB",
    )
    correlate.add_argument(
        "--reset-correlation-state",
        action="store_true",
        help="ignore existing repository alerts when building correlation state",
    )

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


def _build_session(args: argparse.Namespace) -> AnalysisSession:
    requested = tuple(item.strip().lower() for item in args.detectors.split(",") if item.strip())
    if set(requested) - {"recon", "ddos"} or not requested:
        raise ValueError("Select at least one detector from recon,ddos")
    profile = AnalysisProfile(
        "cli-selected-v1", enabled=requested,
        recon=ReconConfig(window_seconds=args.recon_window, unique_port_threshold=args.port_threshold,
                          unique_host_threshold=args.host_threshold, cooldown_seconds=args.cooldown),
        ddos=DDoSConfig(window_seconds=args.ddos_window, syn_attempt_threshold=args.syn_threshold,
                        min_incomplete_ratio=args.min_incomplete_ratio,
                        udp_packet_threshold=args.udp_packet_threshold, cooldown_seconds=args.cooldown))
    return AnalysisSession(profile)


def _run_jsonl(input_path: Path, args: argparse.Namespace) -> int:
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.health_output:
        args.health_output.parent.mkdir(parents=True, exist_ok=True)

    session = _build_session(args)
    prepared = prepare_replay(input_path.read_text(encoding="utf-8"), input_path.name,
                              maximum_records=None, source_kind="connection")
    health = ReplayHealth()
    health.start()

    def observed_events():
        for event in prepared.ordered_events():
            health.record_event(event)
            yield event

    output_context = args.output.open("w", encoding="utf-8") if args.output else nullcontext(sys.stdout)
    with output_context as stream:
        output: TextIO = stream
        session.process_many(observed_events())
        for alert in session.findings(complete=True):
            output.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")
            health.record_alert(alert)
    health.finish()
    report = health.to_dict()
    report["quality"] = prepared.quality.to_dict()
    report["analysis_provenance"] = session.provenance()
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
    session = AnalysisSession(AnalysisProfile("cli-dns-v1", enabled=("dns",),
        dns=DNSConfig(
            window_seconds=args.window,
            tunnel_query_threshold=args.query_threshold,
            tunnel_unique_subdomain_threshold=args.unique_subdomain_threshold,
            tunnel_label_length_threshold=args.label_length_threshold,
            tunnel_entropy_threshold=args.entropy_threshold,
            dga_probability_threshold=args.dga_threshold,
            cooldown_seconds=args.cooldown,
        ),
        allow_domains=tuple(args.allow_domain)), dns_model=model)
    prepared = prepare_replay(input_path.read_text(encoding="utf-8"), input_path.name,
                              maximum_records=None, source_kind="dns")
    events = alerts = 0

    def observed_events():
        nonlocal events
        for event in prepared.ordered_events():
            events += 1
            yield event

    output_context = args.output.open("w", encoding="utf-8") if args.output else nullcontext(sys.stdout)
    with output_context as stream:
        output: TextIO = stream
        session.process_many(observed_events())
        for alert in session.findings(complete=True):
            output.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")
            alerts += 1
    report = {
        "events_processed": events,
        "quality": prepared.quality.to_dict(),
        "analysis_provenance": session.provenance(),
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
    metadata_input = (prepare_replay(args.encrypted_input.read_text(encoding="utf-8"),
                      args.encrypted_input.name, maximum_records=None, source_kind=args.encrypted_transport)
                      if args.encrypted_input else None)
    metadata_events = metadata_input.encrypted_events if metadata_input else []
    context_policy = load_context_policy()
    session = AnalysisSession(AnalysisProfile("cli-c2-v1", enabled=("c2",),
        c2=C2Config(
            window_seconds=args.window,
            minimum_connections=args.minimum_connections,
            minimum_mean_interval_seconds=args.minimum_interval,
            maximum_mean_interval_seconds=args.maximum_interval,
            maximum_interval_cv=args.maximum_interval_cv,
            maximum_size_cv=args.maximum_size_cv,
            cooldown_seconds=args.cooldown,
        ),
        allow_destinations=tuple(args.allow_destination)), context_policy=context_policy)
    prepared = prepare_replay(input_path.read_text(encoding="utf-8"), input_path.name,
                              maximum_records=None, source_kind="connection")
    events = alerts = 0

    def observed_events():
        nonlocal events
        for event in sorted([*prepared.events, *metadata_events], key=event_order):
            if hasattr(event, "protocol"):
                events += 1
            yield event

    output_context = args.output.open("w", encoding="utf-8") if args.output else nullcontext(sys.stdout)
    with output_context as stream:
        output: TextIO = stream
        session.process_many(observed_events())
        for alert in session.findings(complete=True):
            output.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")
            alerts += 1
    report = {
        "events_processed": events,
        "quality": prepared.quality.to_dict(),
        "analysis_provenance": session.provenance(),
        "alerts_emitted": alerts,
        "encrypted_metadata_records": len(metadata_events),
        "encrypted_quality": metadata_input.quality.to_dict() if metadata_input else None,
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
    context_policy = load_context_policy()
    session = AnalysisSession(AnalysisProfile("cli-exfil-v1", enabled=("exfiltration",),
        exfiltration=ExfiltrationConfig(
            window_seconds=args.window,
            minimum_flows=args.minimum_flows,
            minimum_outbound_bytes=args.minimum_outbound_bytes,
            minimum_outbound_ratio=args.minimum_outbound_ratio,
            baseline_multiplier=args.baseline_multiplier,
            cooldown_seconds=args.cooldown,
        ),
        approved_backup_destinations=tuple(args.approved_backup_destination)), context_policy=context_policy)
    detector = session.exfiltration
    prepared = prepare_replay(input_path.read_text(encoding="utf-8"), input_path.name,
                              maximum_records=None, source_kind="connection")
    repository = repository_from_url(args.database) if args.database else None
    state_restored = False
    if repository is not None:
        if args.reset_state:
            repository.delete_runtime_state(args.state_key)
        else:
            state = repository.get_runtime_state(args.state_key)
            if state is not None:
                detector.restore_state(state)
                state_restored = True
    events = alerts = 0

    def observed_events():
        nonlocal events
        for event in prepared.ordered_events():
            events += 1
            yield event

    output_context = args.output.open("w", encoding="utf-8") if args.output else nullcontext(sys.stdout)
    with output_context as stream:
        output: TextIO = stream
        session.process_many(observed_events())
        for alert in session.findings(complete=True):
            output.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")
            alerts += 1
    if repository is not None:
        repository.put_runtime_state(args.state_key, detector.export_state(), time.time())
    report = {
        "events_processed": events,
        "quality": prepared.quality.to_dict(),
        "analysis_provenance": session.provenance(),
        "alerts_emitted": alerts,
        "approved_backup_destinations": sorted(set(args.approved_backup_destination)),
        "baseline_scope": "persistent_repository" if repository is not None else "in_memory_per_source",
        "state_restored": state_restored,
        "state_saved": repository is not None,
    }
    if args.report_output:
        args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"processed {input_path}; exfil_events={events}; alerts={alerts}", file=sys.stderr)
    return 0


def _correlate_alerts(args: argparse.Namespace) -> int:
    store = IncidentStore(args.window)
    repository = repository_from_url(args.database) if args.database else None
    restored_alert_records = (
        repository.list_alerts()
        if repository is not None and not args.reset_correlation_state
        else []
    )
    for record in restored_alert_records:
        store.process(alert_from_dict(record))
    alert_records: list[dict] = []
    for path in args.input:
        with path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                    alert = alert_from_dict(record)
                    store.process(alert)
                    alert_records.append(alert.to_dict())
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError(f"{path}: line {line_number}: invalid alert: {exc}") from exc
    incidents = store.all()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as stream:
        for incident in incidents:
            stream.write(json.dumps(incident.to_dict(), sort_keys=True) + "\n")
    report = {
        "alerts_processed": len(alert_records),
        "incidents_created": len(incidents),
        "highest_risk_score": max((incident.risk_score for incident in incidents), default=0),
        "scoring": "deterministic_policy_v1",
        "automatic_persistence": args.database is not None,
        "correlation_state_restored": bool(restored_alert_records),
        "restored_alerts": len(restored_alert_records),
    }
    if repository is not None:
        persisted = repository.import_records(
            [incident.to_dict() for incident in incidents], alert_records
        )
        report["persisted"] = persisted
        report["database_backend"] = (
            "postgresql" if str(args.database).startswith(("postgres://", "postgresql://"))
            else "sqlite"
        )
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"correlated alerts={len(alert_records)}; incidents={len(incidents)}; "
        f"persisted={args.database is not None}",
        file=sys.stderr,
    )
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


def _write_report(report: dict, path: Path | None) -> None:
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_demo_preflight(args: argparse.Namespace) -> int:
    report = demo_preflight(args.root)
    _write_report(report, args.report_output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ready"] else 2


def _run_demo_prepare(args: argparse.Namespace) -> int:
    preflight = demo_preflight(args.root)
    if not preflight["ready"]:
        raise RuntimeError("demo preflight failed; run demo-preflight for details")
    report = prepare_demo(args.root, args.database, fresh=args.fresh)
    _write_report(report, args.report_output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _run_demo_serve(args: argparse.Namespace) -> int:
    preflight = demo_preflight(args.root)
    if not preflight["ready"]:
        raise RuntimeError("demo preflight failed; run demo-preflight for details")
    project_root = args.root.resolve()
    database = args.database if args.database.is_absolute() else project_root / args.database
    if not args.skip_prepare:
        prepare_demo(project_root, database, fresh=args.fresh)
    os.environ["DRASTHA_DB"] = str(database.resolve())
    os.environ["DRASTHA_ROOT"] = str(project_root)
    os.environ["DRASTHA_WEB"] = str((project_root / "web" / "dist").resolve())
    import uvicorn
    print(f"Drastha demo ready: http://{args.host}:{args.port}", file=sys.stderr)
    uvicorn.run("aegisflow.api:app", host=args.host, port=args.port)
    return 0


def _run_demo_evaluation(args: argparse.Namespace) -> int:
    report = evaluate_demo(args.root, iterations=args.iterations)
    _write_report(report, args.report_output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_scenarios_passed"] else 1


def _run_demo_rehearsal(args: argparse.Namespace) -> int:
    report = rehearse_demo(
        args.root, args.database, evaluation_iterations=args.evaluation_iterations
    )
    _write_report(report, args.report_output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ready"] else 1


class _ReportOnlyRepository:
    def import_records(self, incidents, alerts, feedback=()):
        # No --database means a report-only CLI run, not implicit persistence.
        return {"incidents": 0, "alerts": 0, "feedback": 0}


def _analyse_shared(path, args):
    profiles = {"upload-demo": UPLOAD_DEMO, "stream-demo": STREAM_DEMO,
                "deployment-baseline": DEPLOYMENT_BASELINE}
    repository = repository_from_url(args.database) if args.database else _ReportOnlyRepository()
    return analyse_replay_file(path, repository, root=args.root, profile=profiles[args.profile], model_path=args.model)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "analyse":
            report = _analyse_shared(args.input, args)
            _write_report(report, args.report_output)
            print(json.dumps(report, sort_keys=True))
            return 0
        if args.command == "demo-preflight":
            return _run_demo_preflight(args)
        if args.command == "demo-prepare":
            return _run_demo_prepare(args)
        if args.command == "demo-serve":
            return _run_demo_serve(args)
        if args.command == "evaluate-demo":
            return _run_demo_evaluation(args)
        if args.command == "demo-rehearse":
            return _run_demo_rehearsal(args)
        if args.command == "check-zeek":
            resolved = _build_zeek_runner(args).check_available()
            print(f"Zeek available: {resolved}")
            return 0
        if args.command == "replay":
            return _run_jsonl(args.input, args)
        if args.command == "validate-replay":
            summary = validation_summary(validate_replay_file(args.input))
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0 if summary["quality"]["status"] == "healthy" else 1
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
            if args.all_threats:
                report = _analyse_shared(result.output_directory, args)
                _write_report(report, args.health_output)
                output_context = args.output.open("w", encoding="utf-8") if args.output else nullcontext(sys.stdout)
                with output_context as stream:
                    for alert in report["alerts"]:
                        stream.write(json.dumps(alert, sort_keys=True) + "\n")
                return 0
            return _run_jsonl(result.conn_log, args)
    except (OSError, RuntimeError, ValueError, ZeekRecordError, ZeekUnavailableError, ZeekExecutionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
