from __future__ import annotations

import platform
import statistics
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from aegisflow.detectors import (
    C2BeaconDetector,
    DDoSConfig,
    DDoSDetector,
    DNSDetector,
    ExfiltrationDetector,
    ReconConfig,
    ReconDetector,
)
from aegisflow.dns_model import DNSNgramModel
from aegisflow.ingestion.zeek_dns import read_dns_jsonl
from aegisflow.ingestion.zeek_encrypted import (
    build_encrypted_metadata_index,
    read_encrypted_jsonl,
)
from aegisflow.ingestion.zeek_jsonl import read_conn_jsonl
from aegisflow.pipeline import run_dns_pipeline, run_pipeline


Runner = Callable[[], list]


def _measure(runner: Runner, iterations: int, event_count: int) -> tuple[list, dict[str, Any]]:
    durations: list[float] = []
    alerts = []
    for _ in range(iterations):
        started = time.perf_counter()
        alerts = runner()
        durations.append(time.perf_counter() - started)
    median_seconds = statistics.median(durations)
    return alerts, {
        "iterations": iterations,
        "median_processing_ms": round(median_seconds * 1000, 4),
        "median_events_per_second": round(event_count / max(median_seconds, 1e-9), 2),
    }


def evaluate_demo(root: str | Path, *, iterations: int = 100) -> dict[str, Any]:
    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    project_root = Path(root).resolve()

    scan_events = list(read_conn_jsonl(project_root / "examples/zeek_conn_scan.jsonl"))
    ddos_events = list(read_conn_jsonl(project_root / "examples/zeek_conn_ddos.jsonl"))
    dns_events = list(read_dns_jsonl(project_root / "examples/zeek_dns_threats.jsonl"))
    c2_events = list(read_conn_jsonl(project_root / "examples/zeek_conn_beacon.jsonl"))
    encrypted_events = list(
        read_encrypted_jsonl(project_root / "examples/zeek_ssl_beacon.jsonl", "tls")
    )
    exfil_events = list(read_conn_jsonl(project_root / "examples/zeek_conn_exfil.jsonl"))
    dns_model = DNSNgramModel.load(project_root / "output/models/dns_dga_demo.json")

    scenarios: list[tuple[str, list, Counter[str], Runner]] = [
        (
            "reconnaissance",
            scan_events,
            Counter({"vertical_port_scan": 1}),
            lambda: list(run_pipeline(scan_events, [ReconDetector(ReconConfig(
                unique_port_threshold=5, unique_host_threshold=5
            ))])),
        ),
        (
            "denial_of_service",
            ddos_events,
            Counter({"syn_flood": 1, "udp_flood": 1}),
            lambda: list(run_pipeline(ddos_events, [DDoSDetector(DDoSConfig(
                syn_attempt_threshold=5, udp_packet_threshold=500
            ))])),
        ),
        (
            "dns_threats",
            dns_events,
            Counter({"dga_like_domain": 1, "dns_tunnelling": 1}),
            lambda: list(run_dns_pipeline(dns_events, [DNSDetector(model=dns_model)])),
        ),
        (
            "command_and_control",
            c2_events,
            Counter({"periodic_beacon": 1}),
            lambda: list(run_pipeline(c2_events, [C2BeaconDetector(
                encrypted_metadata=build_encrypted_metadata_index(encrypted_events)
            )])),
        ),
        (
            "data_exfiltration",
            exfil_events,
            Counter({"outbound_volume_anomaly": 1}),
            lambda: list(run_pipeline(exfil_events, [ExfiltrationDetector()])),
        ),
    ]

    results: list[dict[str, Any]] = []
    for name, events, expected, runner in scenarios:
        alerts, benchmark = _measure(runner, iterations, len(events))
        observed = Counter(alert.subtype for alert in alerts)
        results.append({
            "threat_family": name,
            "fixture_events": len(events),
            "expected_alerts": dict(sorted(expected.items())),
            "observed_alerts": dict(sorted(observed.items())),
            "scenario_passed": observed == expected,
            "benchmark": benchmark,
        })

    return {
        "product": "Drastha",
        "evaluation_scope": "synthetic_scenario_validation",
        "quality_claim": (
            "Each threat family is reported separately. These fixture checks prove repeatable "
            "pipeline behaviour; they are not production accuracy, recall, or false-positive claims."
        ),
        "benchmark_note": (
            "Single-process in-memory detector timing on this machine; excludes packet capture, "
            "Zeek conversion, network transport, database writes, and UI rendering."
        ),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "all_scenarios_passed": all(item["scenario_passed"] for item in results),
        "scenarios": results,
    }
