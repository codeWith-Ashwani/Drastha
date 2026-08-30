from __future__ import annotations

import importlib.util
import json
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from aegisflow.api_store import IncidentRepository, read_jsonl
from aegisflow.detectors import C2BeaconDetector, ExfiltrationDetector
from aegisflow.incidents import IncidentStore
from aegisflow.ingestion.zeek_encrypted import (
    build_encrypted_metadata_index,
    normalize_encrypted_record,
)
from aegisflow.ingestion.zeek_jsonl import normalize_conn_record
from aegisflow.pipeline import run_pipeline
from aegisflow.telemetry_quality import load_jsonl_resilient


DEMO_FILES = (
    "output/sprint4_incidents.jsonl",
    "output/sprint3_c2_alerts.jsonl",
    "output/sprint4_exfil_alerts.jsonl",
    "output/sprint4_feedback.json",
)


def demo_preflight(root: str | Path) -> dict[str, Any]:
    project_root = Path(root).resolve()
    checks: list[dict[str, Any]] = []

    def record(name: str, required: bool, passed: bool, detail: str) -> None:
        checks.append({
            "name": name,
            "required": required,
            "passed": passed,
            "detail": detail,
        })

    version_ok = sys.version_info >= (3, 11)
    record("python", True, version_ok, platform.python_version())
    for relative in DEMO_FILES:
        path = project_root / relative
        record(relative, True, path.is_file() and path.stat().st_size > 0, relative)
    frontend = project_root / "web" / "dist" / "index.html"
    record("production_frontend", True, frontend.is_file(), "web/dist/index.html")
    for package in ("fastapi", "uvicorn"):
        record(
            f"python_dependency:{package}", True,
            importlib.util.find_spec(package) is not None,
            "available" if importlib.util.find_spec(package) is not None else "missing",
        )
    docker = shutil.which("docker")
    record("docker_cli", False, docker is not None, docker or "not on PATH; use SQLite fallback")
    zeek = shutil.which("zeek") or shutil.which("wsl")
    record("zeek_or_wsl", False, zeek is not None, zeek or "not on PATH; use saved JSON fixtures")

    required_checks = [item for item in checks if item["required"]]
    return {
        "product": "Drastha",
        "root": ".",
        "ready": all(item["passed"] for item in required_checks),
        "required_passed": sum(bool(item["passed"]) for item in required_checks),
        "required_total": len(required_checks),
        "fallback_mode": "sqlite_offline",
        "checks": checks,
    }


def prepare_demo(
    root: str | Path,
    database: str | Path = "output/drastha-demo.db",
    *,
    fresh: bool = False,
) -> dict[str, Any]:
    project_root = Path(root).resolve()
    database_path = Path(database)
    if not database_path.is_absolute():
        database_path = project_root / database_path
    database_path = database_path.resolve()
    output_root = (project_root / "output").resolve()

    if fresh and database_path.exists():
        if database_path.parent != output_root or database_path.suffix.lower() != ".db":
            raise ValueError("fresh demo reset is restricted to a .db file directly inside output/")
        database_path.unlink()

    incidents = read_jsonl(project_root / "output" / "sprint4_incidents.jsonl")
    alerts: list[dict[str, Any]] = []
    for name in ("sprint3_c2_alerts.jsonl", "sprint4_exfil_alerts.jsonl"):
        alerts.extend(read_jsonl(project_root / "output" / name))
    feedback = json.loads(
        (project_root / "output" / "sprint4_feedback.json").read_text(encoding="utf-8")
    )
    repository = IncidentRepository(database_path)
    loaded = repository.import_records(incidents, alerts, [feedback])
    try:
        database_display = database_path.relative_to(project_root).as_posix()
    except ValueError:
        database_display = str(database_path)
    return {
        "product": "Drastha",
        "database": database_display,
        "fresh": fresh,
        "loaded": loaded,
        "metrics": repository.metrics(),
        "dashboard": "http://127.0.0.1:8000",
    }


def run_attack_story(root: str | Path, repository: Any) -> dict[str, Any]:
    project_root = Path(root).resolve()
    started = __import__("time").perf_counter()
    c2_events, c2_quality = load_jsonl_resilient(
        project_root / "examples/zeek_conn_beacon.jsonl",
        normalize_conn_record,
        stream="zeek:conn:c2",
    )
    encrypted_events, encrypted_quality = load_jsonl_resilient(
        project_root / "examples/zeek_ssl_beacon.jsonl",
        lambda record, line: normalize_encrypted_record(record, line, "tls"),
        stream="zeek:tls",
    )
    exfil_events, exfil_quality = load_jsonl_resilient(
        project_root / "examples/zeek_conn_exfil.jsonl",
        normalize_conn_record,
        stream="zeek:conn:exfiltration",
    )
    quality_reports = [c2_quality, encrypted_quality, exfil_quality]
    blocking = [item for item in quality_reports if item.status in {"unavailable", "unusable"}]
    if blocking:
        return {
            "status": "blocked",
            "reason": "required demo telemetry is unavailable or unusable",
            "telemetry": [item.to_dict() for item in quality_reports],
            "stages": [],
        }

    c2_alerts = list(run_pipeline(c2_events, [C2BeaconDetector(
        encrypted_metadata=build_encrypted_metadata_index(encrypted_events)
    )]))
    exfil_alerts = list(run_pipeline(exfil_events, [ExfiltrationDetector()]))
    alerts = c2_alerts + exfil_alerts
    correlator = IncidentStore()
    for alert in alerts:
        correlator.process(alert)
    incidents = list(correlator.all())
    loaded = repository.import_records(
        [incident.to_dict() for incident in incidents],
        [alert.to_dict() for alert in alerts],
    )
    elapsed_ms = round((__import__("time").perf_counter() - started) * 1000, 3)
    overall_quality = "degraded" if any(
        item.status == "degraded" for item in quality_reports
    ) else "healthy"
    return {
        "status": "completed",
        "telemetry_status": overall_quality,
        "elapsed_ms": elapsed_ms,
        "stages": [
            {"name": "Passive telemetry", "status": overall_quality,
             "records": sum(item.records_accepted for item in quality_reports)},
            {"name": "C2 detection", "status": "detected" if c2_alerts else "no_alert",
             "alerts": len(c2_alerts)},
            {"name": "Exfiltration detection", "status": "detected" if exfil_alerts else "no_alert",
             "alerts": len(exfil_alerts)},
            {"name": "Incident correlation", "status": "critical" if any(
                item.severity == "critical" for item in incidents
            ) else "completed", "incidents": len(incidents)},
        ],
        "loaded": loaded,
        "metrics": repository.metrics(),
        "telemetry": [item.to_dict() for item in quality_reports],
    }


def rehearse_demo(
    root: str | Path,
    database: str | Path = "output/drastha-rehearsal.db",
    *,
    evaluation_iterations: int = 25,
) -> dict[str, Any]:
    from aegisflow.evaluation import evaluate_demo

    project_root = Path(root).resolve()
    preflight = demo_preflight(project_root)
    if not preflight["ready"]:
        return {"product": "Drastha", "ready": False, "preflight": preflight}

    prepared = prepare_demo(project_root, database, fresh=True)
    database_path = Path(database)
    if not database_path.is_absolute():
        database_path = project_root / database_path
    repository = IncidentRepository(database_path)
    first_run = run_attack_story(project_root, repository)
    first_counts = {
        "incidents": len(repository.list_incidents()),
        "alerts": len(repository.list_alerts()),
    }
    second_run = run_attack_story(project_root, repository)
    second_counts = {
        "incidents": len(repository.list_incidents()),
        "alerts": len(repository.list_alerts()),
    }
    evaluation = evaluate_demo(project_root, iterations=evaluation_iterations)
    checks = {
        "preflight_ready": preflight["ready"],
        "attack_story_completed": first_run["status"] == "completed",
        "critical_incident_created": repository.metrics()["critical_incidents"] == 1,
        "replay_is_idempotent": first_counts == second_counts == {"incidents": 1, "alerts": 2},
        "evaluation_passed": evaluation["all_scenarios_passed"],
    }
    return {
        "product": "Drastha",
        "ready": all(checks.values()),
        "checks": checks,
        "prepared": prepared,
        "first_run": first_run,
        "second_run": second_run,
        "evaluation": evaluation,
        "recovery_mode": "SQLite offline; Docker and live Zeek are optional for the SIH demo",
    }
