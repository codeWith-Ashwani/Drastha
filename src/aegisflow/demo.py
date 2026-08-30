from __future__ import annotations

import importlib.util
import json
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from aegisflow.api_store import IncidentRepository, read_jsonl


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
