"""Exercise safe demo-startup failure paths without starting a service."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr
from io import StringIO
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import build_opener, ProxyHandler


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.cli import main  # noqa: E402
from aegisflow.demo import available_demo_port, require_demo_port  # noqa: E402


def _real_loopback_startup(root: Path, temporary: Path) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root / "src")
    database = temporary / "real-startup.db"
    process = subprocess.Popen(
        [sys.executable, "-m", "aegisflow.cli", "demo-serve", "--root", str(root),
         "--database", str(database), "--skip-prepare", "--port", str(port)],
        cwd=root, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    opener = build_opener(ProxyHandler({}))
    healthy = False
    deadline = time.monotonic() + 10
    try:
        while time.monotonic() < deadline and process.poll() is None:
            try:
                with opener.open(f"http://127.0.0.1:{port}/api/health", timeout=0.5) as response:
                    payload = json.loads(response.read())
                    healthy = (
                        response.status == 200
                        and payload.get("status") == "healthy"
                        and payload.get("return_path_required") is False
                    )
                    if healthy:
                        break
            except (OSError, URLError, ValueError):
                time.sleep(0.05)
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            _, server_errors = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            _, server_errors = process.communicate(timeout=5)
    return healthy and "Application startup complete" in server_errors


def audit(root: Path = ROOT) -> dict:
    root = root.resolve()
    with tempfile.TemporaryDirectory(prefix="drastha-startup-") as directory:
        temporary = Path(directory)
        output = temporary / "output"
        output.mkdir()
        database = output / "protected-demo.db"
        sentinel = b"do not reset when listener is unavailable"
        database.write_bytes(sentinel)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            occupied = listener.getsockname()[1]
            errors = StringIO()
            with redirect_stderr(errors):
                result = main([
                    "demo-serve", "--root", str(temporary), "--database", str(database),
                    "--host", "127.0.0.1", "--port", str(occupied), "--fresh",
                ])
        message = errors.getvalue()
        database_unchanged = database.read_bytes() == sentinel
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            free_port = probe.getsockname()[1]
        available = available_demo_port("127.0.0.1", free_port, attempts=0)
        non_loopback_rejected = False
        try:
            require_demo_port("0.0.0.0", 8000)
        except ValueError:
            non_loopback_rejected = True
        real_startup = _real_loopback_startup(root, temporary)
    launcher = (root / "scripts" / "start-demo.ps1").read_text(encoding="utf-8")
    cli = (root / "src" / "aegisflow" / "cli.py").read_text(encoding="utf-8")
    gates = {
        "occupied_port_returns_controlled_error": result == 2 and "already in use" in message,
        "database_unchanged_before_bind_failure": database_unchanged,
        "alternative_port_is_suggested": "Use --port" in message,
        "powershell_owner_diagnostic_is_present": "Get-NetTCPConnection" in message,
        "free_loopback_port_is_accepted": available == free_port,
        "non_loopback_demo_host_is_rejected": non_loopback_rejected,
        "launcher_accepts_explicit_port": "[int]$Port = 8000" in launcher and "--port $Port" in launcher,
        "misleading_ready_message_removed": "Drastha demo ready:" not in cli,
        "uvicorn_receives_prebound_socket": ".run(sockets=[listener])" in cli,
        "real_loopback_health_readback": real_startup,
    }
    return {
        "schema_version": "drastha-sprint27-startup-audit-v1",
        "passed": all(gates.values()),
        "gates": gates,
        "default_url": "http://127.0.0.1:8000",
        "failure_semantics": "fail before demo preparation or --fresh database reset",
        "production_ready": False,
        "limitations": [
            "This hardens the loopback demo launcher, not the protected TLS operator service.",
            "The bounded localhost health check is not browser, TLS or protected-network validation.",
            "Process-owner lookup is shown as an operator command and is not executed automatically.",
        ],
    }


def main_cli() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--report-output", type=Path, required=True)
    args = parser.parse_args()
    if args.report_output.exists():
        parser.error("Choose a new report output path")
    report = audit(args.repo_root)
    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "gates": report["gates"],
                      "report": str(args.report_output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main_cli())
