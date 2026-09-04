"""Disposable real HTTPS launch, online backup and create-only restore drill.

Only localhost is contacted. OpenSSL generates a disposable test certificate;
no trust store, existing deployment, real credentials or sensor is modified.
"""
from contextlib import contextmanager
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aegisflow.audited_store import AuditedIncidentRepository
from aegisflow.operations import backup_database, restore_database, read_key, write_new, verify_database
from init_security import bootstrap


@contextmanager
def server(directory, database, security, cert, tls_key, port):
    command = [sys.executable, str(ROOT / "scripts/operate.py"), "serve", "--database", str(database),
               "--audit-key", str(security / "audit.key"), "--auth", str(security / "auth.json"),
               "--cert", str(cert), "--tls-key", str(tls_key), "--web", str(directory / "web"),
               "--port", str(port), "--root", str(ROOT)]
    # Preflight provenance can exceed Windows' small pipe buffer. Drain to a
    # disposable file, not an unread PIPE that blocks the server before bind.
    with tempfile.TemporaryFile() as log:
        child = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=log,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            yield child
        finally:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()  # Only the owned disposable test server.
                child.wait(timeout=5)


def check():
    openssl = shutil.which("openssl")
    if not openssl:
        return {"status": "blocked", "passed": False, "reason": "OpenSSL is required for the disposable test certificate"}
    with tempfile.TemporaryDirectory(prefix="drastha-ops-drill-") as folder:
        directory = Path(folder)
        security = directory / "security"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        origin = f"https://localhost:{port}"
        bootstrap(security, origin)
        tokens = json.loads((security / "bootstrap-tokens.json").read_text())["tokens"]
        key = read_key(security / "audit.key")
        database = directory / "analyst.db"
        AuditedIncidentRepository(database, key)
        web = directory / "web"
        web.mkdir()
        (web / "index.html").write_text("<!doctype html><title>Disposable operations drill</title>", encoding="utf-8")
        cert, tls_key = directory / "cert.pem", directory / "tls.key"
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-keyout", str(tls_key), "-out", str(cert)], capture_output=True, check=True, timeout=15,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        context = ssl.create_default_context(cafile=str(cert))  # Trust THIS test cert; hostname/expiry checks stay ON.
        # Ignore operator proxy environment; never route this local drill externally.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))

        def request(path, role="viewer", method="GET", payload=None):
            headers = {"Content-Type": "application/json"}
            if role:
                headers["Authorization"] = "Bearer " + tokens[role]
            req = urllib.request.Request(origin + path, headers=headers, method=method,
                                         data=json.dumps(payload).encode() if payload is not None else None)
            try:
                with opener.open(req, timeout=3) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as exc:
                with exc:
                    return exc.code, json.loads(exc.read())

        def ready(child):
            started = time.perf_counter()
            while time.perf_counter() - started < 10:
                if child.poll() is not None:
                    raise RuntimeError("Disposable protected server failed startup")
                try:
                    code, response = request("/api/health")
                    if code == 200:
                        return (time.perf_counter() - started) * 1000
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(.05)
            raise TimeoutError("Protected HTTPS readiness deadline exceeded")

        gates = {}
        with server(directory, database, security, cert, tls_key, port) as child:
            startup_ms = ready(child)
            gates["https_auth_required"] = request("/api/health", role=None)[0] == 401
            gates["viewer_cannot_upload"] = request("/api/replays/analyse", method="POST", payload={})[0] == 403
            records = [{"ts": 1000 + i / 10, "uid": f"OPS{i}", "proto": "tcp", "conn_state": "S0",
                        "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",
                        "id.orig_p": 40000 + i, "id.resp_p": 1000 + i} for i in range(25)]
            code, report = request("/api/replays/analyse", role="analyst", method="POST",
                                   payload={"filename": "ops.jsonl", "content": "".join(json.dumps(r) + "\n" for r in records)})
            if code != 200:
                raise RuntimeError(f"Protected upload failed: HTTP {code}")
            gates["actual_https_upload"] = (report["quality"]["records_accepted"] == 25 and
                report["quality"]["status"] == "healthy" and len(report["alerts"]) == 1 and
                report["alerts"][0]["threat_type"] == "reconnaissance")
            incident = report["incidents"][0]["incident_id"]
            code, before = request("/api/incidents/" + incident)
            gates["evidence_readable"] = code == 200 and bool(before["alerts"])
            start = time.perf_counter()
            backup = backup_database(database, directory / "backup", key)
            backup_ms = (time.perf_counter() - start) * 1000
            expected_head = backup["manifest"]["head"]
            write_new(directory / "independently-selected-head.json", expected_head)
            code, _ = request("/api/incidents/" + incident + "/status", role="analyst", method="PATCH", payload={"status": "investigating"})
            gates["post_backup_write"] = code == 200
            gates["later_head_differs"] = verify_database(database, key)["head"] != expected_head
        start = time.perf_counter()
        result = restore_database(directory / "backup", directory / "restore", key, expected_head)
        restore_ms = (time.perf_counter() - start) * 1000
        gates["restore_verified"] = result["completed"]
        with server(directory, directory / "restore/analyst.db", security, cert, tls_key, port) as child:
            restore_startup_ms = ready(child)
            code, after = request("/api/incidents/" + incident)
            gates["restored_evidence_exact"] = code == 200 and before == after
            code, persisted = request("/api/analysis-runs/" + report["run_id"])
            gates["restored_run_exact"] = code == 200 and report == persisted
        return {"experiment": "sprint15-loopback-https-backup-restore-v1", "passed": all(gates.values()),
                "status": "passed" if all(gates.values()) else "failed", "gates": gates,
                "startup_ms": startup_ms, "backup_ms": backup_ms, "restore_ms": restore_ms,
                "restored_startup_ms": restore_startup_ms, "records_accepted": 25, "findings": len(report["alerts"]),
                "quality": report["quality"]["status"], "rows_restored": result["rows"],
                "tls_certificate_sha256": sha256(cert.read_bytes()).hexdigest(),
                "limitations": ["Disposable localhost HTTPS and synthetic 25-record scan, not a deployed production service",
                    "Certificate trusted explicitly only by this client; no system trust changes or disabled TLS checks",
                    "Restores deliberately selected backup checkpoint; later writes are not silently recovered",
                    "Analyst DB only; no stream journal recovery, real sensor, browser, remote proxy or service-manager validation"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    if args.report_output and args.report_output.exists():
        parser.error("Report is create-only; select a new filename")
    try:
        report = check()
    except Exception as exc:
        report = {"status": "failed", "passed": False, "error": f"{type(exc).__name__}: {exc}"}
    if args.report_output:
        write_new(args.report_output, report)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 2 if report["status"] == "blocked" else 1)
