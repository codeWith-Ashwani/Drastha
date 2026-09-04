"""Operator-only, create-only signed SQLite recovery and protected launch checks.

Never contacts monitored endpoints. No live DB replacement, schema migration,
key export or automatic checkpoint rebinding. Backups are analyst-store ONLY.
"""
from __future__ import annotations

from contextlib import closing
from hashlib import sha256
import hmac
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import ssl
import time

from aegisflow.audited_store import TABLES, canonical, snapshot, verify_connection, EvidenceIntegrityError
from aegisflow.security import AccessSettings
from aegisflow.analysis_session import AnalysisSession, DEPLOYMENT_BASELINE


VERSION = "drastha-analyst-backup-v1"
MAX_BACKUP_BYTES = 1_073_741_824


def read_key(path):
    path = Path(path).resolve(strict=True)
    if path.stat().st_size > 256:
        raise ValueError("Audit key file is too large")
    raw = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[a-fA-F0-9]{64}", raw):
        raise ValueError("Expected a 32-byte audit key encoded as 64 hex characters")
    return bytes.fromhex(raw)


def readonly_database(path):
    path = Path(path).resolve(strict=True)
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    return connection


def verify_database(path, key, expected_head=None):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("A 32-byte audit key is required")
    try:
        with closing(readonly_database(path)) as connection:
            connection.execute("BEGIN")  # One consistent view for integrity, rows and ledger.
            if [row[0] for row in connection.execute("PRAGMA integrity_check")] != ["ok"]:
                raise EvidenceIntegrityError("SQLite integrity check failed")
            # No views/triggers masquerading as evidence tables in recovered files.
            schema = {row["name"]: row["type"] for row in connection.execute("SELECT name, type FROM sqlite_master")}
            if ({name for name, kind in schema.items() if kind == "table"} != set(TABLES) | {"evidence_audit"}
                    or any(schema.get(table) != "table" for table in (*TABLES, "evidence_audit"))):
                raise EvidenceIntegrityError("Required evidence tables missing or substituted")
            if connection.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger', 'view')").fetchone():
                raise EvidenceIntegrityError("Unexpected trigger/view in analyst database")
            state = snapshot(connection)
            head = verify_connection(connection, state, key)
            if expected_head is not None and head != expected_head:
                raise EvidenceIntegrityError("Evidence differs from the independently retained expected head")
            counts = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in TABLES}
            return {"verified": True, "head": head, "rows": counts}
    except sqlite3.Error as exc:
        raise EvidenceIntegrityError("SQLite evidence verification failed") from exc


def file_digest(path):
    digest = sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_new(path, value):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(canonical(value) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def backup_database(database, destination, key, *, timeout_seconds=30):
    """SQLite online backup includes committed WAL, then verifies the snapshot."""
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ValueError("Backup timeout must be in (0, 300] seconds")
    source = Path(database).resolve(strict=True)
    destination = Path(destination).resolve()
    # Exclusive directory creation prevents clobbering files, DB sidecars or keys.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    target = destination / "analyst.db"
    deadline = time.monotonic() + timeout_seconds

    page_size = 0

    def progress(status, remaining, total):
        if total * page_size > MAX_BACKUP_BYTES:
            raise ValueError("Analyst snapshot exceeds the 1 GiB operator-tool budget")
        if time.monotonic() > deadline:
            raise TimeoutError("Online backup exceeded deadline; incomplete destination retained")

    with closing(readonly_database(source)) as incoming, closing(sqlite3.connect(target)) as outgoing:
        page_size = incoming.execute("PRAGMA page_size").fetchone()[0]
        incoming.backup(outgoing, pages=256, progress=progress, sleep=.05)
        # Standalone, closed snapshot: no WAL sidecar is part of the bundle.
        outgoing.execute("PRAGMA journal_mode=DELETE")
    verified = verify_database(target, key)
    with target.open("r+b") as stream:
        os.fsync(stream.fileno())
    body = {"version": VERSION, "created_at": time.time(), "file": "analyst.db",
            "bytes": target.stat().st_size, "sha256": file_digest(target),
            "head": verified["head"], "rows": verified["rows"],
            "scope": "analyst_sqlite_only", "excludes": ["sensor_files", "stream_journal", "keys", "credentials", "tls", "models", "code"]}
    manifest = {**body, "mac": hmac.new(key, canonical(body).encode(), "sha256").hexdigest()}
    write_new(destination / "head.json", verified["head"])
    write_new(destination / "manifest.json", manifest)  # Last: incomplete directories are never valid bundles.
    return {"completed": True, "manifest": manifest,
            "note": "Copy head.json independently; this bundle is not encrypted or a stream checkpoint backup"}


def read_json(path):
    if Path(path).stat().st_size > 65536:
        raise ValueError("Metadata file is too large")
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected an object")
    return value


def restore_database(bundle, destination, key, expected_head):
    """Never replaces a live DB. An operator must explicitly cut over afterward."""
    bundle = Path(bundle).resolve(strict=True)
    destination = Path(destination).resolve()
    if destination == bundle or bundle in destination.parents or destination in bundle.parents:
        raise ValueError("Restore destination must be separate from the backup bundle")
    body = read_json(bundle / "manifest.json")
    mac = body.pop("mac", "")
    if (not isinstance(mac, str) or not hmac.compare_digest(mac, hmac.new(key, canonical(body).encode(), "sha256").hexdigest())
            or body.get("version") != VERSION or body.get("file") != "analyst.db"
            or body.get("scope") != "analyst_sqlite_only"):
        raise EvidenceIntegrityError("Backup manifest signature or format invalid")
    if expected_head is None or body.get("head") != expected_head:
        raise EvidenceIntegrityError("Backup does not match independently retained expected head")
    source = bundle / "analyst.db"
    if type(body.get("bytes")) is not int or not 0 < body["bytes"] <= MAX_BACKUP_BYTES:
        raise ValueError("Invalid backup size or 1 GiB operator-tool budget exceeded")
    if source.is_symlink() or not source.is_file() or any(Path(str(source) + s).exists() for s in ("-wal", "-shm", "-journal")):
        raise EvidenceIntegrityError("Bundle must contain a standalone regular SQLite snapshot")
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    target = destination / "analyst.db"
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with source.open("rb") as incoming, os.fdopen(descriptor, "wb") as outgoing:
        remaining = body["bytes"] + 1
        while remaining:
            block = incoming.read(min(1024 * 1024, remaining))
            if not block:
                break
            outgoing.write(block)
            remaining -= len(block)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    # Verify the copied bytes, not an earlier TOCTOU observation of the source.
    if target.stat().st_size != body["bytes"] or file_digest(target) != body["sha256"]:
        raise EvidenceIntegrityError("Backup snapshot hash/size mismatch; incomplete destination retained")
    verified = verify_database(target, key, expected_head)
    if verified["rows"] != body["rows"]:
        raise EvidenceIntegrityError("Backup row inventory mismatch")
    write_new(destination / "restore-receipt.json", {"version": VERSION, "head": verified["head"],
              "sha256": body["sha256"], "restored_at": time.time(), "automatic_cutover": False})
    return {"completed": True, **verified, "automatic_cutover": False}


def preflight(*, database, audit_key, auth, cert, tls_key, web, root, host="127.0.0.1", port=8443):
    """Local configuration readiness only; no network probes or writes."""
    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("Protected launcher is loopback-only; remote deployment needs an explicitly reviewed network design")
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("Port must be in [1024, 65535]")
    files = [Path(p).resolve(strict=True) for p in (database, audit_key, auth, cert, tls_key)]
    if any(not p.is_file() for p in files) or any(os.path.samefile(a, b) for i, a in enumerate(files) for b in files[i+1:]):
        raise ValueError("Database, credentials and keys/certificate must be distinct regular files")
    web, root = Path(web).resolve(strict=True), Path(root).resolve(strict=True)
    if not (web / "index.html").is_file() or not (root / "pyproject.toml").is_file():
        raise ValueError("Built dashboard and project root are required")
    if any(web == p or web in p.parents for p in files) or (web / ".git").exists():
        raise ValueError("Never place database/credentials/keys under the served web directory")
    settings = AccessSettings.from_file(auth)
    if any(c.expires_at <= time.time() for c in settings.credentials):
        raise ValueError("Expired credentials configured; rotate through an operator-approved process")
    if {c.role for c in settings.credentials} != {"viewer", "analyst", "admin"}:
        raise ValueError("Configure viewer, analyst and admin roles before protected launch")
    if not settings.allowed_origins:
        raise ValueError("An exact HTTPS dashboard origin must be configured")
    from urllib.parse import urlsplit
    if not any(urlsplit(origin).hostname in {"localhost", "127.0.0.1", "::1"}
               and (urlsplit(origin).port or 443) == port for origin in settings.allowed_origins):
        raise ValueError("Configure the loopback HTTPS origin and matching listening port")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(tls_key), password="")  # No interactive password prompt.
    verified = verify_database(database, read_key(audit_key))
    provenance = AnalysisSession.from_root(root, DEPLOYMENT_BASELINE).provenance()
    return {"local_checks_passed": True, "production_ready": False, "evidence": verified,
            "analysis_provenance": provenance,
            "profile": "deployment-baseline-uncalibrated-v1", "host": host, "port": port,
            "proxy_headers": False, "workers": 1,
            "warnings": ["TLS key-pair load is not certificate expiry/hostname/chain trust validation; test a trusted HTTPS client",
                         "Loopback-only staged deployment; Windows ACLs, disk permissions and service supervision require operator review",
                         "Analyst backup excludes sensor and stream journal; recovery is not cross-database exactly-once",
                         "Signed 1000 records/sec failed Sprint 14; 100 records/sec is only a bounded synthetic measurement",
                         "Real Zeek, browser QA, model calibration, rotation/compaction and external anchoring remain open"]}
