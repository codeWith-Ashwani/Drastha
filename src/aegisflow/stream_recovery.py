"""Operator-only coordinated SQLite cut; no source writes or automatic cutover.

Same-engine recovery only. Cross-version migration requires a separately reviewed
equivalence protocol, never an edited engine digest. Originals and failed outputs
are retained. The signed bundle contains raw traffic: protect it like evidence.
"""
from contextlib import closing, contextmanager
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time

from aegisflow.audited_store import canonical, EvidenceIntegrityError
from aegisflow.continuous_ingestion import ContinuousIngestor, StreamLimits, _engine_digest, _different_paths
from aegisflow.operations import readonly_database, verify_database, file_digest, write_new, read_json


VERSION = "drastha-coordinated-cut-v1"
MAX_BYTES = 1_073_741_824
MAX_RECORDS = 20_000
MAX_RAW_BYTES = 67_108_864
FILES = ("journal.db", "analyst.db")
SIDECARS = ("-wal", "-shm", "-journal")


def _key(key):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("A 32-byte external signing key is required")


def _regular(path, *, standalone=False):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected a regular non-symlink file")
    if standalone and any(Path(str(path) + suffix).exists() for suffix in SIDECARS):
        raise EvidenceIntegrityError("Bundle databases must be standalone, without sidecars")
    return path.resolve(strict=True)


@contextmanager
def _freeze(path, *, exclusive=False):
    # Existing file only: do not create a missing lock/database or enroll schema.
    path = _regular(path)
    with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=0)) as db:
        try:
            db.execute("BEGIN EXCLUSIVE" if exclusive else "BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            raise EvidenceIntegrityError("Stop the worker/writer before taking a coordinated cut") from exc
        try:
            yield
        finally:
            db.rollback()


def _snapshot(source, target):
    deadline = time.monotonic() + 30
    with closing(readonly_database(source)) as incoming, closing(sqlite3.connect(target)) as outgoing:
        page_size = incoming.execute("PRAGMA page_size").fetchone()[0]
        def progress(status, remaining, total):
            if total * page_size > MAX_BYTES or time.monotonic() > deadline:
                raise ValueError("Snapshot exceeds 1 GiB/30-second copy budget; incomplete output retained")
        incoming.backup(outgoing, pages=256, progress=progress, sleep=.05)
        outgoing.execute("PRAGMA journal_mode=DELETE")
    with target.open("r+b") as stream:
        os.fsync(stream.fileno())


def _journal(path):
    """Structural checks before any journal is opened by the worker."""
    with closing(readonly_database(path)) as db:
        db.execute("BEGIN")
        if [r[0] for r in db.execute("PRAGMA integrity_check")] != ["ok"]:
            raise EvidenceIntegrityError("Journal SQLite integrity check failed")
        objects = list(db.execute("SELECT name,type FROM sqlite_master WHERE type IN ('table','view','trigger')"))
        if {(r[0], r[1]) for r in objects} != {(n, "table") for n in ("stream_meta", "stream_records", "stream_snapshot")}:
            raise EvidenceIntegrityError("Unexpected journal tables, views or triggers")
        for table in ("stream_meta", "stream_snapshot"):
            if db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] != 1:
                raise EvidenceIntegrityError("A completed journal snapshot is required")
        meta = json.loads(db.execute("SELECT payload FROM stream_meta WHERE id=1").fetchone()[0])
        report = json.loads(db.execute("SELECT payload FROM stream_snapshot WHERE id=1").fetchone()[0])
        if (type(meta["lines"]) is not int or not 0 <= meta["lines"] <= MAX_RECORDS
                or type(meta["offset"]) is not int or not 0 <= meta["offset"] <= MAX_RAW_BYTES):
            raise ValueError("Coordinated recovery is limited to 20,000 lines/64 MiB raw bytes")
        if db.execute("SELECT COUNT(*) FROM stream_records").fetchone()[0] != meta["lines"]:
            raise EvidenceIntegrityError("Journal record count differs from checkpoint")
        # Do not trust the engine/version to make an unsafe journal schema safe.
        expected_columns = {
            "stream_meta": ["id", "payload"], "stream_snapshot": ["id", "payload"],
            "stream_records": ["start_offset", "end_offset", "raw", "disposition", "reason"],
        }
        for table, columns in expected_columns.items():
            if [r[1] for r in db.execute(f"PRAGMA table_info({table})")] != columns:
                raise EvidenceIntegrityError("Journal column contract differs")
        return meta, report


def _cut(meta):
    return {name: meta[name] for name in ("contract", "run_id", "offset", "lines", "prefix_sha256")}


def _source(meta, source):
    source = _regular(source)
    contract = meta["contract"]
    stat = source.stat()
    if str(source) != contract["source"] or [stat.st_dev, stat.st_ino] != contract["source_identity"]:
        raise EvidenceIntegrityError("Original source path/identity required; automatic rebinding forbidden")
    digest = sha256()
    with source.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if [opened.st_dev, opened.st_ino] != contract["source_identity"]:
            raise EvidenceIntegrityError("Source identity changed while opening committed prefix")
        remaining = meta["offset"]
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                raise EvidenceIntegrityError("Original source is shorter than committed cut")
            remaining -= len(block)
            digest.update(block)
    after = source.stat()
    if [after.st_dev, after.st_ino] != contract["source_identity"]:
        raise EvidenceIntegrityError("Source identity changed during prefix verification")
    if digest.hexdigest() != meta["prefix_sha256"]:
        raise EvidenceIntegrityError("Original committed source prefix changed")
    return source


def _reconstruct(journal, source, factory):
    """Replay a disposable copy, with NO repository and NO poll/source advance."""
    meta, report = _journal(journal)
    source = _source(meta, source)
    if meta["contract"]["engine_sha256"] != _engine_digest():
        raise EvidenceIntegrityError("Engine mismatch: retain old release; cross-version migration is not authorized")
    if canonical(meta["contract"]["provenance"]) != canonical(factory().provenance()):
        raise EvidenceIntegrityError("Profile/model/policy provenance mismatch")
    with tempfile.TemporaryDirectory(prefix="drastha-cut-verify-") as folder:
        copy = Path(folder) / "journal.db"
        _snapshot(journal, copy)
        with ContinuousIngestor(source, copy, factory, limits=StreamLimits(**meta["contract"]["limits"])) as worker:
            recovered = worker._report(report["status"], report["stream"]["backlog_bytes"])
            for field in ("run_id", "filename", "quality", "analysis_provenance", "feature_coverage", "alerts", "incidents"):
                if canonical(recovered[field]) != canonical(report[field]):
                    raise EvidenceIntegrityError(f"Reconstructed {field} differs from committed evidence")
            for field in ("committed_offset", "committed_lines", "limits", "batches", "queue_high_watermark", "batch_records_limit"):
                if recovered["stream"][field] != report["stream"][field]:
                    raise EvidenceIntegrityError("Stream snapshot counters differ from checkpoint")
    _source(meta, source)
    return meta, report


def _pair(journal, analyst, source, key, factory, expected_head=None):
    verified = verify_database(analyst, key, expected_head)
    meta, report = _reconstruct(journal, source, factory)
    with closing(readonly_database(analyst)) as db:
        row = db.execute("SELECT payload FROM analysis_runs WHERE run_id=?", (meta["run_id"],)).fetchone()
        if not row or canonical(json.loads(row[0])) != canonical(report):
            raise EvidenceIntegrityError("Analyst projection is not at journal cut; reconcile using the original release first")
        # Review status/feedback are independent; detection payloads must agree.
        for table, identity, records in (("alerts", "alert_id", report["alerts"]),
                                         ("incidents", "incident_id", report["incidents"])):
            for record in records:
                row = db.execute(f"SELECT payload FROM {table} WHERE {identity}=?", (record[identity],)).fetchone()
                observed = json.loads(row[0]) if row else None
                expected = dict(record)
                if table == "incidents" and observed is not None:
                    # set_status legitimately edits this one payload field. Keep
                    # the signed stored review; do not replace it with detector state.
                    observed.pop("status", None)
                    expected.pop("status", None)
                if observed is None or canonical(observed) != canonical(expected):
                    raise EvidenceIntegrityError("Projected evidence differs; no silent review reconciliation")
    return meta, verified


def backup_stream(source, journal, analyst, destination, key, factory):
    """Acquire worker, journal-writer and analyst-writer locks; publish manifest last."""
    _key(key)
    source, journal, analyst = (_regular(p) for p in (source, journal, analyst))
    lock = _regular(Path(str(journal) + ".lock"))
    destinations = [journal, lock, analyst]
    destinations.extend(Path(str(p) + suffix) for p in list(destinations) for suffix in SIDECARS)
    _different_paths(source, destinations)
    destination = Path(destination).resolve()
    # Fixed children under a new directory cannot overwrite any supplied inputs.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    with _freeze(lock, exclusive=True), _freeze(journal), _freeze(analyst):
        _snapshot(journal, destination / "journal.db")
        _snapshot(analyst, destination / "analyst.db")
        meta, verified = _pair(destination / "journal.db", destination / "analyst.db", source, key, factory)
        body = {"version": VERSION, "created_at": time.time(), "cut": _cut(meta),
                "head": verified["head"], "rows": verified["rows"],
                "files": {name: {"bytes": (destination / name).stat().st_size,
                                 "sha256": file_digest(destination / name)} for name in FILES},
                "scope": "one_journal_and_signed_analyst_store",
                "excludes": ["source_file", "keys", "credentials", "code", "models"],
                "automatic_cutover": False}
        manifest = {**body, "mac": hmac.new(key, canonical(body).encode(), "sha256").hexdigest()}
        anchor = {"version": VERSION, "manifest_sha256": sha256(canonical(manifest).encode()).hexdigest()}
        write_new(destination / "anchor.json", anchor)
        write_new(destination / "manifest.json", manifest)
    return {"completed": True, "anchor": anchor, "head": verified["head"], "lines": meta["lines"],
            "automatic_cutover": False, "note": "Retain anchor independently; preserve original source and exact release"}


def _authenticated_manifest(bundle, key, expected_anchor):
    _key(key)
    manifest = read_json(_regular(bundle / "manifest.json"))
    body = {k: v for k, v in manifest.items() if k != "mac"}
    mac = manifest.get("mac")
    if (not isinstance(mac, str) or not hmac.compare_digest(mac, hmac.new(key, canonical(body).encode(), "sha256").hexdigest())
            or body.get("version") != VERSION or body.get("scope") != "one_journal_and_signed_analyst_store"
            or set(body.get("files", {})) != set(FILES)):
        raise EvidenceIntegrityError("Coordinated manifest signature/format invalid")
    anchor = {"version": VERSION, "manifest_sha256": sha256(canonical(manifest).encode()).hexdigest()}
    if expected_anchor != anchor:
        raise EvidenceIntegrityError("Bundle differs from independently retained checkpoint anchor")
    return body


def _copy_checked(source, target, expected):
    source = _regular(source, standalone=True)
    size = expected["bytes"]
    if type(size) is not int or not 0 < size <= MAX_BYTES:
        raise ValueError("Invalid snapshot size/1 GiB budget exceeded")
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with source.open("rb") as incoming, os.fdopen(descriptor, "wb") as outgoing:
        remaining = size + 1
        while remaining:
            block = incoming.read(min(1024 * 1024, remaining))
            if not block:
                break
            outgoing.write(block)
            remaining -= len(block)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    if target.stat().st_size != size or file_digest(target) != expected["sha256"]:
        raise EvidenceIntegrityError("Copied snapshot size/hash mismatch; incomplete output retained")


def restore_stream(bundle, source, destination, key, expected_anchor, factory):
    """Same-engine create-only restore; requires original source identity/prefix."""
    bundle = Path(bundle).resolve(strict=True)
    destination = Path(destination).resolve()
    if destination == bundle or bundle in destination.parents or destination in bundle.parents:
        raise ValueError("Restore destination must be separate from bundle")
    body = _authenticated_manifest(bundle, key, expected_anchor)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name in FILES:
        _copy_checked(bundle / name, destination / name, body["files"][name])
    meta, verified = _pair(destination / "journal.db", destination / "analyst.db", source, key, factory, body["head"])
    if _cut(meta) != body["cut"] or verified["rows"] != body["rows"]:
        raise EvidenceIntegrityError("Restored cut/inventory differs from signed manifest")
    receipt = {"version": VERSION, "restored_at": time.time(), "anchor": expected_anchor,
               "head": verified["head"], "lines": meta["lines"], "automatic_cutover": False,
               "engine_sha256": meta["contract"]["engine_sha256"]}
    write_new(destination / "restore-receipt.json", receipt)
    return {"completed": True, **receipt}


def check_stream(bundle, source, key, expected_anchor, factory):
    """Read-only-to-inputs rehearsal using owned temporary snapshot copies."""
    with tempfile.TemporaryDirectory(prefix="drastha-upgrade-check-") as folder:
        result = restore_stream(bundle, source, Path(folder) / "candidate", key, expected_anchor, factory)
    return {"compatible": True, "production_ready": False, "lines": result["lines"],
            "engine_sha256": result["engine_sha256"], "head": result["head"],
            "automatic_cutover": False, "cross_version_migration": False}
