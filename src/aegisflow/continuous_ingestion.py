"""Bounded, restartable append-only JSONL ingest inside the monitoring enclave.

The journal is the durable commit point. Analyst-store delivery is idempotent,
at-least-once projection, not a distributed exactly-once transaction. Recovery
replays the complete bounded journal to restore windows, baselines and cooldowns.
No pickled state, outbound network requests, source writes or silent state resets.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import sqlite3
import time
from uuid import uuid4

from aegisflow.analysis_session import AnalysisSession
from aegisflow.ingestion.passive_replay import prepare_stream_record, ReplayQualityError
from aegisflow.ingestion.replay_input import record_schema
from aegisflow.telemetry_quality import TelemetryQuality


class StreamStopped(RuntimeError):
    """Fail closed; committed journal remains recoverable."""


@dataclass(frozen=True)
class StreamLimits:
    batch_records: int = 64
    max_line_bytes: int = 262_144
    max_journal_records: int = 20_000
    max_journal_bytes: int = 67_108_864

    def __post_init__(self):
        for value in asdict(self).values():
            if type(value) is not int or value <= 0:
                raise ValueError("Stream limits must be positive integers")
        if self.batch_records > 4096 or self.max_line_bytes > 1_048_576:
            raise ValueError("Batch limit is 4096 records; line limit is 1 MiB")


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _engine_digest():
    digest = sha256()
    root = Path(__file__).parent
    for path in sorted(root.rglob("*.py")):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _different_paths(source, destinations):
    """Include SQLite sidecars and hardlinks in source-write protection."""
    paths = [source, *destinations]
    for index, first in enumerate(paths):
        for second in paths[index + 1:]:
            if first == second or (first.exists() and second.exists() and os.path.samefile(first, second)):
                raise ValueError("Input, journal, lock, sidecars and analyst database must be distinct")


class ContinuousIngestor:
    version = "drastha-continuous-v1"

    def __init__(self, source, checkpoint, session_factory, *, limits=None, repository=None):
        self.source = Path(source).resolve(strict=True)
        if not self.source.is_file():
            raise ValueError("Stream source must be a regular append-only JSONL file")
        self.checkpoint = Path(checkpoint).resolve()
        self.limits = limits or StreamLimits()
        self.repository = repository
        self._factory = session_factory
        self._closed = False
        self._failed = False
        self._db = self._lock = self._input = None
        self._session = session_factory()
        if not isinstance(self._session, AnalysisSession):
            raise TypeError("session_factory must return AnalysisSession")
        destinations = [self.checkpoint, Path(str(self.checkpoint) + ".lock")]
        destinations.extend(Path(str(path) + suffix) for path in list(destinations)
                            for suffix in ("-journal", "-wal", "-shm"))
        if repository is not None and hasattr(repository, "database_path"):
            db = Path(repository.database_path).resolve()
            destinations.extend([db, *(Path(str(db) + s) for s in ("-journal", "-wal", "-shm"))])
        _different_paths(self.source, destinations)
        self.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Separate lifetime SQLite lock: OS releases it on process death.
            self._lock = sqlite3.connect(str(self.checkpoint) + ".lock", timeout=0)
            try:
                self._lock.execute("BEGIN EXCLUSIVE")
            except sqlite3.OperationalError as exc:
                raise StreamStopped("Another worker owns this checkpoint") from exc
            self._input = self.source.open("rb")
            stat = os.fstat(self._input.fileno())
            self._identity = [stat.st_dev, stat.st_ino]
            self._db = sqlite3.connect(self.checkpoint, timeout=5)
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS stream_meta (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS stream_records (
                    start_offset INTEGER PRIMARY KEY, end_offset INTEGER NOT NULL,
                    raw BLOB NOT NULL, disposition TEXT NOT NULL, reason TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS stream_snapshot (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
            """)
            self._contract = {"version": self.version, "source": str(self.source),
                              "source_identity": self._identity, "limits": asdict(self.limits),
                              "provenance": self._session.provenance(), "engine_sha256": _engine_digest()}
            row = self._db.execute("SELECT payload FROM stream_meta WHERE id=1").fetchone()
            self._reset_quality()
            if row:
                self._meta = json.loads(row[0])
                if self._meta["contract"] != json.loads(_json(self._contract)):
                    raise StreamStopped("Checkpoint source, engine, profile, model, policy or limits changed")
                self._verify_source(self._meta["offset"], self._meta["prefix_sha256"])
                self._recover()
            else:
                self._meta = {"contract": self._contract, "run_id": "stream-" + uuid4().hex,
                              "offset": 0, "lines": 0, "prefix_sha256": sha256().hexdigest(),
                              "queue_high_watermark": 0, "batches": 0}
                with self._db:
                    self._db.execute("INSERT INTO stream_meta VALUES (1, ?)", (_json(self._meta),))
            self.recovered_records = self._meta["lines"]
            self._input.seek(self._meta["offset"])
            self._publish()  # Retry a previously committed but undelivered outbox.
        except BaseException:
            self.close()
            raise

    def _reset_quality(self):
        self.quality = TelemetryQuality(stream=self.version, source=self.source.name)
        self._uids = {}
        self._latest = None
        self._digest = sha256()

    def _verify_source(self, offset, expected):
        stat = self.source.stat()
        if [stat.st_dev, stat.st_ino] != self._identity or stat.st_size < offset:
            raise StreamStopped("Source rotated, replaced or truncated; automatic reset is forbidden")
        self._input.seek(0)
        digest = sha256()
        remaining = offset
        while remaining:
            data = self._input.read(min(remaining, 1024 * 1024))
            if not data:
                raise StreamStopped("Source truncated during prefix verification")
            digest.update(data)
            remaining -= len(data)
        if digest.hexdigest() != expected:
            raise StreamStopped("Committed source prefix changed; preserve the original source")

    def _recover(self):
        offset = lines = 0
        for start, end, raw, disposition, reason in self._db.execute(
                "SELECT * FROM stream_records ORDER BY start_offset"):
            if start != offset or end != start + len(raw) or not raw.endswith(b"\n"):
                raise StreamStopped("Journal offset/record continuity check failed")
            if len(raw) > self.limits.max_line_bytes or lines >= self.limits.max_journal_records:
                raise StreamStopped("Journal exceeds configured recovery limits")
            self._digest.update(raw)
            actual = self._consume(raw, lines + 1)
            if actual != (disposition, reason):
                raise StreamStopped("Journal normalization/recovery outcome changed")
            offset, lines = end, lines + 1
        if (offset != self._meta["offset"] or lines != self._meta["lines"] or
                offset > self.limits.max_journal_bytes or
                self._digest.hexdigest() != self._meta["prefix_sha256"]):
            raise StreamStopped("Journal checkpoint/hash mismatch")
        row = self._db.execute("SELECT payload FROM stream_snapshot WHERE id=1").fetchone()
        if lines and (not row or json.loads(row[0])["alerts"] != json.loads(_json(self._alert_records()))):
            raise StreamStopped("Recovered alert evidence differs from committed snapshot")

    def _consume(self, raw, line):
        try:
            text = raw.decode("utf-8-sig" if line == 1 else "utf-8").strip()
            if not text or text.startswith("#"):
                return "ignored", "blank/comment"
            self.quality.records_seen += 1
            record = json.loads(text, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite JSON value")))
            if not isinstance(record, dict):
                raise ValueError("Expected one JSON object per line; containers/manifests are not streams")
            if "records" in record:
                raise ValueError("JSON containers/manifests are not individual stream records")
            prepared = prepare_stream_record(record, self.source.name)
        except (ValueError, UnicodeError, RecursionError) as exc:
            if isinstance(exc, UnicodeError):
                self.quality.records_seen += 1
            if isinstance(exc, ReplayQualityError):
                self.quality.invalid_timestamp_count += exc.quality.invalid_timestamp_count
                self.quality.unsupported_record_count += exc.quality.unsupported_record_count
            return self._reject(line, str(exc)[:500])
        events = prepared.ordered_events()
        canonical = prepared.accepted_records[0]
        key = (record_schema(canonical), str(canonical.get("uid", "")))
        signature = sha256(_json(canonical).encode()).hexdigest()
        timestamp = events[0].timestamp
        reasons = []
        if key in self._uids:
            self.quality.duplicate_uid_count += 1
            exact = self._uids[key] == signature
            field = "exact_duplicate_count" if exact else "conflicting_duplicate_uid_count"
            setattr(self.quality, field, getattr(self.quality, field) + 1)
            reasons.append("duplicate UID within record kind" if exact else "conflicting UID within record kind")
        else:
            self._uids[key] = signature
        if self._latest is not None and timestamp < self._latest:
            self.quality.out_of_order_records += 1
            self.quality.maximum_backward_skew_seconds = max(
                self.quality.maximum_backward_skew_seconds, self._latest - timestamp)
            reasons.append("late timestamp (strict arrival-order policy)")
        self._latest = max(timestamp, self._latest) if self._latest is not None else timestamp
        if reasons:
            return self._reject(line, "; ".join(reasons))
        self._session.process_many(events)
        self.quality.records_accepted += 1
        return "accepted", ""

    def _reject(self, line, reason):
        self.quality.records_rejected += 1
        self.quality.records_quarantined += 1
        message = f"Line {line}: {reason}"
        if len(self.quality.errors) < 5:
            self.quality.errors.append(message)
        if len(self.quality.quarantined_records) < 20:
            self.quality.quarantined_records.append({"line_number": line, "reason": reason})
        return "quarantined", reason

    def _alert_records(self):
        return [alert.to_dict() for alert in self._session.findings()]

    def _report(self, state, pending_bytes, elapsed=0):
        q = self.quality
        q.status = ("unusable" if not q.records_accepted or q.records_rejected / max(q.records_seen, 1) > .10
                    else "degraded" if q.records_rejected else "healthy")
        q.degraded_reasons = [f"{q.records_rejected} rejected/quarantined record(s)"] if q.records_rejected else []
        report = {"run_id": self._meta["run_id"], "status": state, "filename": self.source.name,
                  "quality": q.to_dict(), "analysis_provenance": self._session.provenance(),
                  "feature_coverage": self._session.feature_summary(), "alerts": self._alert_records(),
                  "incidents": [item.to_dict() for item in self._session.incidents()],
                  "stream": {"version": self.version, "committed_offset": self._meta["offset"],
                             "committed_lines": self._meta["lines"], "backlog_bytes": pending_bytes,
                             "queue_high_watermark": self._meta["queue_high_watermark"],
                             "batch_records_limit": self.limits.batch_records,
                             "limits": asdict(self.limits), "batches": self._meta["batches"],
                             "batch_processing_ms": round(elapsed * 1000, 3),
                             "updated_at": time.time(), "return_path_required": False,
                             "delivery": "durable-journal-with-idempotent-at-least-once-projection",
                             "late_policy": "quarantine; never silently reorder",
                             "recovery": "full bounded journal replay; no automatic epoch reset"}}
        return report

    def _publish(self):
        if self.repository is None:
            return
        row = self._db.execute("SELECT payload FROM stream_snapshot WHERE id=1").fetchone()
        if row:
            report = json.loads(row[0])
            project = getattr(self.repository, "project_analysis_run", None)
            if callable(project):
                project(report)
            else:
                # Compatibility for external repositories without atomic projection.
                self.repository.import_records(report["incidents"], report["alerts"])
                self.repository.save_analysis_run(report["run_id"], report)

    def poll(self):
        if self._closed or self._failed:
            raise StreamStopped("Worker closed or failed; reopen from committed checkpoint")
        try:
            self._publish()  # Backpressure: no source consumption while delivery fails.
            self._verify_source(self._meta["offset"], self._meta["prefix_sha256"])
            offset = self._meta["offset"]
            pending = max(0, os.fstat(self._input.fileno()).st_size - offset)
            budget = self.limits.max_journal_bytes - offset
            queue = []
            state = "following"
            for _ in range(min(self.limits.batch_records, self.limits.max_journal_records - self._meta["lines"])):
                if not pending:
                    break
                raw = self._input.readline(min(self.limits.max_line_bytes + 1, pending))
                if len(raw) > self.limits.max_line_bytes:
                    raise StreamStopped("Line exceeds configured byte limit; checkpoint not advanced")
                if not raw.endswith(b"\n"):
                    state = "awaiting_partial_line"
                    break
                if len(raw) > budget:
                    state = "capacity_reached"
                    break
                queue.append(raw)
                budget -= len(raw)
                pending -= len(raw)
            if pending and self._meta["lines"] + len(queue) >= self.limits.max_journal_records:
                state = "capacity_reached"
            started = time.perf_counter()
            with self._db:
                for raw in queue:
                    disposition, reason = self._consume(raw, self._meta["lines"] + 1)
                    self._db.execute("INSERT INTO stream_records VALUES (?, ?, ?, ?, ?)",
                                     (offset, offset + len(raw), raw, disposition, reason))
                    offset += len(raw)
                    self._meta["lines"] += 1
                    self._digest.update(raw)
                self._meta.update(offset=offset, prefix_sha256=self._digest.hexdigest(),
                                  queue_high_watermark=max(len(queue), self._meta["queue_high_watermark"]),
                                  batches=self._meta["batches"] + bool(queue))
                report = self._report(state, os.fstat(self._input.fileno()).st_size - offset,
                                      time.perf_counter() - started)
                self._db.execute("UPDATE stream_meta SET payload=? WHERE id=1", (_json(self._meta),))
                self._db.execute("INSERT OR REPLACE INTO stream_snapshot VALUES (1, ?)", (_json(report),))
            self._publish()
            return report
        except BaseException:
            self._failed = True  # State may have advanced in RAM; only recovery can retry.
            # Keep the last committed evidence/offset; never publish uncommitted RAM.
            try:
                row = self._db.execute("SELECT payload FROM stream_snapshot WHERE id=1").fetchone()
                if row:
                    committed = json.loads(row[0])
                    committed["status"] = "failed"
                    committed["stream"]["updated_at"] = time.time()
                    committed["stream"]["failure"] = "Worker stopped; inspect operator error and restart from checkpoint"
                    with self._db:
                        self._db.execute("UPDATE stream_snapshot SET payload=? WHERE id=1", (_json(committed),))
            except sqlite3.Error:
                pass  # Storage failures cannot be hidden by a fabricated success status.
            raise

    def close(self):
        self._closed = True
        for resource in (self._db, self._input, self._lock):
            if resource is not None:
                resource.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def run_continuous(args):
    """Operator CLI, not a source-accessible HTTP control endpoint."""
    from aegisflow.analysis_session import DEPLOYMENT_BASELINE, UPLOAD_DEMO, STREAM_DEMO
    from aegisflow.api_store import repository_from_url
    if not math.isfinite(args.poll_seconds) or not 0.05 <= args.poll_seconds <= 60:
        raise ValueError("poll-seconds must be between 0.05 and 60")
    profile = {"deployment-baseline": DEPLOYMENT_BASELINE, "upload-demo": UPLOAD_DEMO,
               "stream-demo": STREAM_DEMO}[args.profile]
    # Validate before constructing a repository, which creates schema/sidecars.
    source, checkpoint = args.input.resolve(strict=True), args.checkpoint.resolve()
    destinations = [checkpoint, Path(str(checkpoint) + ".lock")]
    if args.database:
        if "://" in args.database:
            raise ValueError("Sprint 12 projection supports an explicit local SQLite database only")
        destinations.append(Path(args.database).resolve())
    _different_paths(source, [*destinations, *(Path(str(p) + s) for p in destinations
                                             for s in ("-journal", "-wal", "-shm"))])
    repository = repository_from_url(args.database) if args.database else None
    factory = lambda: AnalysisSession.from_root(args.root, profile, model_path=args.model)
    limits = StreamLimits(args.batch_records, args.max_line_bytes,
                          args.max_journal_records, args.max_journal_bytes)
    with ContinuousIngestor(args.input, args.checkpoint, factory, limits=limits, repository=repository) as worker:
        while True:
            report = worker.poll()
            print(_json(report), flush=True)
            if report["status"] == "capacity_reached":
                return 2
            if args.once and (not report["stream"]["backlog_bytes"] or report["status"] == "awaiting_partial_line"):
                return 0
            if not report["stream"]["backlog_bytes"] or report["status"] == "awaiting_partial_line":
                time.sleep(args.poll_seconds)
