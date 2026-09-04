"""SQLite signed evidence ledger and conservative completed-report retention.

HMAC detects DB-only modifications. An independently retained head is necessary
to detect rollback/truncation of the entire database; key/host compromise is not
solved. All repository operations verify the chain and current protected state.
"""
from __future__ import annotations

from hashlib import sha256
import hmac
import json
import math
import sqlite3
import time

from aegisflow.api_store import IncidentRepository, _SQLiteConnection
from aegisflow.security import audit_actor, audit_operation


class EvidenceIntegrityError(RuntimeError):
    pass


TABLES = {"incidents": "incident_id", "alerts": "alert_id", "analyst_feedback": "feedback_id",
          "analysis_runs": "run_id", "runtime_state": "state_key", "evidence_retention": "run_id"}
AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_audit (
    sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, mac TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence_retention (
    run_id TEXT PRIMARY KEY, stored_at REAL NOT NULL, held INTEGER NOT NULL DEFAULT 0);
"""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def snapshot(connection):
    result = {}
    for table, identity in TABLES.items():
        for row in connection.execute(f"SELECT * FROM {table} ORDER BY {identity}").fetchall():
            result[(table, str(row[identity]))] = sha256(canonical(dict(row)).encode()).hexdigest()
    return result


def state_digest(state):
    return sha256(canonical([[*key, value] for key, value in sorted(state.items())]).encode()).hexdigest()


class _AuditedConnection(_SQLiteConnection):
    def __init__(self, repository):
        super().__init__(repository.database_path)
        self.repository = repository
        self.event = None

    def __enter__(self):
        try:
            self.execute("BEGIN IMMEDIATE")
            self.before = snapshot(self)
            self.head = self.repository._verify(self, self.before)
            return self
        except sqlite3.Error as exc:
            self._connection.close()
            raise EvidenceIntegrityError("Signed evidence storage verification failed") from exc
        except BaseException:
            self._connection.close()
            raise

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type is None:
                after = snapshot(self)
                retention_changed = False
                # Retention age follows trusted local storage time, never traffic ts.
                for (table, identity), digest in after.items():
                    if table == "analysis_runs" and self.before.get((table, identity)) != digest:
                        self.execute("INSERT INTO evidence_retention(run_id, stored_at) VALUES (?, ?) "
                                     "ON CONFLICT(run_id) DO UPDATE SET stored_at=excluded.stored_at",
                                     (identity, time.time()))
                        retention_changed = True
                # The existing full snapshot already represents the transaction
                # unless trusted retention bookkeeping added another change.
                if retention_changed:
                    after = snapshot(self)
                if after != self.before or self.event is not None:
                    changes = [{"table": key[0], "id": key[1], "before": self.before.get(key),
                                "after": after.get(key)} for key in sorted(self.before.keys() | after.keys())
                               if self.before.get(key) != after.get(key)]
                    self.repository._append(self, self.head, after, changes, self.event)
                self._connection.commit()
            else:
                self._connection.rollback()
        except BaseException:
            self._connection.rollback()
            raise
        finally:
            self._connection.close()


class AuditedIncidentRepository(IncidentRepository):
    def __init__(self, database_path, key):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("Signed evidence requires a 32-byte external HMAC key")
        self._key = key
        self._ready = False
        super().__init__(database_path)
        with IncidentRepository._connect(self) as connection:
            connection.executescript(AUDIT_SCHEMA)
            connection.execute("BEGIN IMMEDIATE")
            current = snapshot(connection)
            if not connection.execute("SELECT 1 FROM evidence_audit LIMIT 1").fetchone():
                if current:
                    raise EvidenceIntegrityError("Cannot silently certify existing unsigned evidence; use a fresh signed store")
                self._append(connection, {"sequence": 0, "mac": "0" * 64}, current, [], "genesis")
            else:
                self._verify(connection, current)
        self._ready = True

    def _connect(self):
        return _AuditedConnection(self) if self._ready else IncidentRepository._connect(self)

    def _append(self, connection, head, state, changes, event):
        record = {"version": "drastha-evidence-hmac-v1", "sequence": head["sequence"] + 1,
                  "previous_mac": head["mac"], "timestamp": time.time(),
                  "actor": audit_actor.get(), "operation": audit_operation.get(),
                  "event": event or "state_change", "changes": changes, "state_sha256": state_digest(state)}
        payload = canonical(record)
        mac = hmac.new(self._key, payload.encode(), "sha256").hexdigest()
        connection.execute("INSERT INTO evidence_audit VALUES (?, ?, ?)", (record["sequence"], payload, mac))

    def _verify(self, connection, state):
        return verify_connection(connection, state, self._key)

    def verify_evidence(self, expected_head=None):
        with self._connect() as connection:
            head = connection.head
            if expected_head is not None and head != expected_head:
                raise EvidenceIntegrityError("Evidence head differs from the independently retained checkpoint")
            return {"verified": True, "head": head,
                    "scheme": "HMAC-SHA256 chain plus current database state digest",
                    "limitation": "Retain head independently; database-only checks cannot detect whole-store rollback"}

    def record_audit_event(self, event):
        with self._connect() as connection:
            connection.event = event

    def sign_export(self, payload):
        digest = sha256(canonical(payload).encode()).hexdigest()
        self.record_audit_event("export_sha256:" + digest)
        receipt = {"version": "drastha-export-hmac-v1", "payload_sha256": digest,
                   "audit": self.verify_evidence()}
        return {**receipt, "mac": hmac.new(self._key, canonical(receipt).encode(), "sha256").hexdigest()}

    def verify_export(self, payload, receipt):
        expected = dict(receipt)
        mac = expected.pop("mac", "")
        return (hmac.compare_digest(sha256(canonical(payload).encode()).hexdigest(), expected.get("payload_sha256", ""))
                and hmac.compare_digest(hmac.new(self._key, canonical(expected).encode(), "sha256").hexdigest(), mac))

    def set_retention_hold(self, run_id, held):
        if type(held) is not bool:
            raise ValueError("held must be a boolean")
        with self._connect() as connection:
            if not connection.execute("SELECT 1 FROM analysis_runs WHERE run_id=?", (run_id,)).fetchone():
                raise KeyError(run_id)
            connection.execute("UPDATE evidence_retention SET held=? WHERE run_id=?", (int(held), run_id))
            connection.event = "retention_hold"

    def _retention_plan(self, connection, before):
        if not math.isfinite(before) or before <= 0 or before > time.time():
            raise ValueError("Retention cutoff must be a finite past Unix timestamp")
        candidates = []
        for row in connection.execute("SELECT r.run_id, r.payload FROM analysis_runs r JOIN evidence_retention t "
                                      "ON r.run_id=t.run_id WHERE t.stored_at < ? AND t.held=0 ORDER BY r.run_id",
                                      (before,)).fetchall():
            if json.loads(row["payload"]).get("status") == "completed":
                candidates.append(row["run_id"])
                if len(candidates) == 500:
                    break
        plan = {"scope": "completed_analysis_run_reports_only", "before": before,
                "run_ids": candidates, "head_mac": connection.head["mac"], "limit": 500,
                "preserved": ["incidents", "alerts", "feedback", "runtime_state", "active_stream_reports", "held_reports", "source_files", "stream_journals"]}
        return {**plan, "plan_sha256": sha256(canonical(plan).encode()).hexdigest()}

    def retention_plan(self, before):
        with self._connect() as connection:
            return self._retention_plan(connection, before)

    def apply_retention(self, before, plan_sha256):
        with self._connect() as connection:
            plan = self._retention_plan(connection, before)
            if not hmac.compare_digest(plan["plan_sha256"], plan_sha256):
                raise ValueError("Retention plan is stale or changed; preview again")
            for run_id in plan["run_ids"]:
                connection.execute("DELETE FROM analysis_runs WHERE run_id=?", (run_id,))
                connection.execute("DELETE FROM evidence_retention WHERE run_id=?", (run_id,))
            connection.event = "retention_applied"
            return {"deleted_reports": len(plan["run_ids"]), "run_ids": plan["run_ids"],
                    "recoverability": "Application deletion is not secure erasure; recovery requires a separately retained backup"}


def verify_connection(connection, state, key):
    """Shared verifier for repository transactions and read-only recovery tools."""
    sequence, previous = 0, "0" * 64
    expected_state = None
    try:
        for row in connection.execute("SELECT * FROM evidence_audit ORDER BY sequence").fetchall():
            record = json.loads(row["payload"])
            mac = hmac.new(key, row["payload"].encode(), "sha256").hexdigest()
            if (row["sequence"] != sequence + 1 or record["sequence"] != row["sequence"] or
                    record["previous_mac"] != previous or record["version"] != "drastha-evidence-hmac-v1" or
                    not hmac.compare_digest(mac, row["mac"])):
                raise EvidenceIntegrityError("Evidence audit chain verification failed")
            sequence, previous, expected_state = row["sequence"], row["mac"], record["state_sha256"]
        if expected_state is None or not hmac.compare_digest(expected_state, state_digest(state)):
            raise EvidenceIntegrityError("Evidence contents do not match the signed audit head")
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceIntegrityError("Malformed signed evidence ledger") from exc
    return {"sequence": sequence, "mac": previous, "state_sha256": expected_state}
