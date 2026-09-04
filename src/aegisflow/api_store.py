from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable


SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    risk_score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    payload TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_queue
    ON incidents(status, severity, risk_score DESC, last_seen DESC);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    incident_id TEXT,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    window_start REAL NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id, window_start);
CREATE TABLE IF NOT EXISTS analyst_feedback (
    feedback_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    disposition TEXT NOT NULL,
    analyst TEXT NOT NULL,
    timestamp REAL NOT NULL,
    notes TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_feedback_incident
    ON analyst_feedback(incident_id, timestamp DESC);
CREATE TABLE IF NOT EXISTS runtime_state (
    state_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS analysis_runs (
    run_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
"""


class _SQLiteConnection:
    def __init__(self, database_path: Path) -> None:
        self._connection = sqlite3.connect(database_path, timeout=10)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")

    def __enter__(self) -> "_SQLiteConnection":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc_type is None:
            self._connection.commit()
        else:
            self._connection.rollback()
        self._connection.close()

    def execute(self, query: str, parameters: Any = ()) -> sqlite3.Cursor:
        return self._connection.execute(query, parameters)

    def executescript(self, script: str) -> None:
        self._connection.executescript(script)


class IncidentRepository:
    """Small persistent store used by the API and offline demonstration.

    SQLite keeps the local demo dependency-free. The same logical schema is also
    provided as PostgreSQL DDL for the production Docker deployment.
    """

    VALID_STATUSES = {"open", "investigating", "resolved", "false_positive"}
    VALID_DISPOSITIONS = {"confirmed_malicious", "benign", "needs_review"}

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()
        if not hasattr(self, "_key"):
            with self._connect() as connection:
                table = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_audit'").fetchone()
                if table and connection.execute("SELECT 1 FROM evidence_audit LIMIT 1").fetchone():
                    raise RuntimeError("Signed evidence store requires its configured audit key")

    def _connect(self) -> _SQLiteConnection:
        return _SQLiteConnection(self.database_path)

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(SCHEMA)

    def import_records(
        self,
        incidents: Iterable[dict[str, Any]],
        alerts: Iterable[dict[str, Any]],
        feedback: Iterable[dict[str, Any]] = (),
    ) -> dict[str, int]:
        incident_records = list(incidents)
        alert_records = list(alerts)
        feedback_records = list(feedback)
        alert_to_incident = {
            alert_id: incident["incident_id"]
            for incident in incident_records
            for alert_id in incident.get("alert_ids", ())
        }
        with self._connect() as connection:
            for incident in incident_records:
                connection.execute(
                    """INSERT INTO incidents(
                        incident_id, src_ip, first_seen, last_seen, risk_score,
                        severity, confidence, status, payload, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        src_ip=excluded.src_ip, first_seen=excluded.first_seen,
                        last_seen=excluded.last_seen, risk_score=excluded.risk_score,
                        severity=excluded.severity, confidence=excluded.confidence,
                        payload=excluded.payload, updated_at=excluded.updated_at""",
                    (
                        incident["incident_id"], incident["src_ip"], incident["first_seen"],
                        incident["last_seen"], incident["risk_score"], incident["severity"],
                        incident["confidence"], incident.get("status", "open"),
                        json.dumps(incident, sort_keys=True), incident["last_seen"],
                    ),
                )
            for alert in alert_records:
                connection.execute(
                    """INSERT INTO alerts(
                        alert_id, incident_id, threat_type, severity, window_start, payload
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(alert_id) DO UPDATE SET
                        incident_id=excluded.incident_id, payload=excluded.payload""",
                    (
                        alert["alert_id"], alert_to_incident.get(alert["alert_id"]),
                        alert["threat_type"], alert["severity"], alert["window_start"],
                        json.dumps(alert, sort_keys=True),
                    ),
                )
            for item in feedback_records:
                self._insert_feedback(connection, item)
        return {
            "incidents": len(incident_records),
            "alerts": len(alert_records),
            "feedback": len(feedback_records),
        }

    def list_incidents(
        self, *, status: str | None = None, severity: str | None = None
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[str] = []
        if status:
            clauses.append("status = ?")
            parameters.append(status)
        if severity:
            clauses.append("severity = ?")
            parameters.append(severity)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT payload, status FROM incidents{where} "
                "ORDER BY risk_score DESC, last_seen DESC",
                parameters,
            ).fetchall()
        return [self._incident_from_row(row) for row in rows]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, status FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if row is None:
                return None
            alert_rows = connection.execute(
                "SELECT payload FROM alerts WHERE incident_id = ? ORDER BY window_start",
                (incident_id,),
            ).fetchall()
            feedback_rows = connection.execute(
                "SELECT * FROM analyst_feedback WHERE incident_id = ? ORDER BY timestamp DESC",
                (incident_id,),
            ).fetchall()
        incident = self._incident_from_row(row)
        incident["alerts"] = [json.loads(item["payload"]) for item in alert_rows]
        incident["feedback"] = [dict(item) for item in feedback_rows]
        return incident

    def list_alerts(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM alerts ORDER BY window_start, alert_id"
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def save_analysis_run(self, run_id: str, report: dict[str, Any]) -> None:
        """Persist scoped provisional/final results without polluting incident tables."""
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO analysis_runs(run_id, payload) VALUES (?, ?) "
                "ON CONFLICT(run_id) DO UPDATE SET payload=excluded.payload",
                (run_id, json.dumps(report, sort_keys=True)),
            )

    def get_analysis_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM analysis_runs WHERE run_id = ?", (run_id,)).fetchone()
        return json.loads(row["payload"]) if row is not None else None

    def set_status(self, incident_id: str, status: str, updated_at: float) -> bool:
        if status not in self.VALID_STATUSES:
            raise ValueError(f"invalid incident status: {status}")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if row is None:
                return False
            payload = json.loads(row["payload"])
            payload["status"] = status
            connection.execute(
                "UPDATE incidents SET status = ?, payload = ?, updated_at = ? WHERE incident_id = ?",
                (status, json.dumps(payload, sort_keys=True), updated_at, incident_id),
            )
        return True

    def add_feedback(self, record: dict[str, Any]) -> dict[str, Any]:
        if record["disposition"] not in self.VALID_DISPOSITIONS:
            raise ValueError(f"invalid disposition: {record['disposition']}")
        if not str(record["analyst"]).strip():
            raise ValueError("analyst is required")
        with self._connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM incidents WHERE incident_id = ?", (record["incident_id"],)
            ).fetchone()
            if exists is None:
                raise KeyError(record["incident_id"])
            self._insert_feedback(connection, record)
        return record

    def metrics(self) -> dict[str, Any]:
        with self._connect() as connection:
            total = _scalar(connection.execute("SELECT COUNT(*) FROM incidents").fetchone())
            open_count = _scalar(connection.execute(
                "SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'investigating')"
            ).fetchone())
            critical = _scalar(connection.execute(
                "SELECT COUNT(*) FROM incidents WHERE severity = 'critical'"
            ).fetchone())
            reviewed = _scalar(connection.execute("SELECT COUNT(*) FROM analyst_feedback").fetchone())
            average_risk = _scalar(connection.execute(
                "SELECT COALESCE(AVG(risk_score), 0) FROM incidents"
            ).fetchone())
        return {
            "total_incidents": total,
            "active_incidents": open_count,
            "critical_incidents": critical,
            "feedback_records": reviewed,
            "average_risk_score": round(float(average_risk), 1),
        }

    def get_runtime_state(self, state_key: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM runtime_state WHERE state_key = ?", (state_key,)
            ).fetchone()
        return json.loads(row["payload"]) if row is not None else None

    def put_runtime_state(
        self, state_key: str, payload: dict[str, Any], updated_at: float
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO runtime_state(state_key, payload, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(state_key) DO UPDATE SET
                    payload=excluded.payload, updated_at=excluded.updated_at""",
                (state_key, json.dumps(payload, sort_keys=True), updated_at),
            )

    def delete_runtime_state(self, state_key: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM runtime_state WHERE state_key = ?", (state_key,)
            )
        return cursor.rowcount > 0

    @staticmethod
    def _insert_feedback(connection: Any, record: dict[str, Any]) -> None:
        connection.execute(
            """INSERT INTO analyst_feedback(
                feedback_id, incident_id, disposition, analyst, timestamp, notes
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(feedback_id) DO UPDATE SET notes=excluded.notes""",
            (
                record["feedback_id"], record["incident_id"], record["disposition"],
                str(record["analyst"]).strip(), record["timestamp"],
                str(record.get("notes", "")).strip(),
            ),
        )

    @staticmethod
    def _incident_from_row(row: sqlite3.Row) -> dict[str, Any]:
        incident = json.loads(row["payload"])
        incident["status"] = row["status"]
        return incident


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    with Path(path).open("r", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def repository_from_url(database: str | Path) -> IncidentRepository:
    value = str(database)
    if os.getenv("DRASTHA_AUDIT_KEY_FILE"):
        if value.startswith(("postgres://", "postgresql://")):
            raise ValueError("Signed evidence mode currently supports local SQLite only")
        from aegisflow.security import load_audit_key
        from aegisflow.audited_store import AuditedIncidentRepository
        return AuditedIncidentRepository(value, load_audit_key())
    if value.startswith(("postgres://", "postgresql://")):
        from aegisflow.postgres_store import PostgreSQLIncidentRepository
        return PostgreSQLIncidentRepository(value)
    return IncidentRepository(value)


def _scalar(row: Any) -> Any:
    if isinstance(row, dict):
        return next(iter(row.values()))
    return row[0]
