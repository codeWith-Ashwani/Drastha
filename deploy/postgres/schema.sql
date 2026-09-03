CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    first_seen DOUBLE PRECISION NOT NULL,
    last_seen DOUBLE PRECISION NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    severity TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    status TEXT NOT NULL DEFAULT 'open',
    payload TEXT NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_queue
    ON incidents(status, severity, risk_score DESC, last_seen DESC);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    incident_id TEXT REFERENCES incidents(incident_id),
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    window_start DOUBLE PRECISION NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id, window_start);

CREATE TABLE IF NOT EXISTS analyst_feedback (
    feedback_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    disposition TEXT NOT NULL,
    analyst TEXT NOT NULL,
    timestamp DOUBLE PRECISION NOT NULL,
    notes TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_feedback_incident
    ON analyst_feedback(incident_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS runtime_state (
    state_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS analysis_runs (
    run_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
