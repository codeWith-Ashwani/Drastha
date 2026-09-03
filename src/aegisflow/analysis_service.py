from __future__ import annotations

import os
import time
from pathlib import Path
from uuid import uuid4
from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO
from aegisflow.evaluation_scoring import score_ground_truth


def analyse_prepared(prepared, repository, *, filename="passive-replay", upload_bytes=0,
                     started=None, profile=UPLOAD_DEMO, root=None, model_path=None):
    """Shared completed analysis; input adapters own file limits and source loading."""
    started = time.perf_counter() if started is None else started
    safe_name = filename
    quality = prepared.quality
    events, dns_events, encrypted_events = prepared.events, prepared.dns_events, prepared.encrypted_events
    accepted_records = prepared.accepted_records

    detection_started = time.perf_counter()
    root = Path(root or os.getenv("DRASTHA_ROOT") or Path(__file__).resolve().parents[2])
    session = AnalysisSession.from_root(root, profile, model_path=model_path)
    context_policy = session.context_policy
    session.process_many(prepared.ordered_events())
    alerts = session.findings(complete=True)
    evaluation = score_ground_truth(
        accepted_records, alerts
    )
    detection_ms = round((time.perf_counter() - detection_started) * 1000, 3)

    correlation_started = time.perf_counter()
    incidents = session.incidents()
    correlation_ms = round((time.perf_counter() - correlation_started) * 1000, 3)

    persistence_started = time.perf_counter()
    loaded = repository.import_records(
        [incident.to_dict() for incident in incidents],
        [alert.to_dict() for alert in alerts],
    )
    persistence_ms = round((time.perf_counter() - persistence_started) * 1000, 3)
    incident_records = [incident.to_dict() for incident in incidents]
    top_incident = max(incident_records, key=lambda item: item["risk_score"], default=None)
    alert_records = [alert.to_dict() for alert in alerts]
    threat_names = sorted({alert.threat_type for alert in alerts})
    source_ips = sorted({alert.src_ip for alert in alerts})
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)

    if alerts:
        headline = f"{len(alerts)} suspicious behaviour{'s' if len(alerts) != 1 else ''} found"
        summary = (
            f"Drastha found {', '.join(name.replace('_', ' ') for name in threat_names)} "
            f"in traffic linked to {', '.join(source_ips)}."
        )
        verdict = "threat_detected"
    else:
        headline = "No configured threat pattern found"
        summary = (
            "The replay passed validation, but it did not cross the demonstration thresholds "
            "for scanning, flooding, repeated callbacks or unusual outbound transfer."
        )
        verdict = "no_threat_detected"

    report = {
        "status": "completed",
        "verdict": verdict,
        "headline": headline,
        "summary": summary,
        "filename": safe_name,
        "file_size_bytes": upload_bytes,
        "analysis_ms": elapsed_ms,
        "analysis_provenance": session.provenance(),
        "quality": quality.to_dict(),
        "input_schema": prepared.input_schema,
        "telemetry": {
            "connection_records": len(events),
            "dns_records": len(dns_events),
            "encrypted_session_records": len(encrypted_events),
            "supplied_labels_ignored": True,
        },
        "context_policy": {
            "source": context_policy.source,
            "trusted_periodic_rules": len(context_policy.trusted_periodic_endpoints),
            "approved_bulk_transfer_rules": len(
                context_policy.approved_bulk_transfer_endpoints
            ),
            "suppressed_connection_evaluations": (
                session.c2.context_suppressed_records
                + session.exfiltration.context_suppressed_records
            ),
        },
        "evaluation": evaluation,
        "alerts": alert_records,
        "incidents": incident_records,
        "top_incident_id": top_incident["incident_id"] if top_incident else None,
        "loaded": loaded,
        "stages": [
            {"name": "Read replay", "status": "completed", "detail": "Accepted one-way network records", "records": quality.records_accepted, "duration_ms": 0.0},
            {"name": "Check data", "status": quality.status, "detail": "Checked required fields and time order", "records": quality.records_accepted, "rejected": quality.records_rejected, "duration_ms": 0.0},
            {"name": "Find behaviour", "status": "detected" if alerts else "no_alert", "detail": "Ran threat-specific scan, flood, DNS, encrypted-session, callback and exfiltration analysis", "alerts": len(alerts), "duration_ms": detection_ms},
            {"name": "Connect findings", "status": "critical" if any(item.severity == "critical" for item in incidents) else "completed", "detail": "Grouped related findings into incidents", "incidents": len(incidents), "duration_ms": correlation_ms},
            {"name": "Show result", "status": "ready", "detail": "Stored evidence and prepared the judge view", "incidents": len(incidents), "duration_ms": persistence_ms},
        ],
        "scope_note": f"Profile: {profile.name}. Production deployment requires environment-specific calibration.",
    }
    report["run_id"] = uuid4().hex
    if hasattr(repository, "save_analysis_run"):
        repository.save_analysis_run(report["run_id"], report)
    return report
