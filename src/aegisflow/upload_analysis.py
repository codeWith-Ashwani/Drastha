from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from aegisflow.detectors import (
    C2BeaconDetector,
    DDoSConfig,
    DDoSDetector,
    ExfiltrationDetector,
    ReconConfig,
    ReconDetector,
)
from aegisflow.incidents import IncidentStore
from aegisflow.ingestion.zeek_jsonl import ZeekRecordError, normalize_conn_record
from aegisflow.pipeline import run_pipeline
from aegisflow.telemetry_quality import TelemetryQuality


MAX_UPLOAD_BYTES = 5_000_000
MAX_UPLOAD_RECORDS = 20_000
ALLOWED_SUFFIXES = {".jsonl", ".ndjson", ".json"}


def _records_from_content(content: str) -> list[tuple[int, Any]]:
    stripped = content.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON at line {exc.lineno}: {exc.msg}") from exc
        if not isinstance(parsed, list):
            raise ValueError("A JSON upload must contain an array of connection records.")
        return list(enumerate(parsed, start=1))

    records: list[tuple[int, Any]] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            records.append((line_number, json.loads(value)))
        except json.JSONDecodeError as exc:
            records.append((line_number, exc))
    return records


def analyse_uploaded_replay(
    filename: str,
    content: str,
    repository: Any,
) -> dict[str, Any]:
    started = time.perf_counter()
    safe_name = Path(filename).name[:120]
    suffix = Path(safe_name).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise ValueError("Upload a Zeek connection replay as .jsonl, .ndjson or .json.")
    upload_bytes = len(content.encode("utf-8"))
    if upload_bytes > MAX_UPLOAD_BYTES:
        raise ValueError("Replay file is larger than the 5 MB demonstration limit.")

    raw_records = _records_from_content(content)
    if len(raw_records) > MAX_UPLOAD_RECORDS:
        raise ValueError("Replay contains more than 20,000 records.")

    quality = TelemetryQuality(stream="judge_upload:zeek_conn", source=safe_name)
    events = []
    latest_timestamp: float | None = None
    for line_number, raw in raw_records:
        quality.records_seen += 1
        try:
            if isinstance(raw, json.JSONDecodeError):
                raise ZeekRecordError(
                    f"line {line_number}: invalid JSON at column {raw.colno}: {raw.msg}"
                )
            if not isinstance(raw, dict):
                raise ZeekRecordError(f"line {line_number}: expected a JSON object")
            event = normalize_conn_record(raw, line_number)
        except ZeekRecordError as exc:
            quality.records_rejected += 1
            if len(quality.errors) < 5:
                quality.errors.append(str(exc))
            continue
        if latest_timestamp is not None and event.timestamp < latest_timestamp:
            quality.out_of_order_records += 1
            quality.maximum_backward_skew_seconds = max(
                quality.maximum_backward_skew_seconds, latest_timestamp - event.timestamp
            )
        latest_timestamp = max(event.timestamp, latest_timestamp or event.timestamp)
        quality.records_accepted += 1
        events.append(event)

    rejection_ratio = quality.records_rejected / max(quality.records_seen, 1)
    if not events or rejection_ratio > 0.10:
        quality.status = "unusable"
    elif quality.records_rejected or quality.out_of_order_records:
        quality.status = "degraded"
    quality.maximum_backward_skew_seconds = round(quality.maximum_backward_skew_seconds, 6)
    if quality.status == "unusable":
        reason = quality.errors[0] if quality.errors else "No valid Zeek connection records were found."
        raise ValueError(f"Replay could not be analysed: {reason}")

    detection_started = time.perf_counter()
    detectors = [
        ReconDetector(ReconConfig(unique_port_threshold=5, unique_host_threshold=5)),
        DDoSDetector(DDoSConfig(syn_attempt_threshold=5, udp_packet_threshold=500)),
        C2BeaconDetector(),
        ExfiltrationDetector(),
    ]
    alerts = list(run_pipeline(events, detectors))
    detection_ms = round((time.perf_counter() - detection_started) * 1000, 3)

    correlation_started = time.perf_counter()
    correlator = IncidentStore()
    for alert in alerts:
        correlator.process(alert)
    incidents = list(correlator.all())
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

    return {
        "status": "completed",
        "verdict": verdict,
        "headline": headline,
        "summary": summary,
        "filename": safe_name,
        "file_size_bytes": upload_bytes,
        "analysis_ms": elapsed_ms,
        "quality": quality.to_dict(),
        "alerts": alert_records,
        "incidents": incident_records,
        "top_incident_id": top_incident["incident_id"] if top_incident else None,
        "loaded": loaded,
        "stages": [
            {"name": "Read replay", "status": "completed", "detail": "Accepted one-way network records", "records": quality.records_accepted, "duration_ms": 0.0},
            {"name": "Check data", "status": quality.status, "detail": "Checked required fields and time order", "records": quality.records_accepted, "rejected": quality.records_rejected, "duration_ms": 0.0},
            {"name": "Find behaviour", "status": "detected" if alerts else "no_alert", "detail": "Checked scanning, flooding, callbacks and outbound transfer", "alerts": len(alerts), "duration_ms": detection_ms},
            {"name": "Connect findings", "status": "critical" if any(item.severity == "critical" for item in incidents) else "completed", "detail": "Grouped related findings into incidents", "incidents": len(incidents), "duration_ms": correlation_ms},
            {"name": "Show result", "status": "ready", "detail": "Stored evidence and prepared the judge view", "incidents": len(incidents), "duration_ms": persistence_ms},
        ],
        "scope_note": "Demonstration thresholds are used. Production deployment requires environment-specific calibration.",
    }
