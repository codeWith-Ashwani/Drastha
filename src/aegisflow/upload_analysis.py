from __future__ import annotations

import json
import os
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from aegisflow.detectors import (
    C2BeaconDetector,
    DDoSConfig,
    DDoSDetector,
    ExfiltrationDetector,
    DNSConfig,
    DNSDetector,
    EncryptedSessionAnomalyDetector,
    ReconConfig,
    ReconDetector,
)
from aegisflow.incidents import IncidentStore
from aegisflow.context_policy import load_context_policy
from aegisflow.dns_model import DNSNgramModel
from aegisflow.ingestion.zeek_dns import normalize_dns_record
from aegisflow.ingestion.zeek_encrypted import normalize_encrypted_record
from aegisflow.ingestion.zeek_jsonl import ZeekRecordError, normalize_conn_record
from aegisflow.models import Alert, Evidence
from aegisflow.pipeline import run_pipeline
from aegisflow.telemetry_quality import TelemetryQuality


MAX_UPLOAD_BYTES = 5_000_000
MAX_UPLOAD_RECORDS = 20_000
ALLOWED_SUFFIXES = {".jsonl", ".ndjson", ".json"}


def _records_from_content(content: str) -> list[tuple[int, Any]]:
    stripped = content.strip()
    if not stripped:
        return []
    if stripped.startswith(("[", "{")):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            # A valid JSONL file also starts with "{" but contains several
            # complete JSON documents. Fall through to the per-line parser for
            # that specific "extra data" case.
            if exc.msg != "Extra data":
                raise ValueError(f"Invalid JSON at line {exc.lineno}: {exc.msg}") from exc
        else:
            if isinstance(parsed, dict) and isinstance(parsed.get("records"), list):
                parsed = parsed["records"]
            elif isinstance(parsed, dict):
                parsed = [parsed]
            if not isinstance(parsed, list):
                raise ValueError(
                    "A JSON upload must be an array, one record object, or an object containing a records array."
                )
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


def _features(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get(
        "features", record.get("ml_evidence", record.get("evidence", {}))
    )
    return value if isinstance(value, dict) else {}


def _dns_record(record: dict[str, Any]) -> dict[str, Any] | None:
    features = _features(record)
    query = record.get("query") or features.get("query_name")
    if not query:
        return None
    return {
        **record,
        "query": query,
        "qtype_name": record.get("qtype_name") or features.get("record_type") or "UNKNOWN",
        "rcode_name": record.get("rcode_name", "UNKNOWN"),
    }


def _has_encrypted_features(record: dict[str, Any]) -> bool:
    features = _features(record)
    return bool(
        record.get("ja3")
        or record.get("ja4")
        or features.get("ja3")
        or features.get("ja4")
    )


def _deduplicate_and_resolve_conflicts(alerts: list[Alert]) -> list[Alert]:
    """Suppress cross-detector contradictions and merge repeated findings."""
    recon_alerts = [item for item in alerts if item.threat_type == "reconnaissance"]
    resolved: list[Alert] = []
    for alert in alerts:
        if alert.subtype in {"syn_flood", "distributed_syn_flood"}:
            flows = set(alert.flow_ids)
            if any(
                recon.src_ip == alert.src_ip and flows.intersection(recon.flow_ids)
                for recon in recon_alerts
            ):
                continue
        resolved.append(alert)

    grouped: dict[tuple[str, str, str, str | None], Alert] = {}
    counts: dict[tuple[str, str, str, str | None], int] = {}
    for alert in resolved:
        key = (alert.threat_type, alert.subtype, alert.src_ip, alert.dst_ip)
        counts[key] = counts.get(key, 0) + 1
        previous = grouped.get(key)
        if previous is None:
            grouped[key] = alert
            continue
        strongest = alert if alert.confidence > previous.confidence else previous
        grouped[key] = replace(
            strongest,
            confidence=max(previous.confidence, alert.confidence),
            window_start=min(previous.window_start, alert.window_start),
            window_end=max(previous.window_end, alert.window_end),
            flow_ids=tuple(dict.fromkeys((*previous.flow_ids, *alert.flow_ids))),
        )

    output: list[Alert] = []
    for key, alert in grouped.items():
        duplicate_count = counts[key] - 1
        if duplicate_count:
            alert = replace(
                alert,
                evidence=(*alert.evidence, Evidence(
                    "related_findings_merged",
                    duplicate_count,
                    "deduplicated",
                    "Repeated findings from the same source and threat family were merged into one analyst alert.",
                )),
            )
        output.append(alert)
    return sorted(output, key=lambda item: (item.window_start, item.threat_type, item.subtype))


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
    dns_events = []
    encrypted_events = []
    latest_timestamp: float | None = None
    for line_number, raw in raw_records:
        quality.records_seen += 1
        if isinstance(raw, json.JSONDecodeError):
            error = ZeekRecordError(
                f"line {line_number}: invalid JSON at column {raw.colno}: {raw.msg}"
            )
            quality.records_rejected += 1
            if len(quality.errors) < 5:
                quality.errors.append(str(error))
            continue
        if not isinstance(raw, dict):
            quality.records_rejected += 1
            if len(quality.errors) < 5:
                quality.errors.append(f"line {line_number}: expected a JSON object")
            continue

        record_timestamps: list[float] = []
        connection_error: ZeekRecordError | None = None
        try:
            event = normalize_conn_record(raw, line_number)
        except ZeekRecordError as exc:
            connection_error = exc
        else:
            events.append(event)
            record_timestamps.append(event.timestamp)

        dns_source = _dns_record(raw)
        if dns_source is not None:
            try:
                dns_event = normalize_dns_record(dns_source, line_number)
            except ZeekRecordError:
                pass
            else:
                dns_events.append(dns_event)
                record_timestamps.append(dns_event.timestamp)
        if _has_encrypted_features(raw):
            try:
                encrypted_event = normalize_encrypted_record(raw, line_number)
            except ZeekRecordError:
                pass
            else:
                encrypted_events.append(encrypted_event)
                record_timestamps.append(encrypted_event.timestamp)

        if not record_timestamps:
            quality.records_rejected += 1
            if len(quality.errors) < 5:
                quality.errors.append(str(
                    connection_error
                    or ZeekRecordError(
                        f"line {line_number}: no supported connection, DNS, or encrypted-session metadata"
                    )
                ))
            continue

        record_timestamp = min(record_timestamps)
        if latest_timestamp is not None and record_timestamp < latest_timestamp:
            quality.out_of_order_records += 1
            quality.maximum_backward_skew_seconds = max(
                quality.maximum_backward_skew_seconds, latest_timestamp - record_timestamp
            )
        latest_timestamp = max(record_timestamp, latest_timestamp or record_timestamp)
        quality.records_accepted += 1

    rejection_ratio = quality.records_rejected / max(quality.records_seen, 1)
    if not (events or dns_events or encrypted_events) or rejection_ratio > 0.10:
        quality.status = "unusable"
    elif quality.records_rejected or quality.out_of_order_records:
        quality.status = "degraded"
    quality.maximum_backward_skew_seconds = round(quality.maximum_backward_skew_seconds, 6)
    if quality.status == "unusable":
        reason = quality.errors[0] if quality.errors else "No supported passive telemetry records were found."
        raise ValueError(f"Replay could not be analysed: {reason}")

    detection_started = time.perf_counter()
    root = Path(os.getenv("DRASTHA_ROOT") or Path(__file__).resolve().parents[2])
    context_policy = load_context_policy(root)
    recon_detector = ReconDetector(
        ReconConfig(unique_port_threshold=5, unique_host_threshold=5)
    )
    c2_detector = C2BeaconDetector(
        trusted_periodic_endpoints=context_policy.trusted_periodic_endpoints
    )
    exfiltration_detector = ExfiltrationDetector(
        approved_bulk_transfer_endpoints=context_policy.approved_bulk_transfer_endpoints
    )
    detectors = [
        recon_detector,
        DDoSDetector(DDoSConfig(syn_attempt_threshold=5, udp_packet_threshold=500)),
        c2_detector,
        exfiltration_detector,
    ]
    events.sort(key=lambda item: item.timestamp)
    dns_events.sort(key=lambda item: item.timestamp)
    encrypted_events.sort(key=lambda item: item.timestamp)
    alerts = list(run_pipeline(events, detectors))
    alerts = [item for item in alerts if item.threat_type != "reconnaissance"]
    alerts.extend(recon_detector.final_alerts())

    model_path = root / "output" / "models" / "dns_dga_demo.json"
    dns_model = DNSNgramModel.load(model_path) if model_path.is_file() else None
    dns_detector = DNSDetector(DNSConfig(), model=dns_model)
    for event in dns_events:
        alerts.extend(dns_detector.process(event))

    encrypted_detector = EncryptedSessionAnomalyDetector()
    for event in encrypted_events:
        alerts.extend(encrypted_detector.process(event))

    alerts = _deduplicate_and_resolve_conflicts(alerts)
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
                c2_detector.context_suppressed_records
                + exfiltration_detector.context_suppressed_records
            ),
        },
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
        "scope_note": "Demonstration thresholds are used. Production deployment requires environment-specific calibration.",
    }
