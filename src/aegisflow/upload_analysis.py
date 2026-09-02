from __future__ import annotations

import json
import os
import time
from collections import Counter
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
from aegisflow.evaluation_scoring import score_ground_truth
from aegisflow.dns_model import DNSNgramModel
from aegisflow.ingestion.zeek_dns import normalize_dns_record
from aegisflow.ingestion.zeek_encrypted import normalize_encrypted_record
from aegisflow.ingestion.zeek_jsonl import ZeekRecordError, normalize_conn_record
from aegisflow.ingestion.zeek_jsonl import normalize_field_aliases
from aegisflow.ingestion.replay_input import (
    parse_replay_content,
    record_schema,
    schema_summary,
)
from aegisflow.models import Alert, Evidence
from aegisflow.pipeline import run_pipeline
from aegisflow.telemetry_quality import TelemetryQuality


MAX_UPLOAD_BYTES = 5_000_000
MAX_UPLOAD_RECORDS = 20_000
ALLOWED_SUFFIXES = {".jsonl", ".ndjson", ".json"}


def _records_from_content(content: str) -> list[tuple[int, Any]]:
    return list(parse_replay_content(content).records)


def _features(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get(
        "features", record.get("ml_evidence", record.get("evidence", {}))
    )
    return value if isinstance(value, dict) else {}


def _dns_record(record: dict[str, Any]) -> dict[str, Any] | None:
    features = _features(record)
    query = record.get("query") or record.get("query_name") or features.get("query_name")
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
        if alert.subtype in {"syn_flood", "distributed_source_syn_flood"}:
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

    parsed_replay = parse_replay_content(content, safe_name)
    raw_records = list(parsed_replay.records)
    if len(raw_records) > MAX_UPLOAD_RECORDS:
        raise ValueError("Replay contains more than 20,000 records.")

    quality = TelemetryQuality(stream="judge_upload:zeek_conn", source=safe_name)
    events = []
    dns_events = []
    encrypted_events = []
    accepted_records: list[dict[str, Any]] = []
    alias_usage: Counter[tuple[str, str]] = Counter()
    schema_counts: Counter[str] = Counter()
    seen_uids: dict[str, str] = {}
    latest_timestamp: float | None = None
    for line_number, raw in raw_records:
        quality.records_seen += 1
        if isinstance(raw, ZeekRecordError):
            error = raw
            quality.records_rejected += 1
            quality.records_quarantined += 1
            if len(quality.errors) < 5:
                quality.errors.append(str(error))
            quality.quarantined_records.append(error.to_dict())
            continue
        if not isinstance(raw, dict):
            error = ZeekRecordError(
                f"Line {line_number}: unsupported record; expected a JSON object.",
                line_number=line_number,
                category="unsupported_record",
            )
            quality.records_rejected += 1
            quality.records_quarantined += 1
            quality.unsupported_record_count += 1
            if len(quality.errors) < 5:
                quality.errors.append(str(error))
            quality.quarantined_records.append(error.to_dict())
            continue

        try:
            canonical, aliases = normalize_field_aliases(raw, line_number)
        except ZeekRecordError as exc:
            quality.records_rejected += 1
            quality.records_quarantined += 1
            if len(quality.errors) < 5:
                quality.errors.append(str(exc))
            quality.quarantined_records.append(exc.to_dict())
            continue
        for target, source in aliases.items():
            alias_usage[(target, source)] += 1
        kind = record_schema(canonical)
        schema_counts[kind] += 1

        record_timestamps: list[float] = []
        record_events = []
        record_dns_events = []
        record_encrypted_events = []
        record_error: ZeekRecordError | None = None
        try:
            if kind != "dns":
                event = normalize_conn_record(canonical, line_number)
                record_events.append(event)
                record_timestamps.append(event.timestamp)

            dns_source = _dns_record(canonical)
            if kind == "dns" and dns_source is not None:
                dns_event = normalize_dns_record(dns_source, line_number)
                record_dns_events.append(dns_event)
                record_timestamps.append(dns_event.timestamp)

            if kind in {"tls", "quic"}:
                encrypted_event = normalize_encrypted_record(canonical, line_number, kind)
                record_encrypted_events.append(encrypted_event)
                record_timestamps.append(encrypted_event.timestamp)
        except ZeekRecordError as exc:
            record_error = exc

        if not record_timestamps:
            error = record_error or ZeekRecordError(
                f"Line {line_number}: unsupported passive telemetry record. Expected connection, DNS, or TLS/QUIC metadata.",
                line_number=line_number,
                category="unsupported_record",
            )
            quality.records_rejected += 1
            quality.records_quarantined += 1
            if error.category == "invalid_timestamp":
                quality.invalid_timestamp_count += 1
            if error.category == "unsupported_record":
                quality.unsupported_record_count += 1
            if len(quality.errors) < 5:
                quality.errors.append(str(error))
            quality.quarantined_records.append(error.to_dict())
            continue

        events.extend(record_events)
        dns_events.extend(record_dns_events)
        encrypted_events.extend(record_encrypted_events)
        accepted_records.append(canonical)

        uid = str(canonical.get("uid", ""))
        signature = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
        if uid in seen_uids:
            quality.duplicate_uid_count += 1
            if seen_uids[uid] == signature:
                quality.exact_duplicate_count += 1
            else:
                quality.conflicting_duplicate_uid_count += 1
        else:
            seen_uids[uid] = signature

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
    elif quality.records_rejected or quality.out_of_order_records or quality.duplicate_uid_count:
        quality.status = "degraded"
    if quality.records_rejected:
        quality.degraded_reasons.append(f"{quality.records_rejected} rejected record(s)")
    if quality.out_of_order_records:
        quality.degraded_reasons.append(
            f"{quality.out_of_order_records} out-of-order timestamp record(s)"
        )
    if quality.duplicate_uid_count:
        quality.degraded_reasons.append(
            f"{quality.duplicate_uid_count} duplicate flow ID occurrence(s)"
        )
    quality.maximum_backward_skew_seconds = round(quality.maximum_backward_skew_seconds, 6)
    if quality.status == "unusable":
        reason = quality.errors[0] if quality.errors else "No supported passive telemetry records were found."
        raise ValueError(f"Replay could not be analysed (data quality: unusable): {reason}")

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
    # Preserve threshold-crossing reconnaissance findings from the whole replay.
    # A final snapshot can enrich a still-active scan, but must never replace an
    # earlier scan that has expired from the detector's active window.
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
    evaluation = score_ground_truth(
        accepted_records, alerts
    )
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
        "input_schema": schema_summary(
            parsed_replay.input_format, raw_records, alias_usage, schema_counts
        ),
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
        "scope_note": "Demonstration thresholds are used. Production deployment requires environment-specific calibration.",
    }
