"""Versioned, bounded monitoring-side exports of completed replay evidence.

This is a Drastha JSON contract for SIEM importers, not an ECS, CEF, or STIX
implementation. It reads one saved run; it never contacts observed endpoints.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import math


FORMAT = "drastha-siem-export-v1"
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_EVENTS = 5000
MAX_ALERTS = 20000


class ExportValidationError(ValueError):
    """A stored snapshot cannot be exported without losing evidence fidelity."""


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _identity(value, name):
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ExportValidationError(f"Missing or invalid {name}")
    return value


def _number(value, name, minimum=None, maximum=None):
    if (type(value) not in (int, float) or not math.isfinite(value)
            or minimum is not None and value < minimum
            or maximum is not None and value > maximum):
        raise ExportValidationError(f"Missing or invalid {name}")
    return value


def build_siem_export(report):
    """Return a deterministic export payload without mutating the snapshot.

    Event IDs are stable for repeated exports of the exact run snapshot. They
    change for a different run or changed evidence, even when incident IDs recur.
    Consumers may upsert by event_id; this does not guarantee transport delivery.
    """
    if not isinstance(report, dict) or report.get("status") != "completed":
        raise ExportValidationError("Only completed analysis runs can be exported")
    run_id = _identity(report.get("run_id"), "run_id")
    incidents, alerts = report.get("incidents"), report.get("alerts")
    if not isinstance(incidents, list) or not isinstance(alerts, list):
        raise ExportValidationError("Snapshot must contain incident and alert arrays")
    if len(incidents) > MAX_EVENTS or len(alerts) > MAX_ALERTS:
        raise ExportValidationError("Snapshot exceeds the bounded SIEM export record limit")
    try:
        raw = canonical(report).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ExportValidationError("Snapshot must contain finite JSON values") from exc
    if len(raw) > MAX_REPORT_BYTES:
        raise ExportValidationError("Snapshot exceeds the 16 MiB SIEM export limit")
    quality = report.get("quality")
    if not isinstance(quality, dict) or quality.get("status") not in {"healthy", "degraded", "unusable"}:
        raise ExportValidationError("Snapshot is missing a recognized data-quality status")
    snapshot_digest = sha256(raw).hexdigest()
    by_alert = {}
    for item in alerts:
        if not isinstance(item, dict):
            raise ExportValidationError("Alert must be an object")
        identity = _identity(item.get("alert_id"), "alert_id")
        if identity in by_alert:
            raise ExportValidationError("Duplicate alert_id in snapshot")
        by_alert[identity] = item

    events, incident_ids, linked_alerts = [], set(), set()
    for incident in incidents:
        if not isinstance(incident, dict):
            raise ExportValidationError("Incident must be an object")
        identity = _identity(incident.get("incident_id"), "incident_id")
        if identity in incident_ids:
            raise ExportValidationError("Duplicate incident_id in snapshot")
        incident_ids.add(identity)
        source = _identity(incident.get("src_ip"), "incident source")
        first = _number(incident.get("first_seen"), "first_seen")
        last = _number(incident.get("last_seen"), "last_seen")
        if first > last:
            raise ExportValidationError("Incident time window is reversed")
        score = _number(incident.get("risk_score"), "incident risk", 0, 100)
        confidence = _number(incident.get("confidence"), "incident confidence", 0, 1)
        if incident.get("severity") not in {"low", "medium", "high", "critical"}:
            raise ExportValidationError("Unknown incident severity")
        references = incident.get("alert_ids")
        if not isinstance(references, (list, tuple)) or not references:
            raise ExportValidationError("Incident has no alert references")
        evidence = []
        for reference in references:
            reference = _identity(reference, "alert reference")
            if reference not in by_alert or reference in linked_alerts:
                raise ExportValidationError("Missing or multiply linked alert reference")
            item = by_alert[reference]
            if item.get("src_ip") != source:
                raise ExportValidationError("Alert source differs from its incident")
            linked_alerts.add(reference)
            evidence.append(deepcopy(item))
        event_id = sha256(canonical([FORMAT, run_id, snapshot_digest, identity]).encode()).hexdigest()
        events.append({
            "schema_version": "drastha-siem-incident-v1",
            "event_id": event_id,
            "event_kind": "incident",
            "run_id": run_id,
            "snapshot_sha256": snapshot_digest,
            "incident_id": identity,
            "observed_start": first,
            "observed_end": last,
            "timestamp_basis": "source_seconds_preserved",
            "source_ip": source,
            "destination_ips": sorted({item["dst_ip"] for item in evidence if item.get("dst_ip")}),
            "severity": incident["severity"],
            "risk_score": score,
            "confidence": confidence,
            "incident": deepcopy(incident),
            "alerts": sorted(evidence, key=lambda item: item["alert_id"]),
        })
    if linked_alerts != by_alert.keys():
        raise ExportValidationError("Snapshot contains alerts without an incident")
    events.sort(key=lambda item: item["incident_id"])
    manifest = {
        "format": FORMAT,
        "run_id": run_id,
        "snapshot_sha256": snapshot_digest,
        "event_count": len(events),
        "alert_count": len(alerts),
        "scope": "completed_run_snapshot",
        "quality": deepcopy(quality),
        "overall_risk": deepcopy(report.get("overall_risk")),
        "feature_coverage": deepcopy(report.get("feature_coverage")),
        "context_policy": deepcopy(report.get("context_policy")),
        "analysis_provenance": deepcopy(report.get("analysis_provenance")),
        "limitations": [
            "Investigation priority and detector confidence are not calibrated attack probabilities.",
            "No findings or insufficient evidence do not establish that traffic is safe.",
            "Incident reviews reflect the saved run, not later global-queue analyst decisions.",
            "Source timestamps are preserved; relative capture times are not converted to wall-clock dates.",
            "Evidence is exported for monitoring-side import; no delivery or acknowledgement is attempted.",
        ],
    }
    return {"manifest": manifest, "events": events}


def render_siem_export(payload, integrity, format="json"):
    """NDJSON contains one manifest/receipt line followed by one line per incident.

    Reassemble {manifest, events} to verify the same HMAC receipt as JSON. Receipt
    freshness/audit heads may change between exports; event IDs do not.
    """
    if format == "json":
        return canonical({**payload, "integrity": integrity}) + "\n"
    if format != "ndjson":
        raise ExportValidationError("Unsupported SIEM serialization")
    lines = [canonical({"record_type": "manifest", "manifest": payload["manifest"],
                        "integrity": integrity})]
    lines.extend(canonical({"record_type": "incident", "event": event}) for event in payload["events"])
    return "\n".join(lines) + "\n"
