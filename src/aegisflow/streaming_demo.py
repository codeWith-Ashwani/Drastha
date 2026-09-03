from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterator

from aegisflow.analysis_session import AnalysisProfile, AnalysisSession, STREAM_DEMO
from aegisflow.ingestion.passive_replay import prepare_replay, event_order
from aegisflow.evaluation_scoring import score_ground_truth
from uuid import uuid4
from aegisflow.models import DNSEvent, EncryptedSessionMetadata


DETECTION_METHODS = {
    "c2.beacon": "Statistical timing analysis",
    "exfiltration.outbound": "Adaptive baseline analysis",
    "recon.fanout": "Behavioural fan-out analysis",
    "ddos.behavioural": "Traffic-rate analysis",
    "dns.analytics": "DNS n-gram, entropy and query-shape analysis",
    "encrypted.metadata_anomaly": "TLS/QUIC fingerprint, timing and size metadata analysis",
}


def _sse(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"


def _detection_method(alert: Any) -> str:
    if alert.subtype == "dga_like_domain":
        return "Character n-gram ML model"
    if alert.subtype == "dns_tunnelling":
        return "DNS volume and entropy analysis"
    return DETECTION_METHODS.get(alert.detector_id, "Explainable passive analysis")


def stream_simulated_ip_traffic(
    root: str | Path,
    repository: Any,
    *,
    interval_seconds: float = 0.10,
    profile: AnalysisProfile = STREAM_DEMO,
) -> Iterator[str]:
    """Process an accelerated, one-way flow stream and emit dashboard intelligence.

    The source only yields passive observations into the detector pipeline. The
    generator emits a separate monitoring-side SSE feed and never contacts any
    endpoint represented by the input records.
    """
    project_root = Path(root).resolve()
    connection_paths = (
        "zeek_conn_scan.jsonl",
        "zeek_conn_ddos.jsonl",
        "zeek_conn_beacon.jsonl",
        "zeek_conn_exfil.jsonl",
    )
    paths = [*(project_root / "examples" / name for name in connection_paths),
             project_root / "examples/zeek_dns_threats.jsonl",
             project_root / "examples/zeek_ssl_beacon.jsonl"]
    prepared = [prepare_replay(path.read_text(encoding="utf-8"), path.name) for path in paths]
    events = sorted([event for source in prepared for event in source.ordered_events()], key=event_order)
    telemetry = {key: sum(source.telemetry()[key] for source in prepared) for key in
                 ("connection_records", "dns_records", "encrypted_session_records")}
    quality = {"status": "degraded" if any(source.quality.status != "healthy" for source in prepared) else "healthy",
               "sources": [source.quality.to_dict() for source in prepared]}
    yield from stream_events(project_root, repository, events, telemetry, quality,
                             profile=profile, interval_seconds=interval_seconds)


def stream_replay(root, repository, filename, content, *, profile=STREAM_DEMO, interval_seconds=0):
    """Upload-compatible replay delivered incrementally over monitoring-side SSE."""
    prepared = prepare_replay(content, filename)
    yield from stream_events(root, repository, prepared.ordered_events(), prepared.telemetry(),
                             prepared.quality.to_dict(), profile=profile, interval_seconds=interval_seconds,
                             accepted_records=prepared.accepted_records)


def stream_events(root, repository, events, telemetry, quality, *, profile=STREAM_DEMO,
                  interval_seconds=0, accepted_records=()):
    session = AnalysisSession.from_root(root, profile)
    run_id = uuid4().hex
    alerts = []
    started = time.perf_counter()

    yield _sse({
        "type": "started",
        "total_records": len(events),
        "source": "passive replay stream",
        "run_id": run_id,
        "quality": quality,
        "analysis_provenance": session.provenance(),
        "passive": True,
        "return_path_required": False,
        "telemetry": telemetry,
    })

    for index, event in enumerate(events, start=1):
        record_started = time.perf_counter()
        new_alerts = session.process(event)
        if isinstance(event, DNSEvent):
            record = {
                "record_kind": "dns",
                "timestamp": event.timestamp,
                "flow_id": event.flow_id,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "protocol": "dns",
                "dst_port": 53,
                "outbound_bytes": 0,
                "inbound_bytes": 0,
                "query": event.query,
            }
        elif isinstance(event, EncryptedSessionMetadata):
            record = {
                "record_kind": "encrypted_session",
                "timestamp": event.timestamp,
                "flow_id": event.flow_id,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "protocol": event.transport,
                "dst_port": 443,
                "outbound_bytes": 0,
                "inbound_bytes": 0,
                "fingerprint": event.client_fingerprint,
            }
        else:
            record = {
                "record_kind": "connection",
                "timestamp": event.timestamp,
                "flow_id": event.flow_id,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "protocol": event.protocol,
                "dst_port": event.dst_port,
                "outbound_bytes": event.outbound_bytes,
                "inbound_bytes": event.inbound_bytes,
            }
        record_ms = round((time.perf_counter() - record_started) * 1000, 3)
        yield _sse({
            "type": "traffic",
            "processed": index,
            "total_records": len(events),
            "record": record,
            "record_analysis_ms": record_ms,
        })

        for alert in new_alerts:
            alerts.append(alert)
            # Provisional notifications are not inserted into the final incident
            # tables: later evidence can merge or retract them.
            current = session.incidents()
            incident = next((item for item in current if alert.alert_id in item.alert_ids), None)
            if incident is None:
                continue
            if hasattr(repository, "save_analysis_run"):
                repository.save_analysis_run(run_id, {"status": "running", "quality": quality,
                    "analysis_provenance": session.provenance(),
                    "alerts": [item.to_dict() for item in session.findings()],
                    "incidents": [item.to_dict() for item in current]})
            yield _sse({
                "type": "alert",
                "provisional": True,
                "run_id": run_id,
                "processed": index,
                "alert": alert.to_dict(),
                "detection_method": _detection_method(alert),
                "incident": incident.to_dict(),
            })

        if interval_seconds:
            time.sleep(interval_seconds)

    final_alerts = session.findings(complete=True)
    incidents = [item.to_dict() for item in session.incidents()]
    final_records = [item.to_dict() for item in final_alerts]
    repository.import_records(incidents, final_records)
    evaluation = score_ground_truth(list(accepted_records), final_alerts)
    if hasattr(repository, "save_analysis_run"):
        repository.save_analysis_run(run_id, {"status": "completed", "quality": quality,
            "analysis_provenance": session.provenance(), "alerts": final_records,
            "incidents": incidents, "evaluation": evaluation})
    top_incident = max(incidents, key=lambda item: item["risk_score"], default=None)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    yield _sse({
        "type": "complete",
        "processed": len(events),
        "total_records": len(events),
        "alerts": len(final_alerts),
        "emitted_alerts": len(alerts),
        "findings": [{"alert": item, "detection_method": _detection_method(alert),
                      "incident": next(incident for incident in incidents if item["alert_id"] in incident["alert_ids"])}
                     for item, alert in zip(final_records, final_alerts)],
        "incident_records": incidents,
        "evaluation": evaluation,
        "quality": quality,
        "run_id": run_id,
        "incidents": len(incidents),
        "top_incident_id": top_incident["incident_id"] if top_incident else None,
        "risk_score": top_incident["risk_score"] if top_incident else 0,
        "elapsed_ms": elapsed_ms,
        "analysis_provenance": session.provenance(),
        "near_real_time": True,
        "passive": True,
        "return_path_required": False,
        "bounded_latency": True,
        "telemetry": telemetry,
    })
