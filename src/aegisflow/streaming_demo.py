from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterator

from aegisflow.detectors import C2BeaconDetector, DNSDetector, ExfiltrationDetector
from aegisflow.dns_model import DNSNgramModel
from aegisflow.incidents import IncidentStore
from aegisflow.ingestion.zeek_jsonl import read_conn_jsonl
from aegisflow.ingestion.zeek_dns import read_dns_jsonl
from aegisflow.models import DNSEvent


DETECTION_METHODS = {
    "c2.beacon": "Statistical timing analysis",
    "exfiltration.outbound": "Adaptive baseline analysis",
    "recon.fanout": "Behavioural fan-out analysis",
    "ddos.behavioural": "Traffic-rate analysis",
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
) -> Iterator[str]:
    """Process an accelerated, one-way flow stream and emit dashboard intelligence.

    The source only yields passive observations into the detector pipeline. The
    generator emits a separate monitoring-side SSE feed and never contacts any
    endpoint represented by the input records.
    """
    project_root = Path(root).resolve()
    replay_path = project_root / "examples" / "judge_attack_replay.jsonl"
    connection_events = list(read_conn_jsonl(replay_path))
    dns_events = list(read_dns_jsonl(project_root / "examples" / "zeek_dns_threats.jsonl"))
    events = [*dns_events, *connection_events]
    connection_detectors = [C2BeaconDetector(), ExfiltrationDetector()]
    dns_detector = DNSDetector(
        model=DNSNgramModel.load(project_root / "output" / "models" / "dns_dga_demo.json")
    )
    correlator = IncidentStore()
    alerts = []
    started = time.perf_counter()

    yield _sse({
        "type": "started",
        "total_records": len(events),
        "source": "simulated one-way IP stream",
        "passive": True,
        "return_path_required": False,
    })

    for index, event in enumerate(events, start=1):
        record_started = time.perf_counter()
        new_alerts = []
        if isinstance(event, DNSEvent):
            new_alerts.extend(dns_detector.process(event))
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
        else:
            for detector in connection_detectors:
                new_alerts.extend(detector.process(event))
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
            incident = correlator.process(alert)
            repository.import_records([incident.to_dict()], [alert.to_dict()])
            yield _sse({
                "type": "alert",
                "processed": index,
                "alert": alert.to_dict(),
                "detection_method": _detection_method(alert),
                "incident": incident.to_dict(),
            })

        if interval_seconds:
            time.sleep(interval_seconds)

    incidents = [item.to_dict() for item in correlator.all()]
    top_incident = max(incidents, key=lambda item: item["risk_score"], default=None)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    yield _sse({
        "type": "complete",
        "processed": len(events),
        "total_records": len(events),
        "alerts": len(alerts),
        "incidents": len(incidents),
        "top_incident_id": top_incident["incident_id"] if top_incident else None,
        "risk_score": top_incident["risk_score"] if top_incident else 0,
        "elapsed_ms": elapsed_ms,
        "near_real_time": True,
        "passive": True,
    })
