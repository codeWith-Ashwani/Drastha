from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterator

from aegisflow.detectors import (
    C2BeaconDetector,
    DDoSConfig,
    DDoSDetector,
    DNSDetector,
    EncryptedSessionAnomalyDetector,
    ExfiltrationDetector,
    ReconConfig,
    ReconDetector,
)
from aegisflow.dns_model import DNSNgramModel
from aegisflow.context_policy import load_context_policy
from aegisflow.incidents import IncidentStore
from aegisflow.ingestion.zeek_jsonl import read_conn_jsonl
from aegisflow.ingestion.zeek_dns import read_dns_jsonl
from aegisflow.ingestion.zeek_encrypted import (
    build_encrypted_metadata_index,
    read_encrypted_jsonl,
)
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
) -> Iterator[str]:
    """Process an accelerated, one-way flow stream and emit dashboard intelligence.

    The source only yields passive observations into the detector pipeline. The
    generator emits a separate monitoring-side SSE feed and never contacts any
    endpoint represented by the input records.
    """
    project_root = Path(root).resolve()
    context_policy = load_context_policy(project_root)
    connection_paths = (
        "zeek_conn_scan.jsonl",
        "zeek_conn_ddos.jsonl",
        "zeek_conn_beacon.jsonl",
        "zeek_conn_exfil.jsonl",
    )
    connection_events = [
        event
        for name in connection_paths
        for event in read_conn_jsonl(project_root / "examples" / name)
    ]
    dns_events = list(read_dns_jsonl(project_root / "examples" / "zeek_dns_threats.jsonl"))
    encrypted_events = list(read_encrypted_jsonl(
        project_root / "examples" / "zeek_ssl_beacon.jsonl", "tls"
    ))
    events = sorted(
        [*dns_events, *encrypted_events, *connection_events],
        key=lambda item: item.timestamp,
    )
    connection_detectors = [
        ReconDetector(ReconConfig(unique_port_threshold=6, unique_host_threshold=6)),
        DDoSDetector(DDoSConfig(syn_attempt_threshold=5, udp_packet_threshold=500)),
        C2BeaconDetector(
            encrypted_metadata=build_encrypted_metadata_index(encrypted_events),
            trusted_periodic_endpoints=context_policy.trusted_periodic_endpoints,
        ),
        ExfiltrationDetector(
            approved_bulk_transfer_endpoints=context_policy.approved_bulk_transfer_endpoints
        ),
    ]
    dns_detector = DNSDetector(
        model=DNSNgramModel.load(project_root / "output" / "models" / "dns_dga_demo.json")
    )
    encrypted_detector = EncryptedSessionAnomalyDetector()
    correlator = IncidentStore()
    alerts = []
    started = time.perf_counter()

    yield _sse({
        "type": "started",
        "total_records": len(events),
        "source": "simulated one-way IP stream",
        "passive": True,
        "return_path_required": False,
        "telemetry": {
            "connection_records": len(connection_events),
            "dns_records": len(dns_events),
            "encrypted_session_records": len(encrypted_events),
        },
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
        elif isinstance(event, EncryptedSessionMetadata):
            new_alerts.extend(encrypted_detector.process(event))
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
        "return_path_required": False,
        "bounded_latency": True,
        "telemetry": {
            "connection_records": len(connection_events),
            "dns_records": len(dns_events),
            "encrypted_session_records": len(encrypted_events),
        },
    })
