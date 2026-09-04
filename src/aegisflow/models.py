from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


THREAT_CLASS_BY_SUBTYPE = {
    "syn_flood": "Volumetric DDoS - SYN Flood",
    "udp_flood": "Volumetric DDoS - UDP Flood",
    "udp_reflection_amplification": "Volumetric DDoS - UDP Reflection/Amplification",
    "distributed_source_syn_flood": "Volumetric DDoS - Distributed-Source SYN Flood",
    "encrypted_session_metadata_anomaly": "Encrypted-session metadata anomaly",
}


@dataclass(frozen=True, slots=True)
class NetworkEvent:
    timestamp: float
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration_seconds: float = 0.0
    outbound_bytes: int = 0
    inbound_bytes: int = 0
    outbound_packets: int = 0
    inbound_packets: int = 0
    connection_state: str = ""
    source: str = "unknown"
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class DNSEvent:
    timestamp: float
    flow_id: str
    src_ip: str
    dst_ip: str
    query: str
    query_type: str
    response_code: str
    answers: tuple[str, ...] = ()
    rejected: bool = False
    source: str = "unknown"
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class EncryptedSessionMetadata:
    timestamp: float
    flow_id: str
    src_ip: str
    dst_ip: str
    transport: str
    server_name: str = ""
    version: str = ""
    cipher: str = ""
    application_protocol: str = ""
    client_fingerprint: str = ""
    server_fingerprint: str = ""
    established: bool = False
    resumed: bool = False
    source: str = "unknown"
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class Evidence:
    name: str
    observed: int | float | str
    comparison: str
    explanation: str


@dataclass(frozen=True, slots=True)
class IncidentConclusion:
    """Evidence-backed analyst narrative inferred from passive telemetry."""

    assessment: str
    likely_objective: str
    attack_stage: str
    potential_impact: str
    confidence_basis: tuple[str, ...]
    uncertainty: str
    inference_basis: str = "passive_metadata_only"


@dataclass(frozen=True, slots=True)
class Alert:
    alert_id: str
    detector_id: str
    detector_version: str
    threat_type: str
    subtype: str
    confidence: float
    severity: str
    window_start: float
    window_end: float
    src_ip: str
    dst_ip: str | None
    flow_ids: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    limitations: tuple[str, ...] = ()
    analysis_provenance: dict[str, Any] = field(default_factory=dict, compare=False)

    def to_dict(self) -> dict[str, Any]:
        record = asdict(self)
        # Stable interoperability aliases required by the public alert schema.
        # Existing fields remain unchanged for backward compatibility.
        record.update({
            "schema_version": "drastha-alert-v1",
            "timestamp": self.window_end,
            "flow_identifier": self.flow_ids[0] if self.flow_ids else None,
            "threat_class": THREAT_CLASS_BY_SUBTYPE.get(self.subtype, self.threat_type),
            "supporting_evidence": record["evidence"],
        })
        return record


@dataclass(frozen=True, slots=True)
class Incident:
    incident_id: str
    src_ip: str
    first_seen: float
    last_seen: float
    alert_ids: tuple[str, ...]
    detector_ids: tuple[str, ...]
    threat_types: tuple[str, ...]
    confidence: float
    risk_score: int
    severity: str
    scoring_factors: tuple[Evidence, ...]
    conclusion: IncidentConclusion | None = None
    status: str = "open"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AggregateRisk:
    """Replay-wide investigation priority derived from correlated incidents."""

    score: int
    severity: str
    incident_count: int
    distinct_threat_types: int
    affected_sources: int
    dominant_incident_id: str | None
    dominant_threat_types: tuple[str, ...]
    scoring_factors: tuple[Evidence, ...]
    assessment: str
    uncertainty: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AnalystFeedback:
    feedback_id: str
    incident_id: str
    disposition: str
    analyst: str
    timestamp: float
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
