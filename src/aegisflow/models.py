from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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
    status: str = "open"

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
