"""Shared, request-local detector execution for passive telemetry adapters.

Adapters own input validation, ordering, persistence and delivery. This module
owns detector construction and typed event dispatch; it never opens a network
connection or reads evaluation labels.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Iterable

from aegisflow.context_policy import ContextPolicy, load_context_policy
from aegisflow.detectors import (
    C2BeaconDetector, C2Config, DDoSConfig, DDoSDetector, DNSConfig, DNSDetector,
    EncryptedAnomalyConfig, EncryptedSessionAnomalyDetector,
    ExfiltrationConfig, ExfiltrationDetector, ReconConfig, ReconDetector,
)
from aegisflow.dns_model import DNSNgramModel
from aegisflow.ingestion.zeek_dns import DNS_NORMALIZER_VERSION
from aegisflow.ingestion.passive_replay import PARSER_VERSION
from aegisflow.ingestion.zeek_encrypted import build_encrypted_metadata_index
from aegisflow.findings import resolve_findings
from aegisflow.incidents import IncidentStore
from aegisflow.models import Alert, DNSEvent, EncryptedSessionMetadata, NetworkEvent
from aegisflow.passive_features import PassiveFeatureConfig, PassiveFeatureExtractor
from aegisflow.network_context import NetworkScope
from aegisflow.passive_context import PassiveDNSContext


PassiveEvent = NetworkEvent | DNSEvent | EncryptedSessionMetadata


@dataclass(frozen=True)
class AnalysisProfile:
    name: str
    recon: ReconConfig = field(default_factory=ReconConfig)
    ddos: DDoSConfig = field(default_factory=DDoSConfig)
    c2: C2Config = field(default_factory=C2Config)
    dns: DNSConfig = field(default_factory=DNSConfig)
    encrypted: EncryptedAnomalyConfig = field(default_factory=EncryptedAnomalyConfig)
    exfiltration: ExfiltrationConfig = field(default_factory=ExfiltrationConfig)
    enabled: tuple[str, ...] = ("recon", "ddos", "c2", "dns", "encrypted", "exfiltration")
    allow_domains: tuple[str, ...] = ()
    allow_destinations: tuple[str, ...] = ()
    approved_backup_destinations: tuple[str, ...] = ()
    feature_mode: str = "compatibility"
    passive_features: PassiveFeatureConfig = field(default_factory=PassiveFeatureConfig)
    internal_cidrs: tuple[str, ...] = ()

    def __post_init__(self):
        if self.feature_mode not in {"compatibility", "derived"}:
            raise ValueError("Unknown passive feature mode")
        NetworkScope(self.internal_cidrs)
        if not self.enabled or set(self.enabled) - {"recon", "ddos", "c2", "dns", "encrypted", "exfiltration"}:
            raise ValueError("Profile must select known detectors")


# Preserve existing public paths while making their differences inspectable.
UPLOAD_DEMO = AnalysisProfile(
    "upload-demo-v1", recon=ReconConfig(unique_port_threshold=5, unique_host_threshold=5),
    ddos=DDoSConfig(syn_attempt_threshold=5, udp_packet_threshold=500),
)
STREAM_DEMO = AnalysisProfile(
    "stream-demo-v1", recon=ReconConfig(unique_port_threshold=6, unique_host_threshold=6),
    ddos=DDoSConfig(syn_attempt_threshold=5, udp_packet_threshold=500),
)
# These are existing detector defaults, NOT production-calibrated thresholds.
DEPLOYMENT_BASELINE = AnalysisProfile("deployment-baseline-uncalibrated-v1", feature_mode="derived",
                                    ddos=DDoSConfig(require_reflection_service_context=True))


def configured_profile(default: AnalysisProfile) -> AnalysisProfile:
    """Trusted operator selection, never read from an uploaded traffic record."""
    name = os.getenv("DRASTHA_ANALYSIS_PROFILE")
    profiles = {"upload-demo": UPLOAD_DEMO, "stream-demo": STREAM_DEMO,
                "deployment-baseline": DEPLOYMENT_BASELINE}
    if name and name not in profiles:
        raise ValueError(f"Unknown DRASTHA_ANALYSIS_PROFILE: {name}")
    return profiles[name] if name else default


class AnalysisSession:
    """One independent detector state per replay/stream, never module-global."""

    version = "3.0"

    def __init__(
        self, profile: AnalysisProfile, *, context_policy: ContextPolicy | None = None,
        dns_model: DNSNgramModel | None = None,
    ) -> None:
        self.profile = profile
        self.context_policy = context_policy or ContextPolicy()
        self.dns_model = dns_model
        self.feature_extractor = PassiveFeatureExtractor(profile.passive_features)
        self.network_scope = NetworkScope(profile.internal_cidrs)
        self.direction_counts = {}
        self.dns_context = PassiveDNSContext()
        self._latest_timestamp: float | None = None
        self._metadata: dict[tuple[str, str, str], EncryptedSessionMetadata] = {}
        self._alerts: list[Alert] = []
        self._finished = False
        self._final_alerts: list[Alert] = []
        self.recon = ReconDetector(profile.recon)
        self.ddos = DDoSDetector(profile.ddos)
        self.c2 = C2BeaconDetector(
            profile.c2, allowlisted_destinations=set(profile.allow_destinations),
            trusted_periodic_endpoints=self.context_policy.trusted_periodic_endpoints,
        )
        self.exfiltration = ExfiltrationDetector(
            profile.exfiltration,
            approved_backup_destinations=set(profile.approved_backup_destinations),
            approved_bulk_transfer_endpoints=self.context_policy.approved_bulk_transfer_endpoints,
        )
        self.dns = DNSDetector(profile.dns, model=dns_model, allowlisted_base_domains=set(profile.allow_domains))
        self.encrypted = EncryptedSessionAnomalyDetector(profile.encrypted)
        self.connection_detectors = tuple(detector for name, detector in
            (("recon", self.recon), ("ddos", self.ddos), ("c2", self.c2), ("exfiltration", self.exfiltration))
            if name in profile.enabled)
        self._provenance = self.provenance()

    @classmethod
    def from_root(
        cls, root: str | Path, profile: AnalysisProfile, *, require_model: bool = False,
        model_path: str | Path | None = None,
    ) -> AnalysisSession:
        root = Path(root)
        configured_cidrs = os.getenv("DRASTHA_INTERNAL_NETWORKS")
        if configured_cidrs is not None:
            profile = replace(profile, internal_cidrs=tuple(x.strip() for x in configured_cidrs.split(",") if x.strip()))
        configured = model_path or os.getenv("DRASTHA_DNS_MODEL")
        path = Path(configured) if configured else root / "output" / "models" / "dns_dga_demo.json"
        if configured and not path.is_absolute():
            path = root / path
        model = DNSNgramModel.load(path) if configured or require_model or path.is_file() else None
        return cls(profile, context_policy=load_context_policy(root), dns_model=model)

    def process(self, event: PassiveEvent) -> list[Alert]:
        if self._finished:
            raise RuntimeError("Analysis session is complete; create a new session")
        if not isinstance(event, (DNSEvent, EncryptedSessionMetadata, NetworkEvent)):
            raise TypeError(f"Unsupported normalized event: {type(event).__name__}")
        if self._latest_timestamp is not None and event.timestamp < self._latest_timestamp:
            raise ValueError("Session requires ordered events; late observations must be buffered or quarantined by the adapter")
        self._latest_timestamp = event.timestamp
        self._metadata = {key: value for key, value in self._metadata.items()
                          if value.timestamp >= event.timestamp - self.profile.c2.window_seconds}
        if isinstance(event, DNSEvent):
            self.dns_context.observe(event)
            alerts = self.dns.process(event) if "dns" in self.profile.enabled else []
        elif isinstance(event, EncryptedSessionMetadata):
            event = self.feature_extractor.enrich(event, allow_supplied=self.profile.feature_mode == "compatibility")
            self._metadata[(event.flow_id, event.src_ip, event.dst_ip)] = event
            alerts = self.encrypted.process(event) if "encrypted" in self.profile.enabled else []
        else:
            self.c2.encrypted_metadata = build_encrypted_metadata_index([
                value for value in self._metadata.values()
                if value.src_ip == event.src_ip and value.dst_ip == event.dst_ip
            ])
            direction = self.network_scope.direction(event.src_ip, event.dst_ip)
            self.direction_counts[direction] = self.direction_counts.get(direction, 0) + 1
            alerts = []
            for detector in self.connection_detectors:
                view = event
                if detector is self.exfiltration and (self.profile.internal_cidrs or self.profile.feature_mode == "derived"):
                    view = self.network_scope.exfiltration_view(event)
                if view is not None:
                    alerts.extend(detector.process(view))
        dns_evidence = self.dns_context.evidence_for(event) if alerts and not isinstance(event, DNSEvent) else ()
        alerts = [replace(alert, analysis_provenance=self._provenance, evidence=alert.evidence + dns_evidence) for alert in alerts]
        self._alerts.extend(alerts)
        return alerts

    def process_many(self, events: Iterable[PassiveEvent]) -> list[Alert]:
        # Do not sort here: live callers must retain control of event-time policy.
        return [alert for event in events for alert in self.process(event)]

    def final_recon_snapshot(self) -> list[Alert]:
        """Enrichment only: callers must retain prior threshold-crossing alerts."""
        return [replace(alert, analysis_provenance=self._provenance) for alert in self.recon.final_alerts()]

    def findings(self, *, complete: bool = False) -> list[Alert]:
        if complete and not self._finished:
            snapshots = self.final_recon_snapshot() if "recon" in self.profile.enabled else []
            self._final_alerts = resolve_findings([*self._alerts, *snapshots])
            self._finished = True
        return list(self._final_alerts) if self._finished else resolve_findings(self._alerts)

    def incidents(self, *, complete: bool = False):
        store = IncidentStore()
        for alert in self.findings(complete=complete):
            store.process(alert)
        return list(store.all())

    def provenance(self) -> dict:
        def digest(value: dict) -> str:
            return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

        configuration = asdict(self.profile)
        policy = asdict(self.context_policy)
        policy.pop("source")  # Same rules have the same digest on different hosts.
        return {
            "engine_version": self.version,
            "parser_version": PARSER_VERSION,
            "dns_normalizer_version": DNS_NORMALIZER_VERSION,
            "profile": self.profile.name,
            "configuration": configuration,
            "configuration_sha256": digest(configuration),
            "context_policy_sha256": digest(policy),
            "detector_versions": {d.detector_id: d.detector_version for d in
                                  (*self.connection_detectors, self.dns, self.encrypted)},
            "dns_model_version": self.dns_model.payload.get("version") if self.dns_model else None,
            "dns_model_sha256": digest(self.dns_model.payload) if self.dns_model else None,
            "c2_metadata_mode": "observed-event-time-v1",
            "passive_feature_extractor": PassiveFeatureExtractor.version,
            "feature_mode": self.profile.feature_mode,
            "dns_context_mode": "causal-60s-max10000-v1",
        }

    def feature_summary(self):
        return {**self.feature_extractor.summary(), "mode": self.profile.feature_mode,
                "network_direction_counts": dict(self.direction_counts),
                "network_direction_status": "configured" if self.profile.internal_cidrs else "unconfigured",
                "exfiltration_direction": "legacy-originator-view" if not self.profile.internal_cidrs and
                    self.profile.feature_mode == "compatibility" else "configured-boundary-required"}
