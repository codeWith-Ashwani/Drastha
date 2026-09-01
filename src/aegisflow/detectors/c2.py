from __future__ import annotations

import math
from dataclasses import dataclass
from hashlib import sha256

from aegisflow.context_policy import EndpointRule
from aegisflow.models import Alert, EncryptedSessionMetadata, Evidence, NetworkEvent
from aegisflow.windowing import KeyedSlidingWindow


def _coefficient_of_variation(values: list[float]) -> float:
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(variance) / mean


@dataclass(frozen=True, slots=True)
class C2Config:
    window_seconds: float = 300.0
    minimum_connections: int = 6
    minimum_mean_interval_seconds: float = 2.0
    maximum_mean_interval_seconds: float = 120.0
    maximum_interval_cv: float = 0.15
    maximum_size_cv: float = 0.20
    minimum_observation_span_seconds: float = 30.0
    maximum_mean_transfer_bytes: float = 2048.0
    minimum_completed_ratio: float = 0.80
    cooldown_seconds: float = 300.0

    def __post_init__(self) -> None:
        if self.window_seconds <= 0 or self.minimum_connections < 3:
            raise ValueError("C2 window must be positive and minimum_connections at least 3")
        if self.minimum_mean_interval_seconds <= 0:
            raise ValueError("minimum mean interval must be positive")
        if self.maximum_mean_interval_seconds <= self.minimum_mean_interval_seconds:
            raise ValueError("maximum mean interval must exceed minimum mean interval")
        if self.maximum_interval_cv < 0 or self.maximum_size_cv < 0:
            raise ValueError("variation thresholds cannot be negative")
        if self.minimum_observation_span_seconds <= 0 or self.maximum_mean_transfer_bytes <= 0:
            raise ValueError("C2 span and transfer limits must be positive")


class C2BeaconDetector:
    detector_id = "c2.beacon"
    detector_version = "0.1.0"

    def __init__(
        self,
        config: C2Config | None = None,
        encrypted_metadata: dict[str, tuple[EncryptedSessionMetadata, float]] | None = None,
        allowlisted_destinations: set[str] | None = None,
        trusted_periodic_endpoints: tuple[EndpointRule, ...] = (),
    ) -> None:
        self.config = config or C2Config()
        self.encrypted_metadata = encrypted_metadata or {}
        self.allowlisted_destinations = allowlisted_destinations or set()
        self.trusted_periodic_endpoints = trusted_periodic_endpoints
        self.context_suppressed_records = 0
        self._windows: KeyedSlidingWindow[tuple[str, str, int, str], NetworkEvent] = (
            KeyedSlidingWindow(self.config.window_seconds)
        )
        self._last_alert: dict[tuple[str, str, int, str], float] = {}

    def process(self, event: NetworkEvent) -> list[Alert]:
        service = str(event.raw.get("service", "") or "").lower()
        # DNS repetition belongs to DNS analytics, not connection-level beaconing.
        if event.dst_port == 53 or service in {"dns", "domain"}:
            return []
        if any(rule.matches(event) for rule in self.trusted_periodic_endpoints):
            self.context_suppressed_records += 1
            return []
        key = (event.src_ip, event.dst_ip, event.dst_port, event.protocol)
        window = self._windows.add(key, event.timestamp, event)
        events = [item.value for item in window]
        if event.dst_ip in self.allowlisted_destinations or len(events) < self.config.minimum_connections:
            return []

        timestamps = [item.timestamp for item in events]
        intervals = [right - left for left, right in zip(timestamps, timestamps[1:])]
        mean_interval = sum(intervals) / len(intervals)
        interval_cv = _coefficient_of_variation(intervals)
        sizes = [float(item.outbound_bytes + item.inbound_bytes) for item in events]
        size_cv = _coefficient_of_variation(sizes)
        observation_span = timestamps[-1] - timestamps[0]
        mean_transfer_bytes = sum(sizes) / len(sizes)
        completed_ratio = sum(
            item.connection_state not in {"S0", "REJ"} for item in events
        ) / len(events)
        is_beacon = (
            self.config.minimum_mean_interval_seconds <= mean_interval <= self.config.maximum_mean_interval_seconds
            and interval_cv <= self.config.maximum_interval_cv
            and size_cv <= self.config.maximum_size_cv
            and observation_span >= self.config.minimum_observation_span_seconds
            and mean_transfer_bytes <= self.config.maximum_mean_transfer_bytes
            and completed_ratio >= self.config.minimum_completed_ratio
        )
        if not is_beacon:
            return []
        if event.timestamp - self._last_alert.get(key, float("-inf")) < self.config.cooldown_seconds:
            return []
        self._last_alert[key] = event.timestamp
        return [self._build_alert(
            event, events, mean_interval, interval_cv, size_cv,
            observation_span, mean_transfer_bytes, completed_ratio,
        )]

    def _build_alert(
        self,
        event: NetworkEvent,
        events: list[NetworkEvent],
        mean_interval: float,
        interval_cv: float,
        size_cv: float,
        observation_span: float,
        mean_transfer_bytes: float,
        completed_ratio: float,
    ) -> Alert:
        metadata = [self.encrypted_metadata[item.flow_id] for item in events if item.flow_id in self.encrypted_metadata]
        anomaly_scores = [item[1] for item in metadata]
        metadata_score = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else None
        server_names = sorted({item[0].server_name for item in metadata if item[0].server_name})
        fingerprints = sorted({item[0].client_fingerprint for item in metadata if item[0].client_fingerprint})

        timing_score = max(0.0, 1.0 - interval_cv / max(self.config.maximum_interval_cv, 0.001))
        size_score = max(0.0, 1.0 - size_cv / max(self.config.maximum_size_cv, 0.001))
        confidence = 0.68 + 0.12 * timing_score + 0.08 * size_score
        if metadata_score is not None:
            confidence += min(metadata_score, 0.5) * 0.08
        confidence = round(min(confidence, 0.96), 3)
        identity = (
            f"{self.detector_id}|{event.src_ip}|{event.dst_ip}|{event.dst_port}|"
            f"{events[0].timestamp:.6f}|{event.timestamp:.6f}"
        )
        evidence = [
            Evidence(
                "connection_count",
                len(events),
                f">= {self.config.minimum_connections}",
                "Repeated connections targeted the same endpoint inside the observation window.",
            ),
            Evidence(
                "mean_interval_seconds",
                round(mean_interval, 3),
                f"between {self.config.minimum_mean_interval_seconds} and {self.config.maximum_mean_interval_seconds}",
                "The average delay is consistent with periodic callback behaviour.",
            ),
            Evidence(
                "interval_variation",
                round(interval_cv, 4),
                f"<= {self.config.maximum_interval_cv}",
                "Low timing variation indicates regular periodic communication.",
            ),
            Evidence(
                "size_variation",
                round(size_cv, 4),
                f"<= {self.config.maximum_size_cv}",
                "Similar transfer sizes strengthen the repeated-beacon hypothesis.",
            ),
            Evidence(
                "observation_span_seconds",
                round(observation_span, 3),
                f">= {self.config.minimum_observation_span_seconds}",
                "A sustained sequence is stronger evidence than a short burst of normal web requests.",
            ),
            Evidence(
                "mean_transfer_bytes",
                round(mean_transfer_bytes, 3),
                f"<= {self.config.maximum_mean_transfer_bytes}",
                "Small repeated exchanges are more consistent with callbacks than ordinary content downloads.",
            ),
            Evidence(
                "completed_connection_ratio",
                round(completed_ratio, 3),
                f">= {self.config.minimum_completed_ratio}",
                "C2-like callbacks require repeated completed exchanges, not failed scan attempts.",
            ),
        ]
        if metadata_score is not None:
            evidence.extend([
                Evidence(
                    "encrypted_metadata_anomaly_score",
                    round(metadata_score, 3),
                    "supporting context only",
                    "TLS/QUIC metadata can adjust confidence but never triggers this alert alone.",
                ),
                Evidence(
                    "observed_server_names",
                    ", ".join(server_names) if server_names else "not visible",
                    "context",
                    "Server names observed on matching encrypted sessions.",
                ),
                Evidence(
                    "observed_client_fingerprints",
                    ", ".join(fingerprints) if fingerprints else "not available",
                    "context",
                    "Fingerprints are identifiers for correlation, not proof of malware.",
                ),
            ])
        return Alert(
            alert_id=sha256(identity.encode("utf-8")).hexdigest()[:20],
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            threat_type="command_and_control",
            subtype="periodic_beacon",
            confidence=confidence,
            severity="high" if len(events) >= self.config.minimum_connections * 2 else "medium",
            window_start=events[0].timestamp,
            window_end=event.timestamp,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            flow_ids=tuple(item.flow_id for item in events),
            evidence=tuple(evidence),
            limitations=(
                "Software updates, health checks and scheduled monitoring can be periodic.",
                "NAT, packet loss and observation gaps can distort timing and host attribution.",
                "TLS/QUIC payloads are not decrypted and fingerprints are not used as sole proof.",
            ),
        )
