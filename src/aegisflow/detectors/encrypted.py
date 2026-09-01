from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from aegisflow.models import Alert, EncryptedSessionMetadata, Evidence
from aegisflow.windowing import KeyedSlidingWindow


def _feature(event: EncryptedSessionMetadata, name: str, default: float = 0.0) -> float:
    raw: dict[str, Any] = event.raw
    features = raw.get("features", raw.get("ml_evidence", raw.get("evidence", {})))
    if not isinstance(features, dict):
        return default
    try:
        return float(features.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True, slots=True)
class EncryptedAnomalyConfig:
    window_seconds: float = 60.0
    minimum_sessions: int = 4
    maximum_fingerprint_prevalence: float = 0.01
    minimum_packet_size_anomaly: float = 0.75
    minimum_timing_anomaly: float = 0.75
    cooldown_seconds: float = 120.0


class EncryptedSessionAnomalyDetector:
    """Detect a repeated rare-fingerprint anomaly without decrypting payloads.

    A fingerprint is context, never a sole trigger. A finding requires repeated
    sessions plus independent timing and packet-size anomaly features.
    """

    detector_id = "encrypted.metadata_anomaly"
    detector_version = "0.1.0"

    def __init__(self, config: EncryptedAnomalyConfig | None = None) -> None:
        self.config = config or EncryptedAnomalyConfig()
        self._windows: KeyedSlidingWindow[
            tuple[str, str, str], EncryptedSessionMetadata
        ] = KeyedSlidingWindow(self.config.window_seconds)
        self._last_alert: dict[tuple[str, str, str], float] = {}

    def process(self, event: EncryptedSessionMetadata) -> list[Alert]:
        fingerprint = event.client_fingerprint.strip()
        if not fingerprint:
            return []
        key = (event.src_ip, event.dst_ip, fingerprint)
        window = self._windows.add(key, event.timestamp, event)
        sessions = [item.value for item in window]
        if len(sessions) < self.config.minimum_sessions:
            return []

        prevalence = sum(
            _feature(item, "ja4_prevalence", _feature(item, "ja3_prevalence", 1.0))
            for item in sessions
        ) / len(sessions)
        packet_anomaly = sum(
            _feature(item, "packet_size_sequence_anomaly") for item in sessions
        ) / len(sessions)
        timing_anomaly = sum(
            _feature(item, "timing_sequence_anomaly") for item in sessions
        ) / len(sessions)
        suspicious = (
            prevalence <= self.config.maximum_fingerprint_prevalence
            and packet_anomaly >= self.config.minimum_packet_size_anomaly
            and timing_anomaly >= self.config.minimum_timing_anomaly
        )
        if not suspicious:
            return []
        if event.timestamp - self._last_alert.get(key, float("-inf")) < self.config.cooldown_seconds:
            return []
        self._last_alert[key] = event.timestamp

        rarity_strength = 1.0 - min(
            prevalence / max(self.config.maximum_fingerprint_prevalence, 0.000001), 1.0
        )
        confidence = min(
            0.96,
            0.58 + 0.10 * rarity_strength + 0.14 * packet_anomaly + 0.14 * timing_anomaly,
        )
        identity = (
            f"{self.detector_id}|{event.src_ip}|{event.dst_ip}|{fingerprint}|"
            f"{sessions[0].timestamp:.6f}|{event.timestamp:.6f}"
        )
        return [Alert(
            alert_id=sha256(identity.encode("utf-8")).hexdigest()[:20],
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            threat_type="encrypted_session_threat",
            subtype="encrypted_session_metadata_anomaly",
            confidence=round(confidence, 3),
            severity="high",
            window_start=sessions[0].timestamp,
            window_end=event.timestamp,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            flow_ids=tuple(item.flow_id for item in sessions),
            evidence=(
                Evidence("repeated_encrypted_sessions", len(sessions), f">= {self.config.minimum_sessions}", "The same endpoint and fingerprint recurred inside the observation window."),
                Evidence("client_fingerprint", fingerprint, "context, not sole proof", "JA3/JA4 supports correlation but cannot identify malware by itself."),
                Evidence("fingerprint_prevalence", round(prevalence, 5), f"<= {self.config.maximum_fingerprint_prevalence}", "The fingerprint was rare in the supplied monitoring context."),
                Evidence("packet_size_sequence_anomaly", round(packet_anomaly, 3), f">= {self.config.minimum_packet_size_anomaly}", "Packet-size sequence behaviour independently appeared unusual."),
                Evidence("timing_sequence_anomaly", round(timing_anomaly, 3), f">= {self.config.minimum_timing_anomaly}", "Session timing independently appeared unusual."),
            ),
            limitations=(
                "Rare fingerprints can belong to legitimate new software.",
                "The payload remains encrypted; this is a metadata anomaly, not malware proof.",
                "Prevalence and sequence features must come from a trusted monitoring-side extractor.",
            ),
        )]
