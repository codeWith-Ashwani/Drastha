from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import math
from collections import Counter

from aegisflow.detectors.base import Detector
from aegisflow.models import Alert, Evidence, NetworkEvent
from aegisflow.windowing import KeyedSlidingWindow, TimedValue


@dataclass(frozen=True, slots=True)
class DDoSConfig:
    window_seconds: float = 5.0
    syn_attempt_threshold: int = 100
    min_incomplete_ratio: float = 0.80
    udp_packet_threshold: int = 1000
    minimum_target_port_concentration: float = 0.80
    udp_reflection_flow_threshold: int = 4
    udp_amplification_ratio_threshold: float = 10.0
    udp_reflection_bytes_threshold: int = 10_000
    spoofed_source_entropy_threshold: float = 0.85
    spoofed_source_minimum_sources: int = 3
    cooldown_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.syn_attempt_threshold < 2 or self.udp_packet_threshold < 2:
            raise ValueError("DDoS thresholds must be at least 2")
        if not 0.0 <= self.min_incomplete_ratio <= 1.0:
            raise ValueError("min_incomplete_ratio must be between 0 and 1")
        if not 0.0 < self.minimum_target_port_concentration <= 1.0:
            raise ValueError("minimum_target_port_concentration must be between 0 and 1")
        if self.udp_reflection_flow_threshold < 2:
            raise ValueError("udp_reflection_flow_threshold must be at least 2")
        if self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds cannot be negative")


class DDoSDetector(Detector):
    detector_id = "ddos.behavioural"
    detector_version = "0.1.0"
    _incomplete_states = frozenset({"S0", "REJ"})

    def __init__(self, config: DDoSConfig | None = None) -> None:
        self.config = config or DDoSConfig()
        self._events = KeyedSlidingWindow[str, NetworkEvent](self.config.window_seconds)
        self._last_alert: dict[tuple[str, str], float] = {}

    def process(self, event: NetworkEvent) -> list[Alert]:
        if event.protocol not in {"tcp", "udp"}:
            return []
        window = self._events.add(event.dst_ip, event.timestamp, event)
        alerts: list[Alert] = []
        if event.protocol == "tcp":
            alert = self._detect_syn_flood(event, window)
            if alert:
                alerts.append(alert)
        if event.protocol == "udp":
            alert = self._detect_udp_flood(event, window)
            if alert:
                alerts.append(alert)
            reflection = self._detect_udp_reflection(event, window)
            if reflection:
                alerts.append(reflection)
        return alerts

    def _detect_syn_flood(
        self, event: NetworkEvent, window: tuple[TimedValue[NetworkEvent], ...]
    ) -> Alert | None:
        tcp = [item.value for item in window if item.value.protocol == "tcp"]
        if len(tcp) < self.config.syn_attempt_threshold:
            return None
        incomplete = [item for item in tcp if item.connection_state in self._incomplete_states]
        ratio = len(incomplete) / len(tcp)
        if ratio < self.config.min_incomplete_ratio:
            return None
        port_counts: dict[int, int] = {}
        for item in tcp:
            port_counts[item.dst_port] = port_counts.get(item.dst_port, 0) + 1
        port_concentration = max(port_counts.values(), default=0) / len(tcp)
        # A single source touching many ports is reconnaissance, not a SYN flood.
        if port_concentration < self.config.minimum_target_port_concentration:
            return None
        sources = {item.src_ip for item in tcp}
        source_entropy = self._source_entropy(tcp)
        subtype = (
            "suspected_spoofed_source_flood"
            if len(sources) >= self.config.spoofed_source_minimum_sources
            and source_entropy >= self.config.spoofed_source_entropy_threshold
            else "syn_flood"
        )
        if self._cooling_down(event.dst_ip, subtype, event.timestamp):
            return None
        confidence = min(0.99, 0.65 + 0.20 * ratio + 0.14 * min(len(tcp) / self.config.syn_attempt_threshold - 1, 1))
        span = max(tcp[-1].timestamp - tcp[0].timestamp, 0.001)
        measured_rate = len(tcp) / span
        supplied_rates = []
        for item in tcp:
            features = item.raw.get(
                "features", item.raw.get("ml_evidence", item.raw.get("evidence", {}))
            )
            if isinstance(features, dict):
                for name in ("syn_rate_per_sec", "new_src_ips_per_sec"):
                    try:
                        supplied_rates.append(float(features[name]))
                    except (KeyError, TypeError, ValueError):
                        pass
        observed_rate = max([measured_rate, *supplied_rates])
        return self._alert(
            event=event,
            subtype=subtype,
            confidence=confidence,
            severity="critical" if len(tcp) >= 2 * self.config.syn_attempt_threshold else "high",
            relevant=tcp,
            evidence=(
                Evidence("tcp_connection_attempts", len(tcp), f">= {self.config.syn_attempt_threshold}", "Many TCP attempts targeted one host inside the window."),
                Evidence("incomplete_connection_ratio", round(ratio, 3), f">= {self.config.min_incomplete_ratio}", "Most attempts did not complete normally."),
                Evidence("unique_source_ips", len(sources), "context", "Source diversity helps distinguish concentrated and distributed floods."),
                Evidence("target_port_concentration", round(port_concentration, 3), f">= {self.config.minimum_target_port_concentration}", "Flood attempts remain concentrated on one service instead of fanning out like a port scan."),
                Evidence("connection_attempt_rate_per_second", round(observed_rate, 3), "rate feature", "Flow arrival rate measures volumetric pressure inside the observation window."),
                Evidence("normalized_source_ip_entropy", round(source_entropy, 3), f">= {self.config.spoofed_source_entropy_threshold} for spoofing suspicion", "High source diversity and entropy can indicate distributed or spoofed-source traffic."),
            ),
            limitations=(
                "Zeek connection state is a flow-level proxy; packet-level SYN/ACK counts will be added with capture features.",
                "A service outage or aggressive health check can also create incomplete connections.",
            ),
        )

    @staticmethod
    def _source_entropy(events: list[NetworkEvent]) -> float:
        counts = Counter(item.src_ip for item in events)
        if len(counts) <= 1:
            return 0.0
        total = len(events)
        entropy = -sum(
            (count / total) * math.log2(count / total) for count in counts.values()
        )
        return entropy / math.log2(len(counts))

    def _detect_udp_reflection(
        self, event: NetworkEvent, window: tuple[TimedValue[NetworkEvent], ...]
    ) -> Alert | None:
        udp = [item.value for item in window if item.value.protocol == "udp"]
        if len(udp) < self.config.udp_reflection_flow_threshold:
            return None
        request_bytes = sum(max(item.outbound_bytes, 0) for item in udp)
        response_bytes = sum(max(item.inbound_bytes, 0) for item in udp)
        amplification = response_bytes / max(request_bytes, 1)
        if (
            amplification < self.config.udp_amplification_ratio_threshold
            or response_bytes < self.config.udp_reflection_bytes_threshold
        ):
            return None
        subtype = "udp_reflection_amplification"
        if self._cooling_down(event.dst_ip, subtype, event.timestamp):
            return None
        sources = {item.src_ip for item in udp}
        confidence = min(
            0.97,
            0.68
            + 0.14 * min(amplification / self.config.udp_amplification_ratio_threshold - 1, 1)
            + 0.08 * min(len(udp) / self.config.udp_reflection_flow_threshold - 1, 1),
        )
        return self._alert(
            event=event,
            subtype=subtype,
            confidence=confidence,
            severity="high",
            relevant=udp,
            evidence=(
                Evidence("udp_flows_to_target", len(udp), f">= {self.config.udp_reflection_flow_threshold}", "Several UDP exchanges targeted the same host inside the window."),
                Evidence("response_to_request_byte_ratio", round(amplification, 3), f">= {self.config.udp_amplification_ratio_threshold}", "Responder-side volume was much larger than originator-side volume."),
                Evidence("udp_response_bytes", response_bytes, f">= {self.config.udp_reflection_bytes_threshold}", "The amplified response volume crossed the configured floor."),
                Evidence("unique_source_ips", len(sources), "context", "Source diversity supports reflection analysis but cannot prove spoofing."),
            ),
            limitations=(
                "Flow metadata can identify amplification-shaped traffic but cannot prove that source addresses were spoofed.",
                "Legitimate high-volume UDP services require environment-specific allowlists and baselines.",
            ),
        )

    def _detect_udp_flood(
        self, event: NetworkEvent, window: tuple[TimedValue[NetworkEvent], ...]
    ) -> Alert | None:
        udp = [item.value for item in window if item.value.protocol == "udp"]
        packets = sum(max(item.outbound_packets, 1) for item in udp)
        if packets < self.config.udp_packet_threshold:
            return None
        subtype = "udp_flood"
        if self._cooling_down(event.dst_ip, subtype, event.timestamp):
            return None
        sources = {item.src_ip for item in udp}
        outbound_bytes = sum(max(item.outbound_bytes, 0) for item in udp)
        ratio = packets / self.config.udp_packet_threshold
        confidence = min(0.99, 0.70 + 0.20 * min(max(ratio - 1, 0), 1) + 0.05 * min(len(sources) / 10, 1))
        return self._alert(
            event=event,
            subtype=subtype,
            confidence=confidence,
            severity="critical" if ratio >= 2 else "high",
            relevant=udp,
            evidence=(
                Evidence("udp_packets_to_target", packets, f">= {self.config.udp_packet_threshold}", "A high UDP packet volume targeted one host inside the window."),
                Evidence("udp_outbound_bytes", outbound_bytes, "context", "Byte volume provides scale evidence alongside packet count."),
                Evidence("unique_source_ips", len(sources), "context", "Source diversity indicates whether the flood is concentrated or distributed."),
            ),
            limitations=(
                "This Sprint 1 alert identifies UDP flooding; reflection/amplification attribution needs direction and service-aware packet features.",
                "Legitimate high-volume UDP applications require environment-specific baselines.",
            ),
        )

    def _cooling_down(self, target: str, subtype: str, timestamp: float) -> bool:
        key = (target, subtype)
        if timestamp - self._last_alert.get(key, float("-inf")) < self.config.cooldown_seconds:
            return True
        self._last_alert[key] = timestamp
        return False

    def _alert(
        self,
        event: NetworkEvent,
        subtype: str,
        confidence: float,
        severity: str,
        relevant: list[NetworkEvent],
        evidence: tuple[Evidence, ...],
        limitations: tuple[str, ...],
    ) -> Alert:
        start = min(item.timestamp for item in relevant)
        identity = f"{self.detector_id}|{subtype}|{event.dst_ip}|{start:.6f}|{event.timestamp:.6f}"
        return Alert(
            alert_id=sha256(identity.encode("utf-8")).hexdigest()[:20],
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            threat_type="denial_of_service",
            subtype=subtype,
            confidence=round(confidence, 3),
            severity=severity,
            window_start=start,
            window_end=event.timestamp,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            flow_ids=tuple(dict.fromkeys(item.flow_id for item in relevant)),
            evidence=evidence,
            limitations=limitations,
        )
