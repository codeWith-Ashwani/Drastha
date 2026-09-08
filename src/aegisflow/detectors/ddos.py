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
    distributed_source_entropy_threshold: float = 0.85
    distributed_source_minimum_sources: int = 3
    cooldown_seconds: float = 30.0
    require_reflection_service_context: bool = False
    slow_http_window_seconds: float = 15.0
    slow_http_connection_threshold: int = 20
    slow_http_minimum_duration_seconds: float = 120.0
    slow_http_maximum_bytes_per_connection: int = 2048
    slow_http_maximum_packets_per_connection: int = 8

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
        if self.slow_http_window_seconds <= 0 or self.slow_http_connection_threshold < 2:
            raise ValueError("Slow HTTP window must be positive and connection threshold at least 2")
        if self.slow_http_minimum_duration_seconds <= 0:
            raise ValueError("Slow HTTP minimum duration must be positive")
        if self.slow_http_maximum_bytes_per_connection <= 0 or self.slow_http_maximum_packets_per_connection <= 0:
            raise ValueError("Slow HTTP volume ceilings must be positive")


class DDoSDetector(Detector):
    detector_id = "ddos.behavioural"
    detector_version = "0.3.0"
    _incomplete_states = frozenset({"S0", "REJ"})

    def __init__(self, config: DDoSConfig | None = None) -> None:
        self.config = config or DDoSConfig()
        self._events = KeyedSlidingWindow[str, NetworkEvent](self.config.window_seconds)
        self._reflection_events = KeyedSlidingWindow[str, NetworkEvent](self.config.window_seconds)
        self._slow_http_events = KeyedSlidingWindow[str, NetworkEvent](
            self.config.slow_http_window_seconds
        )
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
            slow_http = self._detect_slow_http(event)
            if slow_http:
                alerts.append(slow_http)
        if event.protocol == "udp":
            alert = self._detect_udp_flood(event, window)
            if alert:
                alerts.append(alert)
            reflection_window = (self._reflection_events.add(event.src_ip, event.timestamp, event)
                                 if self.config.require_reflection_service_context else window)
            reflection = self._detect_udp_reflection(event, reflection_window)
            if reflection:
                alerts.append(reflection)
        return alerts

    def _detect_slow_http(self, event: NetworkEvent) -> Alert | None:
        """Detect connection-exhaustion shape from passive flow metadata only.

        Zeek emits a connection record after observation/termination, so this is
        an overlap estimate from start time plus duration, not a live socket count.
        Requiring HTTP service, long duration, partial state and tiny transfers
        prevents ordinary completed web downloads from satisfying the rule.
        """
        service = str(event.raw.get("service", "") or "").lower()
        if event.dst_port not in {80, 8080, 8000, 8888} or service not in {"http", "http-alt"}:
            return None
        window = self._slow_http_events.add(event.dst_ip, event.timestamp, event)
        candidates = [
            item.value for item in window
            if item.value.protocol == "tcp"
            and item.value.connection_state in {"S1", "OTH"}
            and item.value.duration_seconds >= self.config.slow_http_minimum_duration_seconds
            and item.value.outbound_bytes + item.value.inbound_bytes
                <= self.config.slow_http_maximum_bytes_per_connection
            and item.value.outbound_packets + item.value.inbound_packets
                <= self.config.slow_http_maximum_packets_per_connection
        ]
        if len(candidates) < self.config.slow_http_connection_threshold:
            return None
        subtype = "slow_http_connection_exhaustion"
        if self._cooling_down(event.dst_ip, subtype, event.timestamp):
            return None
        durations = [item.duration_seconds for item in candidates]
        byte_totals = [item.outbound_bytes + item.inbound_bytes for item in candidates]
        estimated_overlap = sum(
            item.timestamp + item.duration_seconds >= event.timestamp for item in candidates
        )
        confidence = min(
            0.96,
            0.70 + 0.14 * min(len(candidates) / self.config.slow_http_connection_threshold - 1, 1)
            + 0.08 * min(min(durations) / self.config.slow_http_minimum_duration_seconds - 1, 1),
        )
        return self._alert(
            event=event,
            subtype=subtype,
            confidence=confidence,
            severity="high",
            relevant=candidates,
            evidence=(
                Evidence("long_lived_partial_http_connections", len(candidates),
                         f">= {self.config.slow_http_connection_threshold}",
                         "Many long-lived partial HTTP connections targeted one server."),
                Evidence("estimated_overlapping_connections", estimated_overlap,
                         "passive start-time plus duration estimate",
                         "Observed start times and durations indicate concurrent resource occupancy."),
                Evidence("minimum_connection_duration_seconds", round(min(durations), 3),
                         f">= {self.config.slow_http_minimum_duration_seconds}",
                         "Long duration distinguishes slow resource holding from a short request burst."),
                Evidence("maximum_bytes_per_connection", max(byte_totals),
                         f"<= {self.config.slow_http_maximum_bytes_per_connection}",
                         "Very small transfers despite long duration support a slow-request hypothesis."),
                Evidence("http_destination_port", event.dst_port, "HTTP service context",
                         "The passive service label and destination port identify HTTP-shaped traffic."),
            ),
            limitations=(
                "Passive flow metadata cannot prove a specific Slowloris tool or inspect HTTP headers.",
                "Zeek connection records may arrive only after termination; overlap is estimated from timestamps and durations.",
                "Legitimate long polling requires deployment-specific service policy and baseline validation.",
            ),
        )

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
            "distributed_source_syn_flood"
            if len(sources) >= self.config.distributed_source_minimum_sources
            and source_entropy >= self.config.distributed_source_entropy_threshold
            else "syn_flood"
        )
        if self._cooling_down(event.dst_ip, subtype, event.timestamp):
            return None
        confidence = min(0.99, 0.65 + 0.20 * ratio + 0.14 * min(len(tcp) / self.config.syn_attempt_threshold - 1, 1))
        span = max(tcp[-1].timestamp - tcp[0].timestamp, 0.001)
        measured_rate = len(tcp) / span
        observed_rate = measured_rate
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
                Evidence("normalized_source_ip_entropy", round(source_entropy, 3), f">= {self.config.distributed_source_entropy_threshold} for distributed-source classification", "High source diversity and entropy support a distributed-source classification; passive flows cannot establish whether addresses were spoofed."),
            ),
            limitations=(
                "Zeek connection state is a flow-level proxy; packet-level SYN/ACK counts will be added with capture features.",
                "A service outage or aggressive health check can also create incomplete connections.",
                "Source diversity does not prove IP spoofing; this alert deliberately uses distributed-source wording.",
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
        services = {19: "chargen", 53: "dns", 123: "ntp", 389: "cldap", 1900: "ssdp", 11211: "memcached"}
        strict = self.config.require_reflection_service_context
        if strict:
            # Zeek originator is the request side. Responses return from a
            # recognizable service to that originator, potentially via many hosts.
            udp = [item for item in udp if item.dst_port in services and item.outbound_bytes > 0]
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
        target = event.src_ip if strict else event.dst_ip
        if self._cooling_down(target, subtype, event.timestamp):
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
            target=target,
            subtype=subtype,
            confidence=confidence,
            severity="high",
            relevant=udp,
            evidence=(
                Evidence("udp_flows_to_target", len(udp), f">= {self.config.udp_reflection_flow_threshold}", "Several UDP exchanges targeted the same host inside the window."),
                Evidence("response_to_request_byte_ratio", round(amplification, 3), f">= {self.config.udp_amplification_ratio_threshold}", "Responder-side volume was much larger than originator-side volume."),
                Evidence("udp_response_bytes", response_bytes, f">= {self.config.udp_reflection_bytes_threshold}", "The amplified response volume crossed the configured floor."),
                Evidence("unique_source_ips", len(sources), "context", "Source diversity supports reflection analysis but cannot prove spoofing."),
                Evidence("observed_udp_services", ",".join(sorted({services.get(item.dst_port, "unknown") for item in udp})), "service context", "Responder port identifies a candidate service, not proof of reflection."),
                Evidence("response_recipient", event.src_ip if strict else "legacy-target-group", "direction", "In service-aware mode, responses are grouped by the Zeek originator receiving them."),
                Evidence("responder_host_count", len({item.dst_ip for item in udp}), "context", "Number of observed response-side endpoints."),
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
        target: str | None = None,
    ) -> Alert:
        start = min(item.timestamp for item in relevant)
        target = target or event.dst_ip
        identity = f"{self.detector_id}|{subtype}|{target}|{start:.6f}|{event.timestamp:.6f}"
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
            dst_ip=target,
            flow_ids=tuple(dict.fromkeys(item.flow_id for item in relevant)),
            evidence=evidence,
            limitations=limitations,
        )
