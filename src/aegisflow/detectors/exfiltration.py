from __future__ import annotations

import statistics
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any

from aegisflow.context_policy import EndpointRule
from aegisflow.detectors.base import Detector
from aegisflow.models import Alert, Evidence, NetworkEvent
from aegisflow.windowing import KeyedSlidingWindow


@dataclass(frozen=True, slots=True)
class ExfiltrationConfig:
    window_seconds: float = 300.0
    minimum_flows: int = 3
    minimum_outbound_bytes: int = 1_000_000
    minimum_outbound_ratio: float = 8.0
    baseline_multiplier: float = 4.0
    baseline_history_size: int = 50
    single_flow_minimum_outbound_bytes: int = 10_000_000
    single_flow_minimum_outbound_ratio: float = 20.0
    baseline_free_minimum_outbound_bytes: int = 10_000_000
    baseline_free_minimum_outbound_ratio: float = 20.0
    cooldown_seconds: float = 600.0

    def __post_init__(self) -> None:
        if self.window_seconds <= 0 or self.minimum_flows < 2:
            raise ValueError("exfiltration window must be positive and minimum_flows at least 2")
        if self.minimum_outbound_bytes <= 0 or self.minimum_outbound_ratio <= 1:
            raise ValueError("exfiltration volume and ratio thresholds must be positive")
        if self.baseline_multiplier <= 1 or self.baseline_history_size < 3:
            raise ValueError("baseline multiplier must exceed 1 and history size at least 3")


class ExfiltrationDetector(Detector):
    detector_id = "exfiltration.outbound"
    detector_version = "0.1.0"

    def __init__(
        self,
        config: ExfiltrationConfig | None = None,
        approved_backup_destinations: set[str] | None = None,
        approved_bulk_transfer_endpoints: tuple[EndpointRule, ...] = (),
    ) -> None:
        self.config = config or ExfiltrationConfig()
        self.approved_backup_destinations = approved_backup_destinations or set()
        self.approved_bulk_transfer_endpoints = approved_bulk_transfer_endpoints
        self.context_suppressed_records = 0
        self._windows: KeyedSlidingWindow[tuple[str, str], NetworkEvent] = KeyedSlidingWindow(
            self.config.window_seconds
        )
        self._source_baselines: dict[str, deque[int]] = defaultdict(
            lambda: deque(maxlen=self.config.baseline_history_size)
        )
        self._destination_first_seen: dict[tuple[str, str], float] = {}
        self._last_alert: dict[tuple[str, str], float] = {}

    def export_state(self) -> dict[str, Any]:
        return {
            "version": 1,
            "detector_id": self.detector_id,
            "source_baselines": {
                source: list(values) for source, values in self._source_baselines.items()
            },
            "destination_first_seen": [
                {"src_ip": key[0], "dst_ip": key[1], "timestamp": timestamp}
                for key, timestamp in self._destination_first_seen.items()
            ],
            "last_alert": [
                {"src_ip": key[0], "dst_ip": key[1], "timestamp": timestamp}
                for key, timestamp in self._last_alert.items()
            ],
            "windows": [
                {
                    "src_ip": key[0],
                    "dst_ip": key[1],
                    "events": [asdict(item.value) for item in values],
                }
                for key, values in self._windows.items()
            ],
        }

    def restore_state(self, state: dict[str, Any]) -> None:
        if state.get("version") != 1 or state.get("detector_id") != self.detector_id:
            raise ValueError("incompatible exfiltration detector state")
        self._windows.clear()
        self._source_baselines.clear()
        self._destination_first_seen.clear()
        self._last_alert.clear()
        for source, values in state.get("source_baselines", {}).items():
            self._source_baselines[source].extend(int(value) for value in values)
        for item in state.get("destination_first_seen", []):
            self._destination_first_seen[(item["src_ip"], item["dst_ip"])] = float(
                item["timestamp"]
            )
        for item in state.get("last_alert", []):
            self._last_alert[(item["src_ip"], item["dst_ip"])] = float(item["timestamp"])
        for window in state.get("windows", []):
            key = (window["src_ip"], window["dst_ip"])
            for record in window.get("events", []):
                event = NetworkEvent(**record)
                self._windows.add(key, event.timestamp, event)

    def process(self, event: NetworkEvent) -> list[Alert]:
        if (
            event.dst_ip in self.approved_backup_destinations
            or any(rule.matches(event) for rule in self.approved_bulk_transfer_endpoints)
        ):
            self.context_suppressed_records += 1
            return []

        baseline_history = self._source_baselines[event.src_ip]
        baseline_median = statistics.median(baseline_history) if baseline_history else 0.0
        key = (event.src_ip, event.dst_ip)
        self._destination_first_seen.setdefault(key, event.timestamp)
        window = self._windows.add(key, event.timestamp, event)
        events = [item.value for item in window]
        single_ratio = event.outbound_bytes / max(event.inbound_bytes, 1)
        if (
            event.outbound_bytes >= self.config.single_flow_minimum_outbound_bytes
            and single_ratio >= self.config.single_flow_minimum_outbound_ratio
            and event.timestamp - self._last_alert.get(key, float("-inf")) >= self.config.cooldown_seconds
        ):
            baseline_history.append(event.outbound_bytes)
            self._last_alert[key] = event.timestamp
            return [self._build_alert(
                event,
                [event],
                event.outbound_bytes,
                event.inbound_bytes,
                single_ratio,
                float(event.outbound_bytes),
                baseline_median,
            )]
        if len(events) < self.config.minimum_flows:
            baseline_history.append(event.outbound_bytes)
            return []

        outbound = sum(item.outbound_bytes for item in events)
        inbound = sum(item.inbound_bytes for item in events)
        ratio = outbound / max(inbound, 1)
        average_outbound = outbound / len(events)
        baseline_threshold = max(baseline_median * self.config.baseline_multiplier, 1.0)
        exceeds_baseline = baseline_median > 0 and average_outbound >= baseline_threshold
        baseline_anomaly = (
            outbound >= self.config.minimum_outbound_bytes
            and ratio >= self.config.minimum_outbound_ratio
            and exceeds_baseline
        )
        baseline_free_extreme_asymmetry = (
            outbound >= self.config.baseline_free_minimum_outbound_bytes
            and ratio >= self.config.baseline_free_minimum_outbound_ratio
        )
        suspicious = baseline_anomaly or baseline_free_extreme_asymmetry
        if not suspicious:
            baseline_history.append(event.outbound_bytes)
            return []
        if event.timestamp - self._last_alert.get(key, float("-inf")) < self.config.cooldown_seconds:
            baseline_history.append(event.outbound_bytes)
            return []
        baseline_history.append(event.outbound_bytes)
        self._last_alert[key] = event.timestamp
        return [
            self._build_alert(
                event, events, outbound, inbound, ratio, average_outbound, baseline_median
            )
        ]

    def _build_alert(
        self,
        event: NetworkEvent,
        events: list[NetworkEvent],
        outbound: int,
        inbound: int,
        ratio: float,
        average_outbound: float,
        baseline_median: float,
    ) -> Alert:
        key = (event.src_ip, event.dst_ip)
        destination_age = event.timestamp - self._destination_first_seen[key]
        volume_ratio = outbound / self.config.minimum_outbound_bytes
        confidence = round(min(0.96, 0.70 + min(volume_ratio - 1.0, 1.0) * 0.12 + min(ratio / 50, 1) * 0.10), 3)
        identity = (
            f"{self.detector_id}|{event.src_ip}|{event.dst_ip}|"
            f"{events[0].timestamp:.6f}|{event.timestamp:.6f}"
        )
        return Alert(
            alert_id=sha256(identity.encode("utf-8")).hexdigest()[:20],
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            threat_type="data_exfiltration",
            subtype="outbound_volume_anomaly",
            confidence=confidence,
            severity="high",
            window_start=events[0].timestamp,
            window_end=event.timestamp,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            flow_ids=tuple(item.flow_id for item in events),
            evidence=(
                Evidence(
                    "outbound_bytes",
                    outbound,
                    f">= {self.config.minimum_outbound_bytes}",
                    "A large outbound transfer accumulated inside the configured window.",
                ),
                Evidence(
                    "outbound_to_inbound_ratio",
                    round(ratio, 3),
                    f">= {self.config.minimum_outbound_ratio}",
                    f"Outbound volume substantially exceeded the {inbound} observed inbound bytes.",
                ),
                Evidence(
                    "average_outbound_bytes_per_flow",
                    round(average_outbound, 3),
                    f">= {self.config.baseline_multiplier}x source median",
                    f"The prior source median was {round(baseline_median, 3)} bytes per flow.",
                ),
                Evidence(
                    "destination_age_seconds",
                    round(destination_age, 3),
                    "context",
                    "Recently observed destinations can increase analyst concern but do not trigger alone.",
                ),
            ),
            limitations=(
                "Approved backups and bulk uploads can resemble exfiltration and require allowlisting.",
                "The baseline survives restarts only when a Drastha repository is configured.",
                "NAT and incomplete observation can distort device attribution and byte ratios.",
            ),
        )
