from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from hashlib import sha256

from aegisflow.detectors.base import Detector
from aegisflow.models import Alert, Evidence, NetworkEvent


@dataclass(frozen=True, slots=True)
class ReconConfig:
    window_seconds: float = 10.0
    unique_port_threshold: int = 20
    unique_host_threshold: int = 20
    cooldown_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.unique_port_threshold < 2 or self.unique_host_threshold < 2:
            raise ValueError("recon thresholds must be at least 2")
        if self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds cannot be negative")


@dataclass(frozen=True, slots=True)
class _Contact:
    timestamp: float
    dst_ip: str
    dst_port: int
    flow_id: str


class ReconDetector(Detector):
    detector_id = "recon.fanout"
    detector_version = "0.1.0"

    def __init__(self, config: ReconConfig | None = None) -> None:
        self.config = config or ReconConfig()
        self._contacts: dict[str, deque[_Contact]] = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], float] = {}

    def process(self, event: NetworkEvent) -> list[Alert]:
        contacts = self._contacts[event.src_ip]
        contacts.append(_Contact(event.timestamp, event.dst_ip, event.dst_port, event.flow_id))
        cutoff = event.timestamp - self.config.window_seconds
        while contacts and contacts[0].timestamp < cutoff:
            contacts.popleft()

        ports = {item.dst_port for item in contacts}
        hosts = {item.dst_ip for item in contacts}
        ports_by_host: dict[str, set[int]] = defaultdict(set)
        hosts_by_port: dict[int, set[str]] = defaultdict(set)
        for item in contacts:
            ports_by_host[item.dst_ip].add(item.dst_port)
            hosts_by_port[item.dst_port].add(item.dst_ip)

        vertical_host, vertical_ports = max(ports_by_host.items(), key=lambda pair: len(pair[1]))
        horizontal_port, horizontal_hosts = max(hosts_by_port.items(), key=lambda pair: len(pair[1]))
        candidates: list[tuple[str, int, int, str | None, int | None]] = []
        if len(vertical_ports) >= self.config.unique_port_threshold:
            candidates.append((
                "vertical_port_scan", len(vertical_ports),
                self.config.unique_port_threshold, vertical_host, None,
            ))
        if len(horizontal_hosts) >= self.config.unique_host_threshold:
            candidates.append((
                "horizontal_host_scan", len(horizontal_hosts),
                self.config.unique_host_threshold, None, horizontal_port,
            ))

        alerts: list[Alert] = []
        for subtype, observed, threshold, target_host, target_port in candidates:
            key = (event.src_ip, subtype)
            if event.timestamp - self._last_alert.get(key, float("-inf")) < self.config.cooldown_seconds:
                continue
            self._last_alert[key] = event.timestamp
            alerts.append(self._build_alert(
                event, contacts, ports, hosts, subtype, observed, threshold,
                target_host, target_port,
            ))
        return alerts

    def _build_alert(
        self,
        event: NetworkEvent,
        contacts: deque[_Contact],
        ports: set[int],
        hosts: set[str],
        subtype: str,
        observed: int,
        threshold: int,
        target_host: str | None,
        target_port: int | None,
    ) -> Alert:
        ratio = observed / threshold
        confidence = round(min(0.99, 0.70 + min(max(ratio - 1.0, 0.0), 1.0) * 0.25), 3)
        severity = "high" if ratio >= 2.0 else "medium"
        start = contacts[0].timestamp
        flow_ids = tuple(dict.fromkeys(item.flow_id for item in contacts))
        identity = f"{self.detector_id}|{subtype}|{event.src_ip}|{start:.6f}|{event.timestamp:.6f}"
        alert_id = sha256(identity.encode("utf-8")).hexdigest()[:20]

        if subtype == "vertical_port_scan":
            primary_name = "unique_destination_ports"
            explanation = "One source contacted many destination ports inside the observation window."
            destination = target_host
            pattern_context = f"Target host {target_host} received probes on {observed} unique ports."
        else:
            primary_name = "unique_destination_hosts"
            explanation = "One source contacted many destination hosts inside the observation window."
            destination = None
            pattern_context = f"Destination port {target_port} was probed across {observed} unique hosts."

        return Alert(
            alert_id=alert_id,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            threat_type="reconnaissance",
            subtype=subtype,
            confidence=confidence,
            severity=severity,
            window_start=start,
            window_end=event.timestamp,
            src_ip=event.src_ip,
            dst_ip=destination,
            flow_ids=flow_ids,
            evidence=(
                Evidence(primary_name, observed, f">= {threshold}", explanation),
                Evidence(
                    "observation_window_seconds",
                    round(event.timestamp - start, 3),
                    f"<= {self.config.window_seconds}",
                    "The fan-out occurred inside the configured sliding window.",
                ),
                Evidence(
                    "connection_attempts",
                    len(contacts),
                    "context",
                    pattern_context + f" The full window contained {len(ports)} ports and {len(hosts)} hosts.",
                ),
            ),
            limitations=(
                "Authorized vulnerability scanners can produce the same fan-out pattern.",
                "Severity does not include asset criticality in Sprint 0.",
            ),
        )
