from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from aegisflow.dns_features import base_domain, leftmost_label, lexical_features, shannon_entropy
from aegisflow.dns_model import DNSNgramModel
from aegisflow.models import Alert, DNSEvent, Evidence
from aegisflow.windowing import KeyedSlidingWindow


@dataclass(frozen=True, slots=True)
class DNSConfig:
    window_seconds: float = 60.0
    tunnel_query_threshold: int = 20
    tunnel_unique_subdomain_threshold: int = 15
    tunnel_label_length_threshold: float = 18.0
    tunnel_entropy_threshold: float = 3.5
    dga_probability_threshold: float = 0.50
    cooldown_seconds: float = 120.0

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.tunnel_query_threshold < 2 or self.tunnel_unique_subdomain_threshold < 2:
            raise ValueError("DNS tunnel thresholds must be at least 2")
        if not 0.0 < self.dga_probability_threshold < 1.0:
            raise ValueError("DGA probability threshold must be between 0 and 1")


class DNSDetector:
    detector_id = "dns.analytics"
    detector_version = "0.1.0"

    def __init__(
        self,
        config: DNSConfig | None = None,
        model: DNSNgramModel | None = None,
        allowlisted_base_domains: set[str] | None = None,
    ) -> None:
        self.config = config or DNSConfig()
        self.model = model
        self.allowlisted_base_domains = {
            base_domain(domain) for domain in (allowlisted_base_domains or set())
        }
        self._queries: KeyedSlidingWindow[tuple[str, str], DNSEvent] = KeyedSlidingWindow(
            self.config.window_seconds
        )
        self._last_alert: dict[tuple[str, str, str], float] = {}

    def process(self, event: DNSEvent) -> list[Alert]:
        alerts: list[Alert] = []
        root = base_domain(event.query)
        if self.model and root not in self.allowlisted_base_domains:
            probability = self.model.predict_probability(root)
            key = (event.src_ip, "dga_like_domain", root)
            if probability >= self.config.dga_probability_threshold and self._cooldown_ready(key, event.timestamp):
                alerts.append(self._dga_alert(event, probability, root))

        window = self._queries.add((event.src_ip, root), event.timestamp, event)
        queries = [item.value for item in window]
        labels = [leftmost_label(item.query) for item in queries]
        unique_labels = set(labels)
        average_length = sum(len(label) for label in labels) / len(labels)
        average_entropy = sum(shannon_entropy(label) for label in labels) / len(labels)
        tunnel = (
            len(queries) >= self.config.tunnel_query_threshold
            and len(unique_labels) >= self.config.tunnel_unique_subdomain_threshold
            and (
                average_length >= self.config.tunnel_label_length_threshold
                or average_entropy >= self.config.tunnel_entropy_threshold
            )
        )
        tunnel_key = (event.src_ip, "dns_tunnelling", root)
        if tunnel and root not in self.allowlisted_base_domains and self._cooldown_ready(tunnel_key, event.timestamp):
            alerts.append(
                self._tunnel_alert(event, queries, root, len(unique_labels), average_length, average_entropy)
            )
        return alerts

    def _cooldown_ready(self, key: tuple[str, str, str], timestamp: float) -> bool:
        if timestamp - self._last_alert.get(key, float("-inf")) < self.config.cooldown_seconds:
            return False
        self._last_alert[key] = timestamp
        return True

    def _identity(self, subtype: str, event: DNSEvent, subject: str) -> str:
        value = f"{self.detector_id}|{subtype}|{event.src_ip}|{subject}|{event.timestamp:.6f}"
        return sha256(value.encode("utf-8")).hexdigest()[:20]

    def _dga_alert(self, event: DNSEvent, probability: float, root: str) -> Alert:
        features = lexical_features(root)
        return Alert(
            alert_id=self._identity("dga_like_domain", event, root),
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            threat_type="dns_threat",
            subtype="dga_like_domain",
            confidence=round(probability, 3),
            severity="medium",
            window_start=event.timestamp,
            window_end=event.timestamp,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            flow_ids=(event.flow_id,),
            evidence=(
                Evidence(
                    "model_probability",
                    round(probability, 4),
                    f">= {self.config.dga_probability_threshold}",
                    "Character n-gram patterns resemble the malicious training class.",
                ),
                Evidence(
                    "queried_domain",
                    root,
                    "model input",
                    "The approximate registered domain evaluated by the model.",
                ),
                Evidence(
                    "domain_entropy",
                    round(features["entropy"], 3),
                    "context only",
                    "Entropy is shown for analyst context and is not proof by itself.",
                ),
            ),
            limitations=(
                "New legitimate domains, CDNs and hosted services can resemble DGA names.",
                "The bundled demonstration model is not a production-quality threat classifier.",
                "Encrypted DNS that is not visible to Zeek cannot be evaluated.",
            ),
        )

    def _tunnel_alert(
        self,
        event: DNSEvent,
        queries: list[DNSEvent],
        root: str,
        unique_labels: int,
        average_length: float,
        average_entropy: float,
    ) -> Alert:
        return Alert(
            alert_id=self._identity("dns_tunnelling", event, root),
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            threat_type="dns_threat",
            subtype="dns_tunnelling",
            confidence=round(min(0.99, 0.72 + 0.01 * (unique_labels - self.config.tunnel_unique_subdomain_threshold)), 3),
            severity="high",
            window_start=queries[0].timestamp,
            window_end=event.timestamp,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            flow_ids=tuple(dict.fromkeys(item.flow_id for item in queries)),
            evidence=(
                Evidence(
                    "queries_to_base_domain",
                    len(queries),
                    f">= {self.config.tunnel_query_threshold}",
                    f"Many DNS queries targeted subdomains of {root} inside one window.",
                ),
                Evidence(
                    "unique_subdomain_labels",
                    unique_labels,
                    f">= {self.config.tunnel_unique_subdomain_threshold}",
                    "High subdomain variation can carry encoded data.",
                ),
                Evidence(
                    "average_subdomain_length",
                    round(average_length, 3),
                    f">= {self.config.tunnel_label_length_threshold} or entropy threshold",
                    "Long labels are consistent with data encoded into DNS names.",
                ),
                Evidence(
                    "average_subdomain_entropy",
                    round(average_entropy, 3),
                    f">= {self.config.tunnel_entropy_threshold} or length threshold",
                    "High character randomness is consistent with encoded content.",
                ),
            ),
            limitations=(
                "CDNs, endpoint security products and hosted telemetry can generate similar subdomains.",
                "Base-domain extraction uses a two-label approximation until a public-suffix snapshot is bundled.",
                "Encrypted DNS that is not visible to Zeek cannot be evaluated.",
            ),
        )
