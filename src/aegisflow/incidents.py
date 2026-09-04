from __future__ import annotations

from hashlib import sha256

from aegisflow.models import (
    AggregateRisk,
    Alert,
    AnalystFeedback,
    Evidence,
    Incident,
    IncidentConclusion,
)


THREAT_WEIGHTS = {
    "reconnaissance": 15,
    "denial_of_service": 25,
    "dns_threat": 25,
    "command_and_control": 35,
    "data_exfiltration": 40,
}


# These are cautious intent hypotheses, not signatures that claim to know an
# attacker's identity or state of mind. They translate detector output into an
# analyst-ready conclusion while preserving the limits of passive observation.
CONCLUSION_PROFILES = {
    "syn_flood": (
        "availability disruption",
        "a concentrated burst of incomplete TCP connection attempts",
        "exhaust connection-handling capacity and make the target service unavailable",
        "service latency, connection-table exhaustion, or loss of availability",
    ),
    "distributed_source_syn_flood": (
        "availability disruption",
        "incomplete TCP connection attempts distributed across many source addresses",
        "exhaust connection-handling capacity while making the flood harder to filter by source",
        "service latency, connection-table exhaustion, or loss of availability",
    ),
    "udp_flood": (
        "availability disruption",
        "an unusually high rate of UDP traffic directed at the target",
        "consume target or link capacity and reduce service availability",
        "bandwidth saturation, packet loss, or service unavailability",
    ),
    "udp_reflection_amplification": (
        "availability disruption",
        "a UDP response pattern consistent with reflection or amplification",
        "overwhelm the target with amplified third-party UDP responses",
        "bandwidth saturation, packet loss, or service unavailability",
    ),
    "vertical_port_scan": (
        "discovery",
        "one source probing many ports on a destination",
        "map exposed services and identify an entry point for later access",
        "exposure of reachable services followed by targeted exploitation attempts",
    ),
    "horizontal_host_scan": (
        "discovery",
        "one source probing the same service across many destinations",
        "discover hosts exposing a service that could be targeted later",
        "identification of vulnerable or unexpectedly reachable systems",
    ),
    "multi_host_port_scan": (
        "discovery",
        "one source probing multiple hosts and destination ports",
        "map the reachable attack surface before selecting targets for later access",
        "identification of systems and services suitable for follow-on exploitation",
    ),
    "periodic_beacon": (
        "command and control",
        "regular, low-variation callbacks to a small destination set",
        "maintain recurring command-and-control contact with external infrastructure",
        "continued remote coordination, tasking, or payload retrieval",
    ),
    "dga_like_domain": (
        "command-and-control discovery",
        "DNS names with algorithmically generated characteristics",
        "locate rotating infrastructure while resisting static domain blocklists",
        "connection to disposable command-and-control or payload infrastructure",
    ),
    "dns_tunnelling": (
        "covert communication",
        "DNS queries carrying unusually long or encoded-looking labels and record patterns",
        "carry commands or data through DNS to blend with permitted name-resolution traffic",
        "covert command-and-control communication or data leakage through DNS",
    ),
    "encrypted_session_metadata_anomaly": (
        "execution or command and control",
        "an encrypted session whose fingerprint, packet sizes, or timing differ from the learned baseline",
        "hide potentially malicious communication inside encryption",
        "unobserved command-and-control, payload delivery, or other malicious activity",
    ),
    "outbound_volume_anomaly": (
        "collection and exfiltration",
        "an unusually large and asymmetric outbound transfer",
        "move a substantial volume of data out of the monitored environment",
        "loss of confidential or operational data if the transfer is unauthorized",
    ),
}

THREAT_CONCLUSION_FALLBACKS = {
    "denial_of_service": CONCLUSION_PROFILES["syn_flood"],
    "reconnaissance": CONCLUSION_PROFILES["multi_host_port_scan"],
    "command_and_control": CONCLUSION_PROFILES["periodic_beacon"],
    "dns_threat": CONCLUSION_PROFILES["dga_like_domain"],
    "encrypted_session_threat": CONCLUSION_PROFILES["encrypted_session_metadata_anomaly"],
    "data_exfiltration": CONCLUSION_PROFILES["outbound_volume_anomaly"],
}


def aggregate_incident_risk(incidents: list[Incident] | tuple[Incident, ...]) -> AggregateRisk:
    """Calculate one transparent replay-wide priority score.

    The strongest incident anchors the score so a serious finding cannot be
    diluted by averaging. Small, capped bonuses represent incident breadth and
    distinct threat-category breadth. This is a triage score, not a probability
    and not evidence that otherwise independent incidents share one operator.
    """
    if not incidents:
        return AggregateRisk(
            score=0,
            severity="none",
            incident_count=0,
            distinct_threat_types=0,
            affected_sources=0,
            dominant_incident_id=None,
            dominant_threat_types=(),
            scoring_factors=(),
            assessment="No incident was produced by the configured detectors in this replay.",
            uncertainty=(
                "A zero score means no configured incident was observed; it does not prove the "
                "traffic is safe. Data quality and feature coverage still apply."
            ),
        )

    dominant = max(incidents, key=lambda item: (item.risk_score, item.confidence))
    threat_types = {threat for incident in incidents for threat in incident.threat_types}
    sources = {incident.src_ip for incident in incidents}
    incident_bonus = min(15, max(0, len(incidents) - 1) * 3)
    diversity_bonus = min(15, max(0, len(threat_types) - 1) * 3)
    score = min(100, dominant.risk_score + incident_bonus + diversity_bonus)
    severity = (
        "critical" if score >= 80 else "high" if score >= 60
        else "medium" if score >= 35 else "low"
    )
    return AggregateRisk(
        score=score,
        severity=severity,
        incident_count=len(incidents),
        distinct_threat_types=len(threat_types),
        affected_sources=len(sources),
        dominant_incident_id=dominant.incident_id,
        dominant_threat_types=dominant.threat_types,
        scoring_factors=(
            Evidence(
                "dominant_incident_risk", dominant.risk_score, "base component",
                "The highest incident score anchors replay-wide priority and is never averaged down.",
            ),
            Evidence(
                "incident_breadth_bonus", incident_bonus, "capped at 15",
                "Additional incidents increase operational investigation scope.",
            ),
            Evidence(
                "threat_diversity_bonus", diversity_bonus, "capped at 15",
                "Distinct threat categories indicate broader security exposure.",
            ),
        ),
        assessment=(
            f"{len(incidents)} incidents across {len(sources)} sources and "
            f"{len(threat_types)} threat categories produce a {severity} overall "
            f"investigation priority. Incident {dominant.incident_id} is the dominant risk driver."
        ),
        uncertainty=(
            "This score aggregates investigation priority from passive metadata. It is not an "
            "attack probability, and it does not prove that separate incidents are coordinated."
        ),
    )


def _join_phrases(values: list[str]) -> str:
    unique = list(dict.fromkeys(values))
    if len(unique) < 2:
        return unique[0]
    return "; and ".join(unique)


def build_incident_conclusion(alerts: list[Alert]) -> IncidentConclusion:
    """Build a stable conclusion from detector output, never evaluation labels."""
    if not alerts:
        raise ValueError("at least one alert is required to conclude an incident")

    profiles = [
        CONCLUSION_PROFILES.get(alert.subtype)
        or THREAT_CONCLUSION_FALLBACKS.get(alert.threat_type)
        or (
            "investigation",
            "network behaviour outside the configured baseline",
            "perform activity that requires analyst investigation",
            "operational or security impact that cannot yet be determined",
        )
        for alert in alerts
    ]
    destinations = sorted({alert.dst_ip for alert in alerts if alert.dst_ip})
    destination_text = (
        destinations[0] if len(destinations) == 1
        else f"{len(destinations)} observed destinations" if destinations
        else "multiple or unresolved destinations"
    )
    behaviours = _join_phrases([profile[1] for profile in profiles])
    objectives = _join_phrases([profile[2] for profile in profiles])
    stages = _join_phrases([profile[0] for profile in profiles])
    impacts = _join_phrases([profile[3] for profile in profiles])

    basis: list[str] = []
    for alert in alerts:
        for evidence in alert.evidence:
            statement = (
                f"{evidence.explanation} Observed {evidence.name.replace('_', ' ')}: "
                f"{evidence.observed} ({evidence.comparison})."
            )
            if statement not in basis:
                basis.append(statement)
            if len(basis) == 4:
                break
        if len(basis) == 4:
            break
    if not basis:
        basis.append("The conclusion is based on the correlated detector finding and its passive observation window.")

    limitations = [item.rstrip(". ") for alert in alerts for item in alert.limitations if item.strip()]
    uncertainty = (
        "; ".join(dict.fromkeys(limitations)) + ". "
        if limitations else ""
    ) + "Passive metadata supports a likely objective, but cannot prove the operator's identity or actual intent."

    return IncidentConclusion(
        assessment=(
            f"Passive telemetry shows {behaviours} from {alerts[0].src_ip} toward "
            f"{destination_text}. The combined pattern is consistent with suspicious "
            f"{stages} activity and warrants analyst review."
        ),
        likely_objective=objectives[0].upper() + objectives[1:] + ".",
        attack_stage=stages[0].upper() + stages[1:] + ".",
        potential_impact=impacts[0].upper() + impacts[1:] + ".",
        confidence_basis=tuple(basis),
        uncertainty=uncertainty,
    )


def alert_from_dict(record: dict) -> Alert:
    return Alert(
        alert_id=record["alert_id"],
        detector_id=record["detector_id"],
        detector_version=record["detector_version"],
        threat_type=record["threat_type"],
        subtype=record["subtype"],
        confidence=float(record["confidence"]),
        severity=record["severity"],
        window_start=float(record["window_start"]),
        window_end=float(record["window_end"]),
        src_ip=record["src_ip"],
        dst_ip=record.get("dst_ip"),
        flow_ids=tuple(record.get("flow_ids", ())),
        evidence=tuple(Evidence(**item) for item in record.get("evidence", ())),
        limitations=tuple(record.get("limitations", ())),
        analysis_provenance=dict(record.get("analysis_provenance", {})),
    )


class IncidentStore:
    def __init__(self, correlation_window_seconds: float = 900.0) -> None:
        if correlation_window_seconds <= 0:
            raise ValueError("correlation window must be positive")
        self.correlation_window_seconds = correlation_window_seconds
        self._incidents: dict[str, Incident] = {}
        self._alerts_by_incident: dict[str, list[Alert]] = {}

    def process(self, alert: Alert) -> Incident:
        incident = self._active_incident(alert)
        if incident and alert.alert_id in incident.alert_ids:
            return incident
        if incident is None:
            identity = f"{alert.src_ip}|{alert.window_start:.6f}"
            incident_id = sha256(identity.encode("utf-8")).hexdigest()[:20]
            alerts = [alert]
        else:
            incident_id = incident.incident_id
            alerts = self._alerts_by_incident[incident_id] + [alert]
        updated = self._build_incident(incident_id, alerts)
        self._incidents[incident_id] = updated
        self._alerts_by_incident[incident_id] = alerts
        return updated

    def _active_incident(self, alert: Alert) -> Incident | None:
        candidates = [
            incident for incident in self._incidents.values()
            if incident.src_ip == alert.src_ip
            and alert.window_start - incident.last_seen <= self.correlation_window_seconds
            and alert.window_end >= incident.first_seen - self.correlation_window_seconds
        ]
        return max(candidates, key=lambda item: item.last_seen) if candidates else None

    def _build_incident(self, incident_id: str, alerts: list[Alert]) -> Incident:
        threat_types = tuple(sorted({alert.threat_type for alert in alerts}))
        detector_ids = tuple(sorted({alert.detector_id for alert in alerts}))
        average_confidence = sum(alert.confidence for alert in alerts) / len(alerts)
        threat_score = sum(THREAT_WEIGHTS.get(threat, 10) for threat in threat_types)
        correlation_bonus = max(0, len(detector_ids) - 1) * 8
        confidence_component = round(average_confidence * 20)
        risk_score = min(100, threat_score + correlation_bonus + confidence_component)
        severity = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 35 else "low"
        return Incident(
            incident_id=incident_id,
            src_ip=alerts[0].src_ip,
            first_seen=min(alert.window_start for alert in alerts),
            last_seen=max(alert.window_end for alert in alerts),
            alert_ids=tuple(alert.alert_id for alert in alerts),
            detector_ids=detector_ids,
            threat_types=threat_types,
            confidence=round(average_confidence, 3),
            risk_score=risk_score,
            severity=severity,
            scoring_factors=(
                Evidence("threat_weight_total", threat_score, "policy component", "Fixed weights for distinct observed threat categories."),
                Evidence("cross_detector_bonus", correlation_bonus, "policy component", "Additional detectors strengthen a multi-stage incident story."),
                Evidence("confidence_component", confidence_component, "policy component", "Average detector confidence contributes at most 20 points."),
            ),
            conclusion=build_incident_conclusion(alerts),
        )

    def all(self) -> tuple[Incident, ...]:
        return tuple(sorted(self._incidents.values(), key=lambda item: item.first_seen))


class FeedbackStore:
    VALID_DISPOSITIONS = {"confirmed_malicious", "benign", "needs_review"}

    def __init__(self) -> None:
        self._feedback: dict[str, list[AnalystFeedback]] = {}

    def record(
        self,
        incident_id: str,
        disposition: str,
        analyst: str,
        timestamp: float,
        notes: str = "",
    ) -> AnalystFeedback:
        if disposition not in self.VALID_DISPOSITIONS:
            raise ValueError(f"invalid disposition: {disposition}")
        if not analyst.strip():
            raise ValueError("analyst is required")
        identity = f"{incident_id}|{analyst}|{timestamp:.6f}|{disposition}"
        feedback = AnalystFeedback(
            feedback_id=sha256(identity.encode("utf-8")).hexdigest()[:20],
            incident_id=incident_id,
            disposition=disposition,
            analyst=analyst.strip(),
            timestamp=timestamp,
            notes=notes.strip(),
        )
        self._feedback.setdefault(incident_id, []).append(feedback)
        return feedback

    def for_incident(self, incident_id: str) -> tuple[AnalystFeedback, ...]:
        return tuple(self._feedback.get(incident_id, ()))
