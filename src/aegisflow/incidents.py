from __future__ import annotations

from hashlib import sha256

from aegisflow.models import Alert, AnalystFeedback, Evidence, Incident


THREAT_WEIGHTS = {
    "reconnaissance": 15,
    "denial_of_service": 25,
    "dns_threat": 25,
    "command_and_control": 35,
    "data_exfiltration": 40,
}


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
