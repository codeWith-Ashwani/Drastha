import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.incidents import FeedbackStore, IncidentStore, aggregate_incident_risk
from aegisflow.models import Alert, Evidence


def alert(identifier, threat, detector, timestamp, source="10.0.0.44", confidence=0.8,
          subtype="demo", limitations=()):
    return Alert(
        alert_id=identifier,
        detector_id=detector,
        detector_version="1",
        threat_type=threat,
        subtype=subtype,
        confidence=confidence,
        severity="medium",
        window_start=timestamp,
        window_end=timestamp + 10,
        src_ip=source,
        dst_ip="198.51.100.88",
        flow_ids=(identifier,),
        evidence=(Evidence("measured_rate", 31, "> 20", "Measured rate exceeded the configured threshold."),),
        limitations=tuple(limitations),
    )


class IncidentTests(unittest.TestCase):
    def test_aggregate_risk_anchors_on_dominant_incident_and_adds_bounded_breadth(self):
        store = IncidentStore()
        incidents = [
            store.process(alert("a1", "command_and_control", "c2.beacon", 1000, "10.0.0.1")),
            store.process(alert("a2", "data_exfiltration", "exfiltration.outbound", 1000, "10.0.0.2")),
            store.process(alert("a3", "dns_threat", "dns.analytics", 1000, "10.0.0.3")),
        ]
        result = aggregate_incident_risk(incidents)
        dominant = max(incidents, key=lambda item: item.risk_score)
        self.assertEqual(result.score, dominant.risk_score + 6 + 6)
        self.assertEqual(result.dominant_incident_id, dominant.incident_id)
        self.assertEqual(result.incident_count, 3)
        self.assertEqual(result.distinct_threat_types, 3)
        self.assertEqual(result.affected_sources, 3)
        self.assertIn("not an attack probability", result.uncertainty)

    def test_aggregate_risk_does_not_dilute_single_incident(self):
        incident = IncidentStore().process(
            alert("a1", "data_exfiltration", "exfiltration.outbound", 1000)
        )
        result = aggregate_incident_risk([incident])
        self.assertEqual(result.score, incident.risk_score)
        self.assertEqual([factor.observed for factor in result.scoring_factors], [incident.risk_score, 0, 0])

    def test_empty_aggregate_risk_is_explicitly_not_a_safety_claim(self):
        result = aggregate_incident_risk([])
        self.assertEqual((result.score, result.severity), (0, "none"))
        self.assertIn("does not prove", result.uncertainty)

    def test_cross_detector_alerts_correlate_and_raise_risk(self):
        store = IncidentStore(900)
        first = store.process(alert("a1", "command_and_control", "c2.beacon", 1000))
        second = store.process(alert("a2", "data_exfiltration", "exfiltration.outbound", 1100))
        self.assertEqual(first.incident_id, second.incident_id)
        self.assertEqual(set(second.detector_ids), {"c2.beacon", "exfiltration.outbound"})
        self.assertGreater(second.risk_score, first.risk_score)
        self.assertEqual(second.severity, "critical")
        self.assertIn("command-and-control", second.conclusion.likely_objective)
        self.assertIn("data out", second.conclusion.likely_objective)
        self.assertIn("passive metadata", second.conclusion.uncertainty.lower())

    def test_each_supported_attack_has_a_distinct_recorded_objective(self):
        scenarios = (
            ("denial_of_service", "distributed_source_syn_flood"),
            ("denial_of_service", "udp_reflection_amplification"),
            ("reconnaissance", "multi_host_port_scan"),
            ("command_and_control", "periodic_beacon"),
            ("dns_threat", "dga_like_domain"),
            ("dns_threat", "dns_tunnelling"),
            ("encrypted_session_threat", "encrypted_session_metadata_anomaly"),
            ("data_exfiltration", "outbound_volume_anomaly"),
        )
        objectives = []
        for index, (threat, subtype) in enumerate(scenarios):
            incident = IncidentStore().process(alert(
                f"a{index}", threat, f"detector.{index}", 1000 + index,
                subtype=subtype, limitations=("A legitimate service can produce a similar pattern.",),
            ))
            conclusion = incident.to_dict()["conclusion"]
            objectives.append(conclusion["likely_objective"])
            self.assertEqual(conclusion["inference_basis"], "passive_metadata_only")
            self.assertIn("actual intent", conclusion["uncertainty"])
            self.assertIn("Observed measured rate: 31", conclusion["confidence_basis"][0])
        self.assertEqual(len(set(objectives)), len(scenarios))

    def test_duplicate_alert_is_idempotent(self):
        store = IncidentStore()
        item = alert("same", "dns_threat", "dns.analytics", 1000)
        first = store.process(item)
        second = store.process(item)
        self.assertEqual(first, second)
        self.assertEqual(len(second.alert_ids), 1)

    def test_different_sources_create_different_incidents(self):
        store = IncidentStore()
        one = store.process(alert("a1", "dns_threat", "dns.analytics", 1000, "10.0.0.1"))
        two = store.process(alert("a2", "dns_threat", "dns.analytics", 1000, "10.0.0.2"))
        self.assertNotEqual(one.incident_id, two.incident_id)

    def test_feedback_is_validated_and_retained(self):
        store = FeedbackStore()
        feedback = store.record("incident-1", "confirmed_malicious", "analyst-a", 1234, "verified")
        self.assertEqual(store.for_incident("incident-1"), (feedback,))
        with self.assertRaisesRegex(ValueError, "invalid disposition"):
            store.record("incident-1", "maybe", "analyst-a", 1235)


if __name__ == "__main__":
    unittest.main()
