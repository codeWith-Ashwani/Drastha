import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.incidents import FeedbackStore, IncidentStore
from aegisflow.models import Alert, Evidence


def alert(identifier, threat, detector, timestamp, source="10.0.0.44", confidence=0.8):
    return Alert(
        alert_id=identifier,
        detector_id=detector,
        detector_version="1",
        threat_type=threat,
        subtype="demo",
        confidence=confidence,
        severity="medium",
        window_start=timestamp,
        window_end=timestamp + 10,
        src_ip=source,
        dst_ip="198.51.100.88",
        flow_ids=(identifier,),
        evidence=(Evidence("demo", 1, "context", "demo"),),
    )


class IncidentTests(unittest.TestCase):
    def test_cross_detector_alerts_correlate_and_raise_risk(self):
        store = IncidentStore(900)
        first = store.process(alert("a1", "command_and_control", "c2.beacon", 1000))
        second = store.process(alert("a2", "data_exfiltration", "exfiltration.outbound", 1100))
        self.assertEqual(first.incident_id, second.incident_id)
        self.assertEqual(set(second.detector_ids), {"c2.beacon", "exfiltration.outbound"})
        self.assertGreater(second.risk_score, first.risk_score)
        self.assertEqual(second.severity, "critical")

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
