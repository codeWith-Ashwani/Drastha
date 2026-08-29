from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aegisflow.api_store import IncidentRepository


INCIDENT = {
    "incident_id": "incident-1",
    "src_ip": "10.0.0.44",
    "first_seen": 100.0,
    "last_seen": 120.0,
    "alert_ids": ["alert-1"],
    "detector_ids": ["c2.beacon"],
    "threat_types": ["command_and_control"],
    "confidence": 0.88,
    "risk_score": 72,
    "severity": "high",
    "scoring_factors": [],
    "status": "open",
}
ALERT = {
    "alert_id": "alert-1",
    "detector_id": "c2.beacon",
    "detector_version": "1.0",
    "threat_type": "command_and_control",
    "subtype": "periodic_beacon",
    "confidence": 0.88,
    "severity": "high",
    "window_start": 100.0,
    "window_end": 120.0,
    "src_ip": "10.0.0.44",
    "dst_ip": "198.51.100.10",
    "flow_ids": ["f1"],
    "evidence": [],
    "limitations": [],
}


class IncidentRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = IncidentRepository(Path(self.temp.name) / "test.db")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_import_is_idempotent_and_detail_retains_alert(self) -> None:
        self.store.import_records([INCIDENT], [ALERT])
        self.store.import_records([INCIDENT], [ALERT])
        self.assertEqual(len(self.store.list_incidents()), 1)
        detail = self.store.get_incident("incident-1")
        self.assertEqual(detail["alerts"][0]["alert_id"], "alert-1")
        self.assertEqual(self.store.list_alerts(), [ALERT])

    def test_status_and_feedback_persist(self) -> None:
        self.store.import_records([INCIDENT], [ALERT])
        self.assertTrue(self.store.set_status("incident-1", "investigating", 130.0))
        record = {
            "feedback_id": "feedback-1",
            "incident_id": "incident-1",
            "disposition": "needs_review",
            "analyst": "analyst-a",
            "timestamp": 131.0,
            "notes": "Check destination ownership.",
        }
        self.store.add_feedback(record)
        detail = self.store.get_incident("incident-1")
        self.assertEqual(detail["status"], "investigating")
        self.assertEqual(detail["feedback"][0]["disposition"], "needs_review")

    def test_reimport_does_not_reset_analyst_status(self) -> None:
        self.store.import_records([INCIDENT], [ALERT])
        self.store.set_status("incident-1", "investigating", 130.0)
        self.store.import_records([INCIDENT], [ALERT])
        self.assertEqual(self.store.get_incident("incident-1")["status"], "investigating")

    def test_runtime_state_round_trip_and_delete(self) -> None:
        state = {"version": 1, "values": [10, 20, 30]}
        self.store.put_runtime_state("detector.test", state, 140.0)
        self.assertEqual(self.store.get_runtime_state("detector.test"), state)
        self.assertTrue(self.store.delete_runtime_state("detector.test"))
        self.assertIsNone(self.store.get_runtime_state("detector.test"))

    def test_queue_filters_and_metrics(self) -> None:
        self.store.import_records([INCIDENT], [ALERT])
        self.assertEqual(len(self.store.list_incidents(status="open", severity="high")), 1)
        self.assertEqual(self.store.metrics()["active_incidents"], 1)

    def test_rejects_invalid_workflow_values(self) -> None:
        self.store.import_records([INCIDENT], [ALERT])
        with self.assertRaises(ValueError):
            self.store.set_status("incident-1", "deleted", 130.0)
        with self.assertRaises(ValueError):
            self.store.add_feedback({
                "feedback_id": "feedback-2", "incident_id": "incident-1",
                "disposition": "maybe", "analyst": "a", "timestamp": 132.0,
            })


if __name__ == "__main__":
    unittest.main()
