from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository
from test_api_store import ALERT, INCIDENT


class AnalystAPITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = IncidentRepository(Path(self.temp.name) / "api.db")
        self.store.import_records([INCIDENT], [ALERT])
        self.client = TestClient(create_app(self.store))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_health_and_queue(self) -> None:
        self.assertFalse(self.client.get("/api/health").json()["return_path_required"])
        queue = self.client.get("/api/incidents?status=open").json()
        self.assertEqual(queue[0]["incident_id"], "incident-1")

    def test_detail_review_and_export_workflow(self) -> None:
        detail = self.client.get("/api/incidents/incident-1")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["alerts"][0]["alert_id"], "alert-1")
        status = self.client.patch(
            "/api/incidents/incident-1/status", json={"status": "investigating"}
        )
        self.assertEqual(status.status_code, 200)
        review = self.client.post(
            "/api/incidents/incident-1/feedback",
            json={"disposition": "confirmed_malicious", "analyst": "qa", "notes": "verified"},
        )
        self.assertEqual(review.status_code, 201)
        exported = self.client.get("/api/incidents/incident-1/export").json()
        self.assertEqual(exported["format"], "drastha-incident-v1")
        self.assertEqual(exported["incident"]["status"], "investigating")

    def test_invalid_status_and_missing_incident_are_visible(self) -> None:
        response = self.client.patch(
            "/api/incidents/incident-1/status", json={"status": "hidden"}
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.client.get("/api/incidents/missing").status_code, 404)


if __name__ == "__main__":
    unittest.main()
