from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch
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

    def test_demo_endpoint_runs_real_detectors_and_exposes_health_state(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with patch.dict("os.environ", {"DRASTHA_ROOT": str(root)}):
            response = self.client.post("/api/demo/run")
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["telemetry_status"], "healthy")
        self.assertEqual(report["metrics"]["critical_incidents"], 1)
        self.assertEqual(len(report["stages"]), 7)
        self.assertEqual(report["stages"][-1]["status"], "ready")
        health = self.client.get("/api/health").json()
        self.assertEqual(health["demo_run"]["status"], "completed")

    def test_judge_can_upload_and_analyse_a_replay(self) -> None:
        root = Path(__file__).resolve().parents[1]
        content = (root / "examples" / "judge_attack_replay.jsonl").read_text(encoding="utf-8")
        response = self.client.post(
            "/api/replays/analyse",
            json={"filename": "judge-attack.jsonl", "content": content},
        )
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["verdict"], "threat_detected")
        self.assertEqual(report["quality"]["status"], "healthy")
        self.assertEqual({item["threat_type"] for item in report["alerts"]}, {
            "command_and_control", "data_exfiltration",
        })
        self.assertIsNotNone(report["top_incident_id"])

    def test_upload_rejects_unusable_or_unsupported_files(self) -> None:
        unsupported = self.client.post(
            "/api/replays/analyse", json={"filename": "capture.txt", "content": "data"}
        )
        self.assertEqual(unsupported.status_code, 422)
        malformed = self.client.post(
            "/api/replays/analyse", json={"filename": "capture.jsonl", "content": "not-json"}
        )
        self.assertEqual(malformed.status_code, 422)

    def test_judge_upload_can_return_a_clear_result(self) -> None:
        root = Path(__file__).resolve().parents[1]
        benign_lines = (root / "examples" / "zeek_conn_exfil.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()[:5]
        response = self.client.post(
            "/api/replays/analyse",
            json={"filename": "ordinary-traffic.jsonl", "content": "\n".join(benign_lines)},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verdict"], "no_threat_detected")
        self.assertEqual(response.json()["alerts"], [])

    def test_sample_replay_is_downloadable(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with patch.dict("os.environ", {"DRASTHA_ROOT": str(root)}):
            response = self.client.get("/api/replays/sample")
        self.assertEqual(response.status_code, 200)
        self.assertIn("beacon-1", response.text)

    def test_simulated_stream_emits_near_real_time_labelled_intelligence(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with patch.dict("os.environ", {"DRASTHA_ROOT": str(root)}):
            response = self.client.get("/api/stream/simulated?interval=0")
        self.assertEqual(response.status_code, 200)
        messages = [
            __import__("json").loads(line.removeprefix("data: "))
            for line in response.text.splitlines()
            if line.startswith("data: ")
        ]
        self.assertEqual(messages[0]["type"], "started")
        self.assertFalse(messages[0]["return_path_required"])
        traffic = [item for item in messages if item["type"] == "traffic"]
        alerts = [item for item in messages if item["type"] == "alert"]
        self.assertEqual(len(traffic), 67)
        self.assertEqual({item["alert"]["threat_type"] for item in alerts}, {
            "dns_threat", "command_and_control", "data_exfiltration",
            "denial_of_service", "reconnaissance", "encrypted_session_threat",
        })
        ml_alerts = [item for item in alerts if item["alert"]["subtype"] == "dga_like_domain"]
        self.assertTrue(ml_alerts)
        self.assertEqual(ml_alerts[0]["detection_method"], "Character n-gram ML model")
        ddos_classes = {
            item["alert"]["subtype"]: item["alert"]["threat_class"]
            for item in alerts if item["alert"]["threat_type"] == "denial_of_service"
        }
        self.assertEqual(ddos_classes["syn_flood"], "Volumetric DDoS - SYN Flood")
        self.assertEqual(
            ddos_classes["udp_reflection_amplification"],
            "Volumetric DDoS - UDP Reflection/Amplification",
        )
        self.assertEqual(
            ddos_classes["distributed_source_syn_flood"],
            "Volumetric DDoS - Distributed-Source SYN Flood",
        )
        encrypted_classes = {
            item["alert"]["threat_class"] for item in alerts
            if item["alert"]["threat_type"] == "encrypted_session_threat"
        }
        self.assertEqual(encrypted_classes, {"Encrypted-session metadata anomaly"})
        for item in alerts:
            self.assertIn("confidence", item["alert"])
            self.assertTrue(item["alert"]["evidence"])
            self.assertEqual(item["alert"]["schema_version"], "drastha-alert-v1")
            self.assertIn("timestamp", item["alert"])
            self.assertIn("flow_identifier", item["alert"])
            self.assertIn("threat_class", item["alert"])
            self.assertTrue(item["alert"]["supporting_evidence"])
            self.assertTrue(item["detection_method"])
            self.assertIn("risk_score", item["incident"])
        self.assertEqual(messages[-1]["type"], "complete")
        self.assertTrue(messages[-1]["near_real_time"])
        self.assertTrue(messages[-1]["passive"])
        self.assertTrue(messages[-1]["bounded_latency"])
        self.assertFalse(messages[-1]["return_path_required"])
        self.assertEqual(messages[-1]["telemetry"]["dns_records"], 21)
        self.assertEqual(messages[-1]["telemetry"]["encrypted_session_records"], 8)


if __name__ == "__main__":
    unittest.main()
