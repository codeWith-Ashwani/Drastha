"""SIEM export must preserve scope, evidence, identity and protected access."""
from copy import deepcopy
from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient
from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository
from aegisflow.audited_store import AuditedIncidentRepository
from aegisflow.security import AccessSettings, Credential
from aegisflow.siem_export import ExportValidationError, build_siem_export, render_siem_export


def snapshot():
    return {"run_id": "run-1", "status": "completed", "quality": {"status": "healthy"},
            "alerts": [{"alert_id": "a1", "src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                        "evidence": [{"name": "test", "observed": "value", "comparison": "> 1",
                                      "explanation": "Measured input"}]}],
            "incidents": [{"incident_id": "i1", "src_ip": "192.0.2.1", "alert_ids": ["a1"],
                           "first_seen": 1, "last_seen": 2, "risk_score": 58,
                           "confidence": .9, "severity": "medium",
                           "conclusion": {"likely_objective": "Possible transfer", "uncertainty": "Metadata only"}}]}


class SiemSerializationTests(unittest.TestCase):
    def test_repeat_export_is_deterministic_and_preserves_evidence(self):
        report = snapshot()
        original = deepcopy(report)
        first = build_siem_export(report)
        self.assertEqual(first, build_siem_export(report))
        self.assertEqual(report, original)
        event = first["events"][0]
        self.assertEqual(event["incident"], report["incidents"][0])
        self.assertEqual(event["alerts"], report["alerts"])
        self.assertEqual(event["observed_end"], 2)
        self.assertEqual(event["timestamp_basis"], "source_seconds_preserved")

    def test_new_run_or_changed_snapshot_gets_different_event_identity(self):
        report = snapshot()
        first = build_siem_export(report)["events"][0]["event_id"]
        report["run_id"] = "run-2"
        self.assertNotEqual(first, build_siem_export(report)["events"][0]["event_id"])
        report["run_id"] = "run-1"
        report["alerts"][0]["evidence"][0]["observed"] = "changed"
        self.assertNotEqual(first, build_siem_export(report)["events"][0]["event_id"])

    def test_json_ndjson_roundtrip_preserves_unicode_and_newlines(self):
        report = snapshot()
        report["alerts"][0]["evidence"][0]["observed"] = 'DNS\\name\nअलर्ट\r\n{"record_type":"forged"}'
        payload = build_siem_export(report)
        document = json.loads(render_siem_export(payload, None))
        lines = render_siem_export(payload, None, "ndjson").splitlines()
        self.assertEqual(len(lines), 2)
        manifest, event = map(json.loads, lines)
        self.assertEqual(manifest["manifest"], document["manifest"])
        self.assertEqual(event["event"], document["events"][0])
        self.assertIsNone(manifest["integrity"])

    def test_bad_references_and_duplicate_ids_fail_without_partial_output(self):
        for change in ("missing", "duplicate_alert", "duplicate_incident", "orphan", "source", "repeated_link"):
            with self.subTest(change=change):
                report = snapshot()
                if change == "missing":
                    report["incidents"][0]["alert_ids"] = ["missing"]
                elif change == "duplicate_alert":
                    report["alerts"].append(deepcopy(report["alerts"][0]))
                elif change == "duplicate_incident":
                    report["incidents"].append(deepcopy(report["incidents"][0]))
                elif change == "orphan":
                    report["alerts"].append({**report["alerts"][0], "alert_id": "orphan"})
                elif change == "source":
                    report["alerts"][0]["src_ip"] = "192.0.2.2"
                else:
                    report["incidents"].append({**report["incidents"][0], "incident_id": "other"})
                with self.assertRaises(ExportValidationError):
                    build_siem_export(report)

    def test_invalid_numeric_scores_windows_and_nonfinite_evidence_fail(self):
        for field, value in (("confidence", 2), ("risk_score", -1), ("risk_score", True),
                             ("risk_score", float("nan")), ("first_seen", 9)):
            with self.subTest(field=field, value=value):
                report = snapshot()
                report["incidents"][0][field] = value
                with self.assertRaises(ExportValidationError):
                    build_siem_export(report)
        report = snapshot()
        report["alerts"][0]["evidence"][0]["observed"] = float("inf")
        with self.assertRaises(ExportValidationError):
            build_siem_export(report)

    def test_limits_reject_instead_of_truncating(self):
        for name in ("MAX_REPORT_BYTES", "MAX_EVENTS", "MAX_ALERTS"):
            with self.subTest(name=name), patch("aegisflow.siem_export." + name, 0):
                with self.assertRaises(ExportValidationError):
                    build_siem_export(snapshot())

    def test_empty_and_degraded_snapshots_retain_quality_without_invented_events(self):
        report = snapshot()
        report.update(alerts=[], incidents=[], quality={"status": "degraded", "records_rejected": 2})
        payload = build_siem_export(report)
        self.assertEqual(payload["events"], [])
        self.assertEqual(payload["manifest"]["quality"], report["quality"])
        self.assertIsNone(payload["manifest"]["overall_risk"])
        self.assertEqual(len(render_siem_export(payload, None, "ndjson").splitlines()), 1)


class SiemAPITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.store = IncidentRepository(self.directory / "analyst.db")
        self.client = TestClient(create_app(self.store, access=AccessSettings()))
        self.addCleanup(self.client.close)

    def upload(self, filename="drastha_accuracy_fp_test_v2.jsonl", client=None, headers=None):
        content = (ROOT / "examples" / filename).read_text(encoding="utf-8")
        with patch.dict("os.environ", {"DRASTHA_ROOT": str(ROOT)}):
            response = (client or self.client).post("/api/replays/analyse", headers=headers,
                                                    json={"filename": filename, "content": content})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_actual_eight_threat_upload_exports_all_evidence_and_overall_risk(self):
        run = self.upload()
        endpoint = "/api/analysis-runs/" + run["run_id"] + "/export"
        response = self.client.get(endpoint)
        self.assertEqual(response.status_code, 200, response.text)
        document = response.json()
        self.assertEqual(document["manifest"]["event_count"], 8)
        self.assertEqual(document["manifest"]["overall_risk"]["score"], 88)
        self.assertEqual(document["manifest"]["quality"]["status"], "healthy")
        self.assertEqual({a["alert_id"] for event in document["events"] for a in event["alerts"]},
                         {a["alert_id"] for a in run["alerts"]})
        self.assertTrue(all(event["incident"]["conclusion"] for event in document["events"]))
        self.assertNotIn("evaluation", document["manifest"])
        ndjson = self.client.get(endpoint + "?format=ndjson")
        self.assertEqual(ndjson.status_code, 200)
        self.assertIn("application/x-ndjson", ndjson.headers["content-type"])
        lines = [json.loads(line) for line in ndjson.text.splitlines()]
        self.assertEqual(len(lines), 9)
        self.assertEqual([line["event"] for line in lines[1:]], document["events"])
        self.assertEqual(self.client.get("/api/analysis-runs/" + run["run_id"]).json(), run)
        self.assertIn("attachment;", response.headers["content-disposition"])
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_export_uses_saved_run_after_global_incident_reviews_change(self):
        run = self.upload("judge_attack_replay.jsonl")
        endpoint = "/api/analysis-runs/" + run["run_id"] + "/export"
        before = self.client.get(endpoint).json()
        for incident in run["incidents"]:
            self.store.set_status(incident["incident_id"], "false_positive", time.time())
        after = self.client.get(endpoint).json()
        self.assertEqual(before, after)
        next_run = self.upload("judge_attack_replay.jsonl")
        next_export = self.client.get("/api/analysis-runs/" + next_run["run_id"] + "/export").json()
        self.assertNotEqual(before["events"][0]["event_id"], next_export["events"][0]["event_id"])

    def test_missing_unfinished_malformed_and_invalid_format_have_explicit_errors(self):
        self.assertEqual(self.client.get("/api/analysis-runs/missing/export").status_code, 404)
        report = snapshot()
        report["status"] = "running"
        self.store.save_analysis_run("run-1", report)
        self.assertEqual(self.client.get("/api/analysis-runs/run-1/export").status_code, 409)
        report["status"] = "completed"
        report["alerts"] = []
        self.store.save_analysis_run("run-1", report)
        self.assertEqual(self.client.get("/api/analysis-runs/run-1/export").status_code, 409)
        self.assertEqual(self.client.get("/api/analysis-runs/run-1/export?format=cef").status_code, 422)

    def test_untrusted_names_cannot_inject_download_headers(self):
        report = snapshot()
        report["run_id"] = 'run-"\r\nX-Injected: yes'
        report["filename"] = report["run_id"]
        self.store.save_analysis_run(report["run_id"], report)
        from urllib.parse import quote
        response = self.client.get("/api/analysis-runs/" + quote(report["run_id"], safe="") + "/export")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("X-Injected", response.headers)
        self.assertNotIn("Injected", response.headers["content-disposition"])

    def test_signed_authentication_receipts_and_tampering_fail_closed(self):
        key = sha256(b"public-siem-regression-key").digest()
        token = "public-siem-viewer-token-" + "x" * 40
        config = AccessSettings("required", (Credential("viewer", "viewer", sha256(token.encode()).hexdigest(),
                                                       time.time() + 3600),), ())
        store = AuditedIncidentRepository(self.directory / "signed.db", key)
        store.save_analysis_run("run-1", snapshot())
        with TestClient(create_app(store, access=config), base_url="https://testserver") as client:
            endpoint = "/api/analysis-runs/run-1/export"
            self.assertEqual(client.get(endpoint).status_code, 401)
            headers = {"Authorization": "Bearer " + token}
            first = client.get(endpoint, headers=headers)
            self.assertEqual(first.status_code, 200, first.text)
            document = first.json()
            receipt = document.pop("integrity")
            self.assertTrue(store.verify_export(document, receipt))
            lines = [json.loads(line) for line in client.get(endpoint + "?format=ndjson", headers=headers).text.splitlines()]
            reconstructed = {"manifest": lines[0]["manifest"], "events": [line["event"] for line in lines[1:]]}
            self.assertTrue(store.verify_export(reconstructed, lines[0]["integrity"]))
            self.assertEqual(document["events"], reconstructed["events"])
            document["events"][0]["risk_score"] = 0
            self.assertFalse(store.verify_export(document, receipt))
            with closing(sqlite3.connect(store.database_path)) as db:
                with db:
                    db.execute("UPDATE analysis_runs SET payload='{}'")
            self.assertEqual(client.get(endpoint, headers=headers).status_code, 503)


if __name__ == "__main__":
    unittest.main()
