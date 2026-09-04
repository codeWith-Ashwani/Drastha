"""Evidence navigation must not confuse run snapshots with the global queue."""
import json
from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient
from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository

ROOT = Path(__file__).resolve().parents[1]


class ReplayEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = IncidentRepository(Path(temporary.name) / "evidence.db")
        self.client = TestClient(create_app(self.store))
        self.addCleanup(self.client.close)

    def upload(self, name, records):
        response = self.client.post("/api/replays/analyse", json={
            "filename": name, "content": json.dumps(records),
        })
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_mixed_top_is_only_exfiltration_not_the_full_replay(self):
        records = [json.loads(line) for line in (ROOT / "examples/drastha_mixed_evaluation_v3.jsonl").read_text().splitlines()]
        report = self.upload("mixed.json", records)
        self.assertEqual(len(report["incidents"]), 8)
        for incident in report["incidents"]:
            conclusion = incident["conclusion"]
            self.assertTrue(conclusion["assessment"])
            self.assertTrue(conclusion["likely_objective"])
            self.assertTrue(conclusion["confidence_basis"])
            self.assertEqual(conclusion["inference_basis"], "passive_metadata_only")
        top = self.client.get("/api/incidents/" + report["top_incident_id"]).json()
        self.assertEqual(top["threat_types"], ["data_exfiltration"])
        self.assertLess(len(top["alerts"]), len(report["alerts"]))
        saved = self.client.get("/api/analysis-runs/" + report["run_id"]).json()
        self.assertEqual(saved["alerts"], report["alerts"])

    def test_reused_source_and_start_time_does_not_mix_old_alerts_into_new_detail(self):
        base = {"ts": 2000000000, "uid": "bulk", "id.orig_h": "10.0.0.44",
                "id.resp_h": "198.51.100.88", "id.orig_p": 52000, "id.resp_p": 443,
                "proto": "tcp", "conn_state": "SF", "duration": 5,
                "orig_bytes": 100000000, "resp_bytes": 1000}
        old = self.upload("exfil.json", [base])
        self.assertEqual(old["incidents"][0]["threat_types"], ["data_exfiltration"])
        scans = [{**base, "ts": base["ts"] + i / 10, "uid": f"scan-{i}",
                  "id.resp_p": 1000 + i, "conn_state": "S0", "orig_bytes": 0,
                  "resp_bytes": 0} for i in range(25)]
        new = self.upload("scan.json", scans)
        self.assertEqual(new["incidents"][0]["threat_types"], ["reconnaissance"])
        self.assertEqual(old["top_incident_id"], new["top_incident_id"])
        detail = self.client.get("/api/incidents/" + new["top_incident_id"]).json()
        self.assertEqual({a["alert_id"] for a in detail["alerts"]}, set(detail["alert_ids"]))
        self.assertEqual({a["threat_type"] for a in detail["alerts"]}, {"reconnaissance"})
        # Historical run snapshots must remain exact even when the queue updates.
        for report in (old, new):
            saved = self.client.get("/api/analysis-runs/" + report["run_id"]).json()
            self.assertEqual(saved, report)
        self.assertTrue(any(a["threat_type"] == "data_exfiltration" for a in self.store.list_alerts()))

    def test_sequential_different_inputs_and_benign_run_keep_their_own_snapshots(self):
        reports = []
        for filename in ("zeek_conn_exfil.jsonl", "zeek_conn_scan.jsonl", "zeek_dns_threats.jsonl"):
            records = [json.loads(line) for line in (ROOT / "examples" / filename).read_text().splitlines()
                       if line.strip() and not line.lstrip().startswith("#")]
            reports.append(self.upload(filename, records))
        benign = {"ts": 2000001000, "uid": "benign", "id.orig_h": "192.0.2.201",
                  "id.resp_h": "198.51.100.201", "proto": "tcp", "id.resp_p": 443,
                  "conn_state": "SF", "orig_bytes": 1000, "resp_bytes": 1000}
        reports.append(self.upload("benign.json", [benign]))
        self.assertEqual([{a["threat_type"] for a in report["alerts"]} for report in reports], [
            {"data_exfiltration"}, {"reconnaissance"}, {"dns_threat"}, set(),
        ])
        self.assertEqual(reports[-1]["alerts"], [])
        self.assertIsNone(reports[-1]["top_incident_id"])
        self.assertEqual(len({r["run_id"] for r in reports}), 4)
        for report in reports:
            self.assertEqual(self.client.get("/api/analysis-runs/" + report["run_id"]).json(), report)


if __name__ == "__main__":
    unittest.main()
