import hashlib
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.upload_analysis import analyse_uploaded_replay


class _Repository:
    def import_records(self, incidents, alerts, feedback=None):
        return {"incidents": len(incidents), "alerts": len(alerts), "feedback": 0}


class Sprint31InputComplianceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(
            (ROOT / "data/manifests/sih26145-input-compliance-v1.json").read_text()
        )

    def test_manifest_pins_every_committed_artifact(self):
        for entry in self.manifest["artifacts"]:
            with self.subTest(path=entry["path"]):
                path = ROOT / entry["path"]
                self.assertTrue(path.is_file())
                self.assertEqual(entry["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_tool_derived_zeek_fixture_uses_actual_upload_path(self):
        path = ROOT / "examples/sih26145_tool_capture_zeek_v1.jsonl"
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            report = analyse_uploaded_replay(path.name, path.read_text(), _Repository())
        self.assertEqual(45, report["quality"]["records_accepted"])
        self.assertEqual(0, report["quality"]["records_rejected"])
        self.assertEqual(0, report["quality"]["out_of_order_records"])
        self.assertEqual("healthy", report["quality"]["status"])

    def test_claim_boundaries_remain_explicit(self):
        contract = self.manifest["collector_contract"]
        self.assertEqual("collector-decoded JSON records", contract["representation"])
        self.assertFalse(contract["binary_wire_decoder_claimed"])
        self.assertFalse(self.manifest["local_capture_provenance"]["committed"])


if __name__ == "__main__":
    unittest.main()
