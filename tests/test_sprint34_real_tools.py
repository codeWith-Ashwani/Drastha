import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_sprint34_real_tools import build_report


class Sprint34RealToolTests(unittest.TestCase):
    def test_committed_fixture_is_checksum_pinned(self):
        manifest = json.loads(
            (ROOT / "data/manifests/sih26145-real-tools-v1.json").read_text(encoding="utf-8")
        )
        fixture = ROOT / manifest["derived_fixture"]["path"]
        self.assertEqual(
            manifest["derived_fixture"]["sha256"],
            hashlib.sha256(fixture.read_bytes()).hexdigest(),
        )

    def test_actual_upload_path_detects_three_tools_and_not_health_control(self):
        report = build_report()
        self.assertTrue(report["passed"])
        self.assertEqual(report["quality"]["status"], "healthy")
        self.assertEqual(report["quality"]["records_accepted"], 141)
        self.assertEqual(report["quality"]["records_rejected"], 0)
        self.assertEqual(
            {item["subtype"] for item in report["detections"]},
            {"slow_http_connection_exhaustion", "periodic_beacon", "dns_tunnelling"},
        )
        self.assertTrue(report["alert_checks"]["benign_health_remains_benign"])

    def test_real_zeek_dns_uid_reuse_is_not_corruption(self):
        report = build_report()
        self.assertEqual(report["source_counts"]["zeek:sprint34:dns"], 52)
        self.assertEqual(report["quality"]["duplicate_uid_count"], 0)


if __name__ == "__main__":
    unittest.main()
