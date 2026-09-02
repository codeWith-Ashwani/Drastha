import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.ingestion.zeek_jsonl import _timestamp
from aegisflow.upload_analysis import analyse_uploaded_replay


FIXTURE = ROOT / "examples" / "drastha_mixed_evaluation_v3.jsonl"
REQUIRED_ZEEK_FIELDS = ("ts", "uid", "id.orig_h", "id.resp_h", "proto")
EXPECTED_SUBTYPES = {
    "distributed_source_syn_flood",
    "udp_reflection_amplification",
    "multi_host_port_scan",
    "periodic_beacon",
    "dga_like_domain",
    "dns_tunnelling",
    "encrypted_session_metadata_anomaly",
    "outbound_volume_anomaly",
}


class _Repository:
    def import_records(self, incidents, alerts, feedback=None):
        return {
            "incidents": len(incidents),
            "alerts": len(alerts),
            "feedback": len(feedback or []),
        }


class MixedEvaluationReplayTests(unittest.TestCase):
    def test_canonical_fixture_is_chronological_healthy_and_preserves_results(self):
        content = FIXTURE.read_text(encoding="utf-8")
        records = [json.loads(line) for line in content.splitlines() if line.strip()]

        self.assertEqual(len(records), 452)
        for line_number, record in enumerate(records, start=1):
            for field in REQUIRED_ZEEK_FIELDS:
                self.assertIn(field, record, f"line {line_number}: missing {field}")
                self.assertNotIn(record[field], (None, ""), f"line {line_number}: empty {field}")

        uids = [record["uid"] for record in records]
        self.assertEqual(len(uids), len(set(uids)), "fixture contains duplicate UIDs")
        labels = [record.get("evaluation_label") for record in records]
        self.assertEqual(labels.count("attack"), 91)
        self.assertEqual(labels.count("benign"), 361)
        self.assertTrue(all(record.get("evaluation_threat_class") for record in records))
        timestamps = [_timestamp(record, line_number=index) for index, record in enumerate(records, 1)]
        self.assertTrue(
            all(previous < current for previous, current in zip(timestamps, timestamps[1:])),
            "fixture timestamps must be strictly chronological",
        )

        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            report = analyse_uploaded_replay(FIXTURE.name, content, _Repository())

        quality = report["quality"]
        self.assertEqual(quality["status"], "healthy")
        self.assertEqual(quality["records_seen"], 452)
        self.assertEqual(quality["records_accepted"], 452)
        self.assertEqual(quality["records_rejected"], 0)
        self.assertEqual(quality["out_of_order_records"], 0)
        self.assertEqual(quality["maximum_backward_skew_seconds"], 0.0)

        self.assertEqual(len(report["alerts"]), 8)
        self.assertEqual(len(report["incidents"]), 8)
        self.assertEqual({alert["subtype"] for alert in report["alerts"]}, EXPECTED_SUBTYPES)

        evaluation = report["evaluation"]
        self.assertEqual(evaluation["true_positive"], 8)
        self.assertEqual(evaluation["false_positive"], 0)
        self.assertEqual(evaluation["false_negative"], 0)
        self.assertEqual(evaluation["true_negative"], 86)
        self.assertEqual(evaluation["precision"], 1.0)
        self.assertEqual(evaluation["recall"], 1.0)
        self.assertEqual(evaluation["f1_score"], 1.0)
        self.assertEqual(evaluation["false_positive_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()
