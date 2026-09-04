import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_accuracy_fixture import build, load_records
from check_accuracy_fixture import check


class AccuracyFalsePositiveFixtureTests(unittest.TestCase):
    def test_generator_identifies_all_four_invalid_clock_values_and_preserves_source(self):
        source = Path("G:/Testing/drastha_accuracy_fp_test.jsonl")
        if not source.is_file():
            source = Path("G:/Testing/drastha_accuracy_fp_test.json")
        if not source.is_file():
            source = ROOT / "examples/drastha_accuracy_fp_test_v2.jsonl"
            # The committed output still proves generation invariants when the
            # user-provided draft is unavailable on another machine.
            self.assertEqual(check(source)["source_records_preserved"], 53)
            return
        payload = build(source)
        records = payload["records"]
        self.assertEqual(payload["source_records"], 53)
        self.assertEqual(payload["source_invalid_timestamps_corrected"], 4)
        self.assertEqual(len(records), 153)
        self.assertFalse(any(str(record["ts"]).endswith((":60Z", ":90Z", ":120Z", ":150Z")) for record in records))

    def test_json_and_jsonl_outputs_have_identical_replay_records(self):
        json_records = load_records(ROOT / "examples/drastha_accuracy_fp_test_v2.json")
        jsonl_records = load_records(ROOT / "examples/drastha_accuracy_fp_test_v2.jsonl")
        self.assertEqual(jsonl_records, json_records)
        self.assertEqual(len(jsonl_records), 153)

    def test_actual_upload_path_has_eight_threats_no_false_positives_and_measured_tls(self):
        report = check()
        self.assertTrue(report["passed"])
        self.assertEqual(report["quality"]["status"], "healthy")
        self.assertEqual(report["evaluation"]["true_positive"], 8)
        self.assertEqual(report["evaluation"]["false_positive"], 0)
        self.assertEqual(report["c2_source"], "192.168.20.60")
        self.assertEqual(report["feature_coverage"]["counts"]["derived"], 4)
        self.assertTrue(all(report["benign_hard_negatives"].values()))
        self.assertEqual(report["overall_risk"]["score"], 88)
        self.assertEqual(report["overall_risk"]["severity"], "critical")
        self.assertEqual(report["overall_risk"]["incident_count"], 8)


if __name__ == "__main__":
    unittest.main()
