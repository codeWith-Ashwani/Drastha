import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_sprint32_sih_validation import EXPECTED_CLASSES, validate_report


class Sprint32SIHValidationTests(unittest.TestCase):
    def test_every_required_subtype_has_specific_presentation_class(self):
        self.assertEqual(8, len(EXPECTED_CLASSES))
        self.assertNotIn("denial_of_service", EXPECTED_CLASSES.values())
        self.assertNotIn("dns_threat", EXPECTED_CLASSES.values())
        self.assertNotIn("command_and_control", EXPECTED_CLASSES.values())

    def test_checked_in_audit_passes_every_gate(self):
        report = json.loads((ROOT / "output/sprint32_sih_validation_audit.json").read_text())
        self.assertTrue(report["passed"])
        self.assertTrue(all(report["gates"].values()))
        self.assertTrue(all(report["streaming_gates"].values()))
        for gates in report["http_replay_gates"].values():
            self.assertTrue(all(gates.values()), gates)
        mixed = report["http_replays"]["drastha_mixed_evaluation_v3.jsonl"]["metrics"]
        self.assertEqual((452, 8, 0, 0, 86), (
            mixed["records"], mixed["tp"], mixed["fp"], mixed["fn"], mixed["tn"]
        ))
        self.assertEqual("healthy", mixed["quality"])


if __name__ == "__main__":
    unittest.main()
