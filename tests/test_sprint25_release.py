from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_sprint25_release import audit  # noqa: E402


class Sprint25ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = audit(ROOT)

    def test_every_release_gate_passes(self):
        self.assertTrue(self.report["passed"], self.report["gates"])
        self.assertTrue(all(self.report["gates"].values()))

    def test_controlled_accuracy_and_hardening_results_are_exact(self):
        self.assertEqual(
            {"records": 153, "findings": 8, "incidents": 8, "tp": 8, "fp": 0, "fn": 0},
            self.report["verified_results"]["accuracy_replay"],
        )
        self.assertEqual(
            {"tp": 9, "fp": 0, "fn": 0, "tn": 5},
            self.report["verified_results"]["lab_hardening"],
        )

    def test_release_does_not_claim_production_readiness(self):
        self.assertFalse(self.report["production_ready"])
        self.assertIn("production accuracy", self.report["excluded_claims"])
        self.assertIn("production-approved DGA model", self.report["excluded_claims"])


if __name__ == "__main__":
    unittest.main()
