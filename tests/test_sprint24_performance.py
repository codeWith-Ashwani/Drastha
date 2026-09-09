from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_sprint24_performance import audit  # noqa: E402


class Sprint24PerformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = audit(ROOT)

    def test_demonstrated_mixed_protocol_target_passes_every_gate(self):
        self.assertTrue(self.report["passed"], self.report["gates"])
        self.assertEqual(50, self.report["demonstrated_target"]["records_per_second"])
        self.assertEqual(3000, self.report["demonstrated_target"]["records"])

    def test_failed_higher_rate_is_preserved_not_relabelled(self):
        failure = self.report["undemonstrated_target"]
        self.assertEqual(100, failure["records_per_second"])
        self.assertEqual(2, failure["attempts"])
        self.assertTrue(all(value > 100 for value in failure["producer_lag_max_ms"]))

    def test_protocol_counts_and_quality_are_exact(self):
        target = self.report["demonstrated_target"]
        self.assertEqual({"connection": 2400, "dns": 600, "encrypted": 300}, target["record_mix"])
        self.assertTrue(self.report["gates"]["healthy_zero_rejection"])
        self.assertTrue(self.report["gates"]["zero_final_backlog"])


if __name__ == "__main__":
    unittest.main()
