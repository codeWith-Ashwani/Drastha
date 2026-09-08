from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_sprint22_hardening import (  # noqa: E402
    EXPECTED_WITH_CONTEXT, EXPECTED_WITHOUT_CONTEXT, audit,
)


class Sprint22HardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = audit(ROOT)

    def test_context_policy_removes_only_the_three_known_false_positives(self):
        self.assertEqual(EXPECTED_WITHOUT_CONTEXT, self.report["before_context"])
        self.assertEqual(EXPECTED_WITH_CONTEXT, self.report["after_context"])

    def test_slow_http_and_all_existing_attacks_remain_detected(self):
        self.assertTrue(self.report["passed"], self.report["gates"])
        self.assertTrue(all(self.report["gates"].values()))

    def test_policy_is_checksum_pinned_and_suppression_is_auditable(self):
        self.assertEqual(64, len(self.report["policy"]["sha256"]))
        self.assertEqual(8, self.report["suppressed_records"]["benign-health-control"]["command_and_control"])
        self.assertEqual(3, self.report["suppressed_records"]["benign-backup-control"]["data_exfiltration"])
        self.assertEqual(22, self.report["suppressed_records"]["authorized-scanner-control"]["reconnaissance"])


if __name__ == "__main__":
    unittest.main()
