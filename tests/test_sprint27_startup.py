from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_sprint27_startup import audit  # noqa: E402


class Sprint27StartupAuditTests(unittest.TestCase):
    def test_every_startup_safety_gate_passes(self):
        report = audit(ROOT)
        self.assertTrue(report["passed"], report["gates"])
        self.assertTrue(all(report["gates"].values()))
        self.assertFalse(report["production_ready"])


if __name__ == "__main__":
    unittest.main()
