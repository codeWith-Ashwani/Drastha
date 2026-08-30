from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aegisflow.demo import rehearse_demo


ROOT = Path(__file__).resolve().parents[1]


class DemoRehearsalTests(unittest.TestCase):
    def test_complete_demo_is_repeatable_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = rehearse_demo(
                ROOT, Path(directory) / "output" / "drastha-rehearsal.db",
                evaluation_iterations=1,
            )
        self.assertTrue(report["ready"])
        self.assertTrue(report["checks"]["replay_is_idempotent"])
        self.assertTrue(report["checks"]["evaluation_passed"])


if __name__ == "__main__":
    unittest.main()
