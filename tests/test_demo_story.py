from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aegisflow.api_store import IncidentRepository
from aegisflow.demo import run_attack_story


ROOT = Path(__file__).resolve().parents[1]


class DemoAttackStoryTests(unittest.TestCase):
    def test_story_runs_detectors_correlation_and_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = IncidentRepository(Path(directory) / "demo.db")
            report = run_attack_story(ROOT, repository)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["telemetry_status"], "healthy")
        self.assertEqual(report["loaded"]["alerts"], 2)
        self.assertEqual(report["metrics"]["critical_incidents"], 1)
        self.assertEqual(
            [stage["status"] for stage in report["stages"]],
            ["healthy", "detected", "detected", "critical"],
        )


if __name__ == "__main__":
    unittest.main()
