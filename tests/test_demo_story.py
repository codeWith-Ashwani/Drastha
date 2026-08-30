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
        self.assertEqual(len(report["stages"]), 7)
        self.assertEqual(
            [stage["name"] for stage in report["stages"]],
            [
                "Passive ingestion", "Quality validation", "C2 timing analysis",
                "Exfiltration analysis", "Incident correlation",
                "Evidence persistence", "Dashboard delivery",
            ],
        )
        self.assertEqual(report["stages"][2]["status"], "detected")
        self.assertEqual(report["stages"][3]["status"], "detected")
        self.assertEqual(report["stages"][4]["status"], "critical")
        for stage in report["stages"]:
            self.assertIn("detail", stage)
            self.assertIn("duration_ms", stage)


if __name__ == "__main__":
    unittest.main()
