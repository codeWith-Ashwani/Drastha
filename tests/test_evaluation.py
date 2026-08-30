from __future__ import annotations

import unittest
from pathlib import Path

from aegisflow.evaluation import evaluate_demo


ROOT = Path(__file__).resolve().parents[1]


class DemoEvaluationTests(unittest.TestCase):
    def test_every_threat_family_is_reported_separately(self) -> None:
        report = evaluate_demo(ROOT, iterations=1)
        self.assertTrue(report["all_scenarios_passed"])
        self.assertEqual(len(report["scenarios"]), 5)
        self.assertEqual(
            {item["threat_family"] for item in report["scenarios"]},
            {
                "reconnaissance",
                "denial_of_service",
                "dns_threats",
                "command_and_control",
                "data_exfiltration",
            },
        )

    def test_report_does_not_present_fixture_checks_as_accuracy(self) -> None:
        report = evaluate_demo(ROOT, iterations=1)
        self.assertEqual(report["evaluation_scope"], "synthetic_scenario_validation")
        self.assertIn("not production accuracy", report["quality_claim"])
        for scenario in report["scenarios"]:
            self.assertGreater(scenario["benchmark"]["median_events_per_second"], 0)

    def test_iterations_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            evaluate_demo(ROOT, iterations=0)


if __name__ == "__main__":
    unittest.main()
