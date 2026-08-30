from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegisflow.demo import demo_preflight, prepare_demo
from test_api_store import ALERT, INCIDENT


class DemoReliabilityTests(unittest.TestCase):
    def build_demo_root(self, root: Path) -> None:
        output = root / "output"
        frontend = root / "web" / "dist"
        output.mkdir(parents=True)
        frontend.mkdir(parents=True)
        (frontend / "index.html").write_text("<html>Drastha</html>", encoding="utf-8")
        (output / "sprint4_incidents.jsonl").write_text(
            json.dumps(INCIDENT) + "\n", encoding="utf-8"
        )
        (output / "sprint3_c2_alerts.jsonl").write_text(
            json.dumps(ALERT) + "\n", encoding="utf-8"
        )
        (output / "sprint4_exfil_alerts.jsonl").write_text(
            json.dumps({**ALERT, "alert_id": "alert-2"}) + "\n", encoding="utf-8"
        )
        (output / "sprint4_feedback.json").write_text(json.dumps({
            "feedback_id": "feedback-demo",
            "incident_id": INCIDENT["incident_id"],
            "disposition": "needs_review",
            "analyst": "demo-analyst",
            "timestamp": 130.0,
            "notes": "Demo fixture",
        }), encoding="utf-8")

    def test_preflight_distinguishes_required_and_optional_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.build_demo_root(root)
            with patch("aegisflow.demo.shutil.which", return_value=None):
                report = demo_preflight(root)
            self.assertTrue(report["ready"])
            self.assertEqual(report["required_passed"], report["required_total"])
            docker = next(item for item in report["checks"] if item["name"] == "docker_cli")
            self.assertFalse(docker["required"])
            self.assertFalse(docker["passed"])

    def test_preflight_fails_when_frontend_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.build_demo_root(root)
            (root / "web" / "dist" / "index.html").unlink()
            self.assertFalse(demo_preflight(root)["ready"])

    def test_prepare_creates_repeatable_demo_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.build_demo_root(root)
            database = Path("output/drastha-demo.db")
            first = prepare_demo(root, database, fresh=True)
            second = prepare_demo(root, database, fresh=True)
            self.assertEqual(first["loaded"]["incidents"], 1)
            self.assertEqual(second["metrics"]["total_incidents"], 1)
            self.assertEqual(second["metrics"]["feedback_records"], 1)

    def test_fresh_reset_rejects_database_outside_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.build_demo_root(root)
            unsafe = root / "elsewhere.db"
            unsafe.write_text("do not delete", encoding="utf-8")
            with self.assertRaises(ValueError):
                prepare_demo(root, unsafe, fresh=True)
            self.assertEqual(unsafe.read_text(encoding="utf-8"), "do not delete")


if __name__ == "__main__":
    unittest.main()
