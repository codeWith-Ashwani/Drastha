from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aegisflow.api_store import IncidentRepository
from aegisflow.cli import main
from test_api_store import ALERT


class CorrelationPersistenceTests(unittest.TestCase):
    def test_correlation_can_persist_without_manual_api_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alert_path = root / "alerts.jsonl"
            output_path = root / "incidents.jsonl"
            report_path = root / "report.json"
            database_path = root / "analyst.db"
            alert_path.write_text(json.dumps(ALERT) + "\n", encoding="utf-8")

            result = main([
                "correlate-alerts", "--input", str(alert_path),
                "--output", str(output_path), "--report-output", str(report_path),
                "--database", str(database_path),
            ])

            self.assertEqual(result, 0)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertTrue(report["automatic_persistence"])
            self.assertEqual(report["persisted"], {"incidents": 1, "alerts": 1, "feedback": 0})
            detail = IncidentRepository(database_path).list_incidents()
            self.assertEqual(detail[0]["alert_ids"], ["alert-1"])


if __name__ == "__main__":
    unittest.main()
