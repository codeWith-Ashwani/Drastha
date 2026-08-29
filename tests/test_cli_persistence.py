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

    def test_exfiltration_baseline_restores_between_cli_runs(self) -> None:
        fixture = Path(__file__).resolve().parents[1] / "examples" / "zeek_conn_exfil.jsonl"
        records = fixture.read_text(encoding="utf-8").splitlines()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.jsonl"
            suspicious = root / "suspicious.jsonl"
            database = root / "analyst.db"
            first_report = root / "first-report.json"
            second_report = root / "second-report.json"
            alerts = root / "alerts.jsonl"
            baseline.write_text("\n".join(records[:5]) + "\n", encoding="utf-8")
            suspicious.write_text("\n".join(records[5:]) + "\n", encoding="utf-8")

            first = main([
                "exfil-replay", "--input", str(baseline), "--database", str(database),
                "--report-output", str(first_report), "--reset-state",
            ])
            second = main([
                "exfil-replay", "--input", str(suspicious), "--database", str(database),
                "--output", str(alerts), "--report-output", str(second_report),
            ])

            self.assertEqual((first, second), (0, 0))
            report = json.loads(second_report.read_text(encoding="utf-8"))
            self.assertTrue(report["state_restored"])
            self.assertTrue(report["state_saved"])
            self.assertEqual(report["baseline_scope"], "persistent_repository")
            self.assertEqual(report["alerts_emitted"], 1)

    def test_correlation_merges_alerts_across_process_restarts(self) -> None:
        exfil_alert = {
            **ALERT,
            "alert_id": "alert-2",
            "detector_id": "exfiltration.outbound",
            "threat_type": "data_exfiltration",
            "subtype": "outbound_volume_anomaly",
            "window_start": 150.0,
            "window_end": 180.0,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_input = root / "first.jsonl"
            second_input = root / "second.jsonl"
            database = root / "analyst.db"
            first_input.write_text(json.dumps(ALERT) + "\n", encoding="utf-8")
            second_input.write_text(json.dumps(exfil_alert) + "\n", encoding="utf-8")

            first = main([
                "correlate-alerts", "--input", str(first_input),
                "--output", str(root / "first-incidents.jsonl"),
                "--database", str(database),
            ])
            second_report = root / "second-report.json"
            second = main([
                "correlate-alerts", "--input", str(second_input),
                "--output", str(root / "second-incidents.jsonl"),
                "--report-output", str(second_report), "--database", str(database),
            ])

            self.assertEqual((first, second), (0, 0))
            report = json.loads(second_report.read_text(encoding="utf-8"))
            self.assertTrue(report["correlation_state_restored"])
            self.assertEqual(report["restored_alerts"], 1)
            repository = IncidentRepository(database)
            incidents = repository.list_incidents()
            self.assertEqual(len(incidents), 1)
            self.assertEqual(incidents[0]["risk_score"], 100)
            self.assertEqual(len(repository.get_incident(incidents[0]["incident_id"])["alerts"]), 2)


if __name__ == "__main__":
    unittest.main()
