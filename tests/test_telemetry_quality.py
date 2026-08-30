from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aegisflow.ingestion.zeek_jsonl import normalize_conn_record
from aegisflow.telemetry_quality import load_jsonl_resilient


def record(timestamp: float, uid: str) -> dict:
    return {
        "ts": timestamp, "uid": uid, "id.orig_h": "10.0.0.4",
        "id.resp_h": "203.0.113.9", "id.orig_p": 50000,
        "id.resp_p": 443, "proto": "tcp",
    }


class TelemetryQualityTests(unittest.TestCase):
    def test_missing_stream_is_visible_without_crashing(self) -> None:
        events, quality = load_jsonl_resilient(
            Path("missing.jsonl"), normalize_conn_record, stream="zeek:conn"
        )
        self.assertEqual(events, [])
        self.assertEqual(quality.status, "unavailable")

    def test_bad_record_is_quarantined_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mixed.jsonl"
            lines = [json.dumps(record(float(index), f"C{index}")) for index in range(10)]
            lines.insert(4, "{bad-json")
            path.write_text("\n".join(lines), encoding="utf-8")
            events, quality = load_jsonl_resilient(
                path, normalize_conn_record, stream="zeek:conn"
            )
        self.assertEqual(len(events), 10)
        self.assertEqual(quality.status, "degraded")
        self.assertEqual(quality.records_rejected, 1)
        self.assertIn("line 5", quality.errors[0])

    def test_excessive_corruption_marks_stream_unusable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text("{}\nnot-json\n", encoding="utf-8")
            events, quality = load_jsonl_resilient(
                path, normalize_conn_record, stream="zeek:conn"
            )
        self.assertEqual(events, [])
        self.assertEqual(quality.status, "unusable")

    def test_out_of_order_timestamp_reports_backward_skew(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "skew.jsonl"
            path.write_text("\n".join([
                json.dumps(record(10.0, "C1")), json.dumps(record(7.5, "C2")),
                json.dumps(record(11.0, "C3")),
            ]), encoding="utf-8")
            events, quality = load_jsonl_resilient(
                path, normalize_conn_record, stream="zeek:conn"
            )
        self.assertEqual(len(events), 3)
        self.assertEqual(quality.status, "degraded")
        self.assertEqual(quality.out_of_order_records, 1)
        self.assertEqual(quality.maximum_backward_skew_seconds, 2.5)


if __name__ == "__main__":
    unittest.main()
