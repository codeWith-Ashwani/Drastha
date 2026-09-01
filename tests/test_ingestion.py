import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.ingestion.zeek_jsonl import ZeekRecordError, normalize_conn_record, read_conn_jsonl


class ZeekIngestionTests(unittest.TestCase):
    def test_normalizes_connection_record(self):
        event = normalize_conn_record({
            "ts": 100.25,
            "uid": "C1",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 50000,
            "id.resp_h": "10.0.0.8",
            "id.resp_p": 443,
            "proto": "TCP",
            "duration": 0.5,
            "orig_bytes": 120,
            "resp_bytes": 900,
        })
        self.assertEqual(event.flow_id, "C1")
        self.assertEqual(event.protocol, "tcp")
        self.assertEqual(event.outbound_bytes, 120)
        self.assertEqual(event.inbound_bytes, 900)
        self.assertEqual(event.source, "zeek:conn")

    def test_reports_line_number_for_missing_field(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text(json.dumps({"ts": 1.0, "uid": "C1"}) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ZeekRecordError, "line 1"):
                list(read_conn_jsonl(path))

    def test_accepts_iso_timestamp_and_infers_connection_state_from_history(self):
        event = normalize_conn_record({
            "ts": "2026-09-01T16:58:30Z",
            "uid": "C-ISO",
            "id.orig_h": "198.51.100.10",
            "id.orig_p": 40000,
            "id.resp_h": "10.0.0.20",
            "id.resp_p": 443,
            "proto": "tcp",
            "history": "S",
            "resp_bytes": 0,
        })
        self.assertGreater(event.timestamp, 0)
        self.assertEqual(event.connection_state, "S0")

    def test_scan_history_is_not_misread_as_incomplete_tcp(self):
        event = normalize_conn_record({
            "ts": 100.0,
            "uid": "C-SCAN",
            "id.orig_h": "192.0.2.10",
            "id.resp_h": "192.0.2.20",
            "id.resp_p": 22,
            "proto": "tcp",
            "history": "D",
            "resp_bytes": 0,
        })
        self.assertEqual(event.connection_state, "")


if __name__ == "__main__":
    unittest.main()
