import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.ingestion.zeek_dns import read_dns_jsonl
from aegisflow.ingestion.zeek_jsonl import ZeekRecordError


class DNSIngestionTests(unittest.TestCase):
    def test_normalizes_dns_record(self):
        record = {
            "ts": 10.5,
            "uid": "dns-1",
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "10.0.0.53",
            "query": "Example.COM.",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
            "answers": ["192.0.2.1"],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dns.log"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            event = next(read_dns_jsonl(path))
        self.assertEqual(event.query, "example.com")
        self.assertEqual(event.answers, ("192.0.2.1",))
        self.assertEqual(event.source, "zeek:dns")

    def test_missing_query_reports_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dns.log"
            path.write_text('{"ts": 1, "uid": "x", "id.orig_h": "a", "id.resp_h": "b"}\n')
            with self.assertRaisesRegex(ZeekRecordError, "line 1.*query"):
                list(read_dns_jsonl(path))


if __name__ == "__main__":
    unittest.main()
