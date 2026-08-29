import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegisflow.ingestion.zeek_encrypted import (
    build_encrypted_metadata_index,
    read_encrypted_jsonl,
)


class EncryptedIngestionTests(unittest.TestCase):
    def test_reads_tls_metadata_without_payload(self):
        record = {
            "ts": 1.0,
            "uid": "tls-1",
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "192.0.2.5",
            "server_name": "Example.COM",
            "version": "TLSv13",
            "ja3": "fingerprint-a",
            "established": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ssl.log"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            event = next(read_encrypted_jsonl(path))
        self.assertEqual(event.server_name, "example.com")
        self.assertEqual(event.client_fingerprint, "fingerprint-a")
        self.assertNotIn("payload", event.raw)

    def test_rare_fingerprint_only_affects_context_score(self):
        record = {
            "ts": 1.0,
            "uid": "tls-1",
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "192.0.2.5",
            "ja3": "one-off",
            "established": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ssl.log"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            events = list(read_encrypted_jsonl(path))
        index = build_encrypted_metadata_index(events)
        self.assertGreater(index["tls-1"][1], 0)
        self.assertLessEqual(index["tls-1"][1], 1)


if __name__ == "__main__":
    unittest.main()
