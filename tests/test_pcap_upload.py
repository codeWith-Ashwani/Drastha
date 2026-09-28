from __future__ import annotations

import base64
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository
from aegisflow.ingestion.zeek_runner import ZeekRunResult, ZeekUnavailableError


def empty_classic_pcap() -> bytes:
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


class _FakeRunner:
    def __init__(self, records: list[dict]):
        self.records = records
        self.capture_path: Path | None = None

    def process_pcap(self, pcap, output_directory, *, timeout_seconds=None):
        self.timeout_seconds = timeout_seconds
        self.capture_path = Path(pcap)
        self.capture_bytes = self.capture_path.read_bytes()
        output = Path(output_directory)
        output.mkdir(parents=True)
        conn_log = output / "conn.log"
        conn_log.write_text(
            "\n".join(json.dumps(record) for record in self.records) + "\n",
            encoding="utf-8",
        )
        return ZeekRunResult(
            conn_log=conn_log,
            output_directory=output,
            stdout="",
            stderr="",
            log_files=(conn_log,),
            command=("fake-zeek",),
        )


class _UnavailableRunner:
    def process_pcap(self, pcap, output_directory, *, timeout_seconds=None):
        raise ZeekUnavailableError("test Zeek is unavailable")


class PcapUploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.client = TestClient(
            create_app(IncidentRepository(Path(self.temp.name) / "pcap-upload.db"))
        )

    def tearDown(self):
        self.temp.cleanup()

    def _records(self):
        records = [
            {
                "ts": 1_700_000_000 + index / 10,
                "uid": f"pcap-scan-{index}",
                "id.orig_h": "192.0.2.10",
                "id.orig_p": 50_000 + index,
                "id.resp_h": "192.0.2.20",
                "id.resp_p": port,
                "proto": "tcp",
                "conn_state": "S0",
                "orig_bytes": 0,
                "resp_bytes": 0,
                "orig_pkts": 1,
                "resp_pkts": 0,
            }
            for index, port in enumerate((21, 22, 23, 25, 80, 443))
        ]
        # Zeek may emit completed flows in close order rather than start-time
        # order. The PCAP adapter must normalize this derived representation.
        return [records[3], records[0], records[5], records[1], records[4], records[2]]

    def test_pcap_uses_zeek_and_shared_dashboard_analysis_path(self):
        capture = empty_classic_pcap()
        runner = _FakeRunner(self._records())
        with patch("aegisflow.pcap_upload._configured_runner", return_value=runner):
            response = self.client.post(
                "/api/replays/analyse",
                json={
                    "filename": "evidence.pcap",
                    "content_base64": base64.b64encode(capture).decode("ascii"),
                },
            )
        self.assertEqual(response.status_code, 200, response.text)
        report = response.json()
        self.assertEqual(report["filename"], "evidence.pcap")
        self.assertEqual(report["file_size_bytes"], len(capture))
        self.assertEqual(report["quality"]["records_accepted"], 6)
        self.assertEqual(report["quality"]["status"], "healthy")
        self.assertEqual(report["quality"]["out_of_order_records"], 0)
        self.assertEqual(report["quality"]["source"], "evidence.pcap")
        self.assertIn("vertical_port_scan", {item["subtype"] for item in report["alerts"]})
        self.assertEqual(report["input_schema"]["source_upload"]["format"], "pcap")
        self.assertFalse(report["input_schema"]["source_upload"]["raw_capture_retained"])
        self.assertFalse(report["safety"]["payload_decryption_performed"])
        self.assertEqual(runner.capture_bytes, capture)
        self.assertEqual(runner.timeout_seconds, 30.0)
        self.assertFalse(runner.capture_path.exists())

    def test_invalid_capture_and_wrong_envelopes_fail_closed(self):
        invalid = self.client.post(
            "/api/replays/analyse",
            json={"filename": "bad.pcap", "content_base64": base64.b64encode(b"not-pcap").decode()},
        )
        self.assertEqual(invalid.status_code, 422)
        self.assertIn("classic .pcap", invalid.json()["detail"])

        text_for_pcap = self.client.post(
            "/api/replays/analyse",
            json={"filename": "bad.pcap", "content": "{}"},
        )
        self.assertEqual(text_for_pcap.status_code, 422)
        self.assertIn("binary capture content", text_for_pcap.json()["detail"])

        binary_for_json = self.client.post(
            "/api/replays/analyse",
            json={"filename": "bad.json", "content_base64": "e30="},
        )
        self.assertEqual(binary_for_json.status_code, 422)
        self.assertIn("replay text content", binary_for_json.json()["detail"])

    def test_missing_zeek_returns_actionable_upload_error(self):
        with patch("aegisflow.pcap_upload._configured_runner", return_value=_UnavailableRunner()):
            response = self.client.post(
                "/api/replays/analyse",
                json={
                    "filename": "evidence.pcap",
                    "content_base64": base64.b64encode(empty_classic_pcap()).decode("ascii"),
                },
            )
        self.assertEqual(response.status_code, 422)
        self.assertIn("could not be analysed with Zeek", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
