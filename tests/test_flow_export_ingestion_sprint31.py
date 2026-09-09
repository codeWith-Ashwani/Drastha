import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.ingestion.flow_exports import normalize_exported_flow_record
from aegisflow.ingestion.passive_replay import prepare_replay
from aegisflow.upload_analysis import analyse_uploaded_replay


class _Repository:
    def import_records(self, incidents, alerts, feedback=None):
        return {"incidents": len(incidents), "alerts": len(alerts), "feedback": 0}


class FlowExportIngestionSprint31Tests(unittest.TestCase):
    def analyse_fixture(self, name):
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            return analyse_uploaded_replay(
                name, (FIXTURES / name).read_text(encoding="utf-8"), _Repository()
            )

    def test_netflow_ipfix_and_sflow_use_actual_shared_upload_path(self):
        for filename, flow_format in (
            ("netflow_v5.jsonl", "netflow"),
            ("ipfix.jsonl", "ipfix"),
            ("sflow.jsonl", "sflow"),
        ):
            with self.subTest(filename=filename):
                report = self.analyse_fixture(filename)
                self.assertEqual("healthy", report["quality"]["status"])
                self.assertEqual(2, report["quality"]["records_accepted"])
                self.assertEqual(0, report["quality"]["records_rejected"])
                self.assertEqual({flow_format: 2}, report["telemetry"]["exported_flow_formats"])
                self.assertEqual(flow_format, report["input_schema"]["schema"])
                self.assertEqual({flow_format: 2}, report["input_schema"]["record_types"])

    def test_protocol_counters_duration_source_and_provenance_are_preserved(self):
        prepared = prepare_replay((FIXTURES / "ipfix.jsonl").read_text(), "ipfix.jsonl")
        first, second = prepared.events
        self.assertEqual("tcp", first.protocol)
        self.assertEqual(1789027210.0, first.timestamp)
        self.assertEqual(2048, first.outbound_bytes)
        self.assertEqual(4096, first.inbound_bytes)
        self.assertEqual(0.75, first.duration_seconds)
        self.assertEqual("ipfix:collector", first.source)
        self.assertEqual("udp", second.protocol)
        self.assertEqual("ipfix", first.raw["flow_export_format"])
        self.assertTrue(first.raw["_drastha_ingest"]["passive"])
        self.assertFalse(first.raw["_drastha_ingest"]["generated_flow_id"])

    def test_sflow_sampling_is_reported_but_counters_are_not_artificially_inflated(self):
        prepared = prepare_replay((FIXTURES / "sflow.jsonl").read_text(), "sflow.jsonl")
        event = prepared.events[0]
        self.assertEqual(1514, event.outbound_bytes)
        self.assertEqual(1, event.outbound_packets)
        self.assertEqual(1000, event.raw["_drastha_ingest"]["sampling_rate_observed"])

    def test_missing_exporter_uid_gets_stable_content_derived_identifier(self):
        raw = {
            "flow_format": "ipfix", "flowStartSeconds": 1789027230,
            "sourceIPv4Address": "192.0.2.60", "destinationIPv4Address": "198.51.100.60",
            "sourceTransportPort": 55000, "destinationTransportPort": 443,
            "protocolIdentifier": 6, "octetDeltaCount": 10, "packetDeltaCount": 1,
        }
        first, _ = normalize_exported_flow_record(raw)
        second, _ = normalize_exported_flow_record(dict(raw))
        self.assertEqual(first["uid"], second["uid"])
        self.assertTrue(first["uid"].startswith("ipfix-"))
        self.assertTrue(first["_drastha_ingest"]["generated_flow_id"])

    def test_duplicate_content_derived_flow_ids_degrade_quality(self):
        raw = {
            "flow_format": "netflow", "unix_secs": 1789027240,
            "srcaddr": "192.0.2.70", "dstaddr": "198.51.100.70",
            "srcport": 56000, "dstport": 443, "prot": 6, "dOctets": 10, "dPkts": 1,
        }
        prepared = prepare_replay("\n".join((json.dumps(raw), json.dumps(raw))), "dupe.jsonl")
        self.assertEqual("degraded", prepared.quality.status)
        self.assertEqual(1, prepared.quality.duplicate_uid_count)
        self.assertEqual(1, prepared.quality.exact_duplicate_count)

    def test_unknown_protocol_and_missing_timestamp_fail_with_quality_evidence(self):
        invalid = {
            "flow_format": "ipfix", "flowStartSeconds": 1,
            "sourceIPv4Address": "192.0.2.80", "destinationIPv4Address": "198.51.100.80",
            "protocolIdentifier": 255,
        }
        with self.assertRaisesRegex(ValueError, "unsupported IP protocol number 255"):
            prepare_replay(json.dumps(invalid), "bad.json")
        del invalid["flowStartSeconds"]
        invalid["protocolIdentifier"] = 6
        with self.assertRaisesRegex(ValueError, "missing required timestamp for ipfix"):
            prepare_replay(json.dumps(invalid), "bad.json")

    def test_conflicting_exporter_aliases_are_rejected(self):
        invalid = {
            "flow_format": "netflow", "unix_secs": 1789027250,
            "srcaddr": "192.0.2.90", "src_ip": "192.0.2.91",
            "dstaddr": "198.51.100.90", "prot": 6,
        }
        with self.assertRaisesRegex(ValueError, "conflicting netflow aliases.*srcaddr, src_ip"):
            prepare_replay(json.dumps(invalid), "conflict.json")

    def test_netflow_uptime_is_converted_to_flow_start_time(self):
        raw = {
            "flow_format": "netflow-v9", "unix_secs": 1789027300,
            "sys_uptime": 10000, "first": 7500, "last": 8000,
            "srcaddr": "192.0.2.100", "dstaddr": "198.51.100.100", "prot": 6,
        }
        prepared = prepare_replay(json.dumps(raw), "netflow.json")
        self.assertEqual(1789027297.5, prepared.events[0].timestamp)
        self.assertEqual(0.5, prepared.events[0].duration_seconds)


if __name__ == "__main__":
    unittest.main()
