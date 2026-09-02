import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.ingestion.zeek_jsonl import ZeekRecordError, normalize_conn_record
from aegisflow.upload_analysis import analyse_uploaded_replay
from aegisflow.validate_replay import validation_summary, validate_replay_file


class _Repository:
    def import_records(self, incidents, alerts, feedback=None):
        return {"incidents": len(incidents), "alerts": len(alerts), "feedback": 0}


def connection(uid="flow-1", ts=1700000000, **overrides):
    record = {
        "ts": ts,
        "uid": uid,
        "id.orig_h": "192.0.2.1",
        "id.orig_p": 51000,
        "id.resp_h": "198.51.100.1",
        "id.resp_p": 443,
        "proto": "tcp",
    }
    record.update(overrides)
    return record


class UniversalIngestionTests(unittest.TestCase):
    def analyse(self, filename, content):
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            return analyse_uploaded_replay(filename, content, _Repository())

    def test_supported_container_and_fixture_matrix(self):
        cases = {
            "zeek_native.jsonl": ("jsonl", 2),
            "zeek_array.json": ("json_array", 1),
            "zeek_wrapped.json": ("wrapped_json", 1),
            "flow_aliases.jsonl": ("jsonl", 1),
        }
        for name, (input_format, count) in cases.items():
            with self.subTest(name=name):
                report = self.analyse(name, (FIXTURES / name).read_text(encoding="utf-8"))
                self.assertEqual(report["quality"]["status"], "healthy")
                self.assertEqual(report["quality"]["records_accepted"], count)
                self.assertEqual(report["input_schema"]["format"], input_format)

    def test_single_object_blank_lines_unknown_fields_unix_iso_and_ipv6(self):
        record = connection(
            "ipv6", "2026-09-02T08:00:00+05:30",
            **{"id.orig_h": "2001:db8::1", "id.resp_h": "2001:db8::2", "extra": 42},
        )
        report = self.analyse("single.json", "\n" + json.dumps(record) + "\n")
        self.assertEqual(report["input_schema"]["format"], "single_json_object")
        self.assertEqual(report["quality"]["records_accepted"], 1)
        self.assertEqual(normalize_conn_record(connection()).timestamp, 1700000000)

    def test_aliases_include_nested_ecs_fields(self):
        record = {
            "@timestamp": "2026-09-02T08:00:00Z",
            "flowid": "nested-1",
            "source": {"address": "2001:db8::1", "port": 1234},
            "destination": {"address": "2001:db8::2", "port": 443},
            "network": {"transport": "tcp"},
        }
        report = self.analyse("nested.json", json.dumps(record))
        aliases = {(item["source"], item["canonical"]) for item in report["input_schema"]["aliases_used"]}
        self.assertIn(("source.address", "id.orig_h"), aliases)
        self.assertEqual(report["quality"]["status"], "healthy")

    def test_conflicting_aliases_are_rejected_as_ambiguous(self):
        record = connection(src_ip="203.0.113.99")
        with self.assertRaisesRegex(ValueError, "conflicting aliases for source IP"):
            self.analyse("conflict.json", json.dumps(record))

    def test_actionable_missing_required_field_errors(self):
        cases = (
            ("ts", "missing required timestamp field.*Accepted one of: ts, timestamp, time, @timestamp"),
            ("id.orig_h", "missing required source IP.*id.orig_h, src_ip"),
            ("id.resp_h", "missing required destination IP.*id.resp_h, dst_ip"),
            ("proto", "missing required protocol.*proto, protocol"),
        )
        for field, message in cases:
            record = connection()
            del record[field]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                self.analyse("missing.json", json.dumps(record))

    def test_invalid_timestamp_ip_port_and_protocol_are_actionable(self):
        cases = (
            ({"ts": "abc"}, "invalid timestamp.*'abc'.*Unix timestamp or ISO-8601"),
            ({"id.orig_h": "999.1.1.1"}, "invalid source IP '999.1.1.1'"),
            ({"id.resp_p": 99999}, "invalid port.*99999.*0 to 65535"),
            ({"proto": "made-up"}, "unsupported protocol 'made-up'"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides), self.assertRaisesRegex(ValueError, message):
                self.analyse("invalid.json", json.dumps(connection(**overrides)))

    def test_malformed_json_reports_the_actual_line(self):
        lines = [json.dumps(connection("good-1", 1700000000)), "{broken"]
        lines.extend(
            json.dumps(connection(f"good-{index}", 1700000000 + index))
            for index in range(2, 11)
        )
        content = "\n".join(lines)
        report = self.analyse("malformed.jsonl", content)
        self.assertEqual(report["quality"]["records_accepted"], 10)
        self.assertEqual(report["quality"]["records_quarantined"], 1)
        self.assertEqual(report["quality"]["quarantined_records"][0]["line_number"], 2)
        self.assertEqual(report["quality"]["quarantined_records"][0]["error_category"], "invalid_json")

    def test_mixed_valid_invalid_is_degraded_not_silently_dropped(self):
        report = self.analyse(
            "mixed_valid_invalid.jsonl",
            (FIXTURES / "mixed_valid_invalid.jsonl").read_text(encoding="utf-8"),
        )
        self.assertEqual(report["quality"]["status"], "degraded")
        self.assertEqual(report["quality"]["records_received"], 11)
        self.assertEqual(report["quality"]["records_accepted"], 10)
        self.assertEqual(report["quality"]["records_rejected"], 1)
        self.assertEqual(report["quality"]["invalid_timestamp_count"], 1)

    def test_timestamp_ordering_regressions_and_identical_values(self):
        chronological = [connection("a", 1), connection("b", 2), connection("c", 2)]
        healthy = self.analyse("same-ts.json", "\n".join(map(json.dumps, chronological)))
        self.assertEqual(healthy["quality"]["out_of_order_records"], 0)
        self.assertEqual(healthy["quality"]["status"], "healthy")

        regressed = [connection("a", 4), connection("b", 3), connection("c", 2)]
        degraded = self.analyse("regressed.json", json.dumps(regressed))
        self.assertEqual(degraded["quality"]["out_of_order_records"], 2)
        self.assertEqual(degraded["quality"]["status"], "degraded")

    def test_exact_and_conflicting_duplicate_uids_are_reported(self):
        first = connection("same", 1)
        report = self.analyse("duplicates.json", json.dumps([
            first, dict(first), connection("same", 2, **{"id.resp_h": "198.51.100.2"}),
        ]))
        self.assertEqual(report["quality"]["duplicate_uid_count"], 2)
        self.assertEqual(report["quality"]["exact_duplicate_count"], 1)
        self.assertEqual(report["quality"]["conflicting_duplicate_uid_count"], 1)
        self.assertEqual(report["quality"]["records_rejected"], 0)
        self.assertEqual(report["quality"]["status"], "degraded")

    def test_dns_alias_record_routes_only_to_dns(self):
        record = {
            "timestamp": 1, "flow_id": "dns-1", "src_ip": "192.0.2.1",
            "dst_ip": "192.0.2.53", "protocol": "udp", "query_name": "example.test",
            "qtype": 1, "answers": ["198.51.100.8"], "rcode": 0,
        }
        report = self.analyse("dns.json", json.dumps(record))
        self.assertEqual(report["telemetry"]["dns_records"], 1)
        self.assertEqual(report["telemetry"]["connection_records"], 0)

    def test_tls_and_quic_metadata_are_passive_and_preserved(self):
        records = [
            {**connection("tls", 1), "ja3": "abc", "ja3s": "server"},
            {**connection("quic", 2, proto="quic"), "ja4": "def", "transport": "quic"},
        ]
        report = self.analyse("encrypted.json", json.dumps(records))
        self.assertEqual(report["telemetry"]["encrypted_session_records"], 2)
        self.assertNotIn("encrypted_session_metadata_anomaly", {x["subtype"] for x in report["alerts"]})

    def test_unsupported_json_structures_have_expected_formats(self):
        with self.assertRaisesRegex(ValueError, "'records' must be an array.*Expected JSONL"):
            self.analyse("bad-wrapper.json", json.dumps({"records": "wrong"}))

    def test_dataset_manifest_is_rejected_with_the_correct_upload_target(self):
        manifest = {
            "dataset": "drastha_mixed_evaluation_v3.jsonl",
            "records": 452,
            "attack_records": 91,
            "benign_records": 361,
        }
        with self.assertRaisesRegex(
            ValueError,
            "dataset manifest, not a traffic replay.*Upload 'drastha_mixed_evaluation_v3.jsonl'",
        ):
            self.analyse("manifest.json", json.dumps(manifest))

    def test_validation_cli_backend_returns_compact_quality_summary(self):
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            summary = validation_summary(validate_replay_file(FIXTURES / "flow_aliases.jsonl"))
        self.assertEqual(summary["format"], "jsonl")
        self.assertEqual(summary["quality"]["status"], "healthy")
        self.assertEqual(summary["quality"]["accepted"], 1)
        self.assertEqual(summary["quality"]["rejected"], 0)


if __name__ == "__main__":
    unittest.main()
