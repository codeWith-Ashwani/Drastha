import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.analysis_session import (
    AnalysisSession, DEPLOYMENT_BASELINE, STREAM_DEMO, UPLOAD_DEMO,
)
from aegisflow.ingestion.zeek_jsonl import read_conn_jsonl
from aegisflow.ingestion.zeek_dns import normalize_dns_record, read_dns_jsonl
from aegisflow.ingestion.zeek_encrypted import read_encrypted_jsonl
from aegisflow.streaming_demo import stream_simulated_ip_traffic
from aegisflow.upload_analysis import analyse_uploaded_replay


class Repository:
    def import_records(self, incidents, alerts):
        return {"incidents": len(incidents), "alerts": len(alerts)}


class AnalysisSessionTests(unittest.TestCase):
    def test_dns_numeric_codes_and_feature_aliases_share_normalization(self):
        raw = {"ts": 1, "uid": "dns-1", "id.orig_h": "10.0.0.1",
               "id.resp_h": "10.0.0.2", "qtype": 16, "rcode": 0,
               "ml_evidence": {"query_name": "Encoded.Example.test"}}
        event = normalize_dns_record(raw)
        self.assertEqual(event.query_type, "TXT")
        self.assertEqual(event.response_code, "NOERROR")
        self.assertEqual(event.query, "encoded.example.test")
        self.assertNotIn("query", raw)
        self.assertEqual(normalize_dns_record({**raw, "qtype": "28"}).query_type, "AAAA")
        self.assertEqual(normalize_dns_record({**raw, "rcode": 3}).response_code, "NXDOMAIN")

    def test_dns_named_values_take_precedence_and_unknown_codes_survive(self):
        raw = {"ts": 1, "uid": "dns-1", "id.orig_h": "10.0.0.1",
               "id.resp_h": "10.0.0.2", "query": "example.test", "qtype": 65000}
        self.assertEqual(normalize_dns_record(raw).query_type, "65000")
        self.assertEqual(normalize_dns_record({**raw, "qtype_name": "txt"}).query_type, "TXT")

    def test_numeric_txt_upload_matches_named_txt_upload(self):
        path = ROOT / "examples/drastha_mixed_evaluation_v3.jsonl"
        records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        replacements = 0
        for record in records:
            if record.get("ml_evidence", {}).get("record_type") == "TXT":
                del record["ml_evidence"]["record_type"]
                record["qtype"] = 16
                replacements += 1
        self.assertGreater(replacements, 0)
        with patch.dict("os.environ", {"DRASTHA_ROOT": str(ROOT)}):
            original = analyse_uploaded_replay(path.name, path.read_text(), Repository())
            numeric = analyse_uploaded_replay("numeric.json", json.dumps(records), Repository())
        self.assertEqual(original["alerts"], numeric["alerts"])
        self.assertEqual(numeric["quality"]["status"], "healthy")

    def events(self):
        events = list(read_conn_jsonl(ROOT / "examples/zeek_conn_scan.jsonl"))
        events += list(read_dns_jsonl(ROOT / "examples/zeek_dns_threats.jsonl"))
        events += list(read_encrypted_jsonl(ROOT / "examples/zeek_ssl_beacon.jsonl"))
        return sorted(events, key=lambda event: event.timestamp)

    def test_incremental_and_bulk_dispatch_are_identical(self):
        bulk = AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
        incremental = AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
        expected = bulk.process_many(self.events())
        observed = [alert for event in self.events() for alert in incremental.process(event)]
        self.assertTrue(expected)
        self.assertEqual([a.to_dict() for a in expected], [a.to_dict() for a in observed])
        self.assertEqual(bulk.final_recon_snapshot(), incremental.final_recon_snapshot())

    def test_sessions_do_not_share_windows_or_cooldowns(self):
        first = AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
        second = AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
        expected = first.process_many(self.events())
        self.assertIsNot(first.recon, second.recon)
        self.assertIsNot(first.c2, second.c2)
        self.assertIsNot(first.exfiltration, second.exfiltration)
        self.assertEqual(second.final_recon_snapshot(), [])
        self.assertEqual(expected, second.process_many(self.events()))

    def test_profile_thresholds_preserve_existing_defaults(self):
        self.assertEqual(UPLOAD_DEMO.recon.unique_port_threshold, 5)
        self.assertEqual(STREAM_DEMO.recon.unique_port_threshold, 6)
        self.assertEqual(UPLOAD_DEMO.ddos.syn_attempt_threshold, 5)
        self.assertEqual(DEPLOYMENT_BASELINE.recon.unique_port_threshold, 20)
        self.assertIn("uncalibrated", DEPLOYMENT_BASELINE.name)

    def test_provenance_is_stable_and_sensitive_to_configuration(self):
        first = AnalysisSession.from_root(ROOT, UPLOAD_DEMO).provenance()
        same = AnalysisSession.from_root(ROOT, UPLOAD_DEMO).provenance()
        changed = AnalysisSession.from_root(ROOT, STREAM_DEMO).provenance()
        self.assertEqual(first, same)
        self.assertNotEqual(first["configuration_sha256"], changed["configuration_sha256"])
        self.assertEqual(len(first["detector_versions"]), 6)
        self.assertEqual(len(first["dns_model_sha256"]), 64)

    def test_missing_model_is_explicit_not_silently_reported_as_loaded(self):
        provenance = AnalysisSession(UPLOAD_DEMO).provenance()
        self.assertIsNone(provenance["dns_model_sha256"])
        self.assertIsNone(provenance["dns_model_version"])

    def test_supplied_answer_keys_do_not_change_predictions(self):
        events = self.events()
        poisoned = [replace(event, raw={**event.raw, "evaluation_label": "benign",
                    "evaluation_threat_class": "none", "label": "benign",
                    "threat_class": "none", "confidence": 0}) for event in events]
        first = AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
        second = AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
        self.assertEqual(first.process_many(events), second.process_many(poisoned))

    def test_unknown_event_is_rejected(self):
        with self.assertRaises(TypeError):
            AnalysisSession(UPLOAD_DEMO).process({"uid": "not normalized"})

    def test_upload_reports_selected_profile(self):
        path = ROOT / "examples/zeek_conn_scan.jsonl"
        with patch.dict("os.environ", {"DRASTHA_ROOT": str(ROOT)}):
            result = analyse_uploaded_replay(path.name, path.read_text(), Repository(),
                                             profile=STREAM_DEMO)
        self.assertEqual(result["analysis_provenance"]["profile"], STREAM_DEMO.name)

    def test_stream_exposes_matching_start_and_end_provenance(self):
        messages = [json.loads(item.removeprefix("data: ")) for item in
                    stream_simulated_ip_traffic(ROOT, Repository(), interval_seconds=0)]
        self.assertEqual(messages[0]["analysis_provenance"],
                         messages[-1]["analysis_provenance"])
        self.assertEqual(messages[0]["analysis_provenance"]["profile"], STREAM_DEMO.name)
        self.assertEqual(messages[-1]["processed"], 67)
        self.assertEqual(messages[-1]["alerts"], 10)
        self.assertEqual(messages[-1]["incidents"], 8)


if __name__ == "__main__":
    unittest.main()
