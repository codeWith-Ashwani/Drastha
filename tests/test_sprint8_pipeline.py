import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient
from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO
from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository
from aegisflow.cli import main
from aegisflow.ingestion.passive_replay import prepare_replay, event_order
from aegisflow.ingestion.zeek_jsonl import read_conn_jsonl, ZeekRecordError
from aegisflow.ingestion.zeek_encrypted import read_encrypted_jsonl
from aegisflow.ingestion.zeek_runner import ZeekRunResult
from aegisflow.replay_service import analyse_replay_file, prepare_zeek_directory
from aegisflow.streaming_demo import stream_replay
from aegisflow.upload_analysis import analyse_uploaded_replay

FIXTURE = ROOT / "examples/drastha_mixed_evaluation_v3.jsonl"


def wire(value):
    """Compare the serialized contract (Python tuples become JSON arrays)."""
    return json.loads(json.dumps(value))


class Sprint8PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.repository = IncidentRepository(self.folder / "test.db")
        self.env = patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def stream(self, content):
        return [json.loads(item.removeprefix("data: ")) for item in
                stream_replay(ROOT, self.repository, "test.json", content, profile=UPLOAD_DEMO)]

    def test_actual_http_upload_matches_stream_and_cli_file_adapter(self):
        content = FIXTURE.read_text(encoding="utf-8")
        client = TestClient(create_app(self.repository))
        response = client.post("/api/replays/analyse", json={"filename": FIXTURE.name, "content": content})
        self.assertEqual(response.status_code, 200)
        uploaded = response.json()
        streamed = self.stream(content)[-1]
        cli = analyse_replay_file(FIXTURE, self.repository, root=ROOT, profile=UPLOAD_DEMO)
        self.assertEqual(uploaded["alerts"], wire(cli["alerts"]))
        self.assertEqual(uploaded["alerts"], [f["alert"] for f in streamed["findings"]])
        self.assertEqual(uploaded["incidents"], streamed["incident_records"])
        self.assertEqual(uploaded["evaluation"], streamed["evaluation"])
        self.assertEqual(streamed["quality"]["records_accepted"], 452)
        self.assertEqual(streamed["quality"]["status"], "healthy")
        self.assertEqual(client.get(f'/api/analysis-runs/{uploaded["run_id"]}').json()["alerts"], uploaded["alerts"])
        self.assertEqual(client.get("/api/analysis-runs/missing").status_code, 404)

    def test_cli_analyse_command_matches_upload(self):
        report_path = self.folder / "report.json"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main(["analyse", "--input", str(FIXTURE), "--root", str(ROOT),
                         "--profile", "upload-demo", "--database", str(self.folder / "cli.db"),
                         "--report-output", str(report_path)])
        self.assertEqual(code, 0)
        report = json.loads(report_path.read_text())
        self.assertEqual(report["evaluation"]["true_positive"], 8)
        self.assertEqual(report["evaluation"]["false_positive"], 0)
        self.assertEqual(report["quality"]["status"], "healthy")
        reopened = IncidentRepository(self.folder / "cli.db")
        self.assertEqual(reopened.get_analysis_run(report["run_id"])["alerts"], report["alerts"])

    def test_operator_profile_is_shared_by_both_http_paths(self):
        client = TestClient(create_app(self.repository))
        with patch.dict(os.environ, {"DRASTHA_ANALYSIS_PROFILE": "deployment-baseline"}):
            upload = client.post("/api/replays/analyse", json={"filename": FIXTURE.name,
                                 "content": FIXTURE.read_text()}).json()
            stream = client.get("/api/stream/simulated?interval=0")
        started = json.loads(stream.text.splitlines()[0].removeprefix("data: "))
        self.assertEqual(upload["analysis_provenance"], started["analysis_provenance"])
        self.assertIn("uncalibrated", started["analysis_provenance"]["profile"])

    def test_invalid_operator_profile_fails_explicitly(self):
        client = TestClient(create_app(self.repository))
        with patch.dict(os.environ, {"DRASTHA_ANALYSIS_PROFILE": "unknown"}):
            self.assertEqual(client.get("/api/stream/simulated?interval=0").status_code, 422)
            self.assertEqual(client.post("/api/replays/analyse", json={"filename": FIXTURE.name,
                             "content": FIXTURE.read_text()}).status_code, 422)

    def test_quality_is_identical_before_sorting_for_stream_and_upload(self):
        records = [json.loads(line) for line in FIXTURE.read_text().splitlines()]
        records[0], records[-1] = records[-1], records[0]
        content = json.dumps(records)
        upload = analyse_uploaded_replay("out-of-order.json", content, self.repository)
        stream = self.stream(content)[-1]
        self.assertEqual(upload["quality"]["status"], "degraded")
        self.assertEqual(upload["quality"]["out_of_order_records"], stream["quality"]["out_of_order_records"])
        self.assertEqual(wire(upload["alerts"]), [f["alert"] for f in stream["findings"]])

    def test_tied_metadata_is_sorted_before_connection_without_future_lookahead(self):
        connections = list(read_conn_jsonl(ROOT / "examples/zeek_conn_beacon.jsonl"))
        metadata = list(read_encrypted_jsonl(ROOT / "examples/zeek_ssl_beacon.jsonl"))
        profile = replace(UPLOAD_DEMO, enabled=("c2",))
        ordered = sorted([*connections, *metadata], key=event_order)
        a = AnalysisSession(profile)
        with_context = a.process_many(ordered)
        self.assertTrue(any(e.name == "observed_client_fingerprints" for x in with_context for e in x.evidence))
        future = [replace(m, timestamp=connections[-1].timestamp + 100 + i) for i, m in enumerate(metadata)]
        b = AnalysisSession(profile)
        alerts = b.process_many(sorted([*connections, *future], key=event_order))
        self.assertFalse(any(e.name == "observed_client_fingerprints" for x in alerts for e in x.evidence))

    def test_wrong_endpoint_metadata_cannot_enrich_matching_uid(self):
        connections = list(read_conn_jsonl(ROOT / "examples/zeek_conn_beacon.jsonl"))
        metadata = [replace(m, src_ip="10.0.0.99") for m in
                    read_encrypted_jsonl(ROOT / "examples/zeek_ssl_beacon.jsonl")]
        session = AnalysisSession(replace(UPLOAD_DEMO, enabled=("c2",)))
        alerts = session.process_many(sorted([*connections, *metadata], key=event_order))
        self.assertFalse(any(e.name == "observed_client_fingerprints" for x in alerts for e in x.evidence))

    def test_late_event_rejected_and_finished_session_cannot_be_reused(self):
        events = list(read_conn_jsonl(ROOT / "examples/zeek_conn_scan.jsonl"))
        session = AnalysisSession(UPLOAD_DEMO)
        session.process(events[-1])
        with self.assertRaises(ValueError):
            session.process(events[0])
        result = session.findings(complete=True)
        self.assertEqual(result, session.findings(complete=True))
        with self.assertRaises(RuntimeError):
            session.process(events[-1])

    def test_metadata_only_native_record_has_no_invented_connection(self):
        record = json.loads((ROOT / "examples/zeek_ssl_beacon.jsonl").read_text().splitlines()[0])
        prepared = prepare_replay(json.dumps(record))
        self.assertEqual(len(prepared.events), 0)
        self.assertEqual(len(prepared.encrypted_events), 1)
        self.assertEqual(prepared.quality.records_accepted, 1)

    def test_failed_projection_rejects_whole_record(self):
        records = [json.loads(line) for line in FIXTURE.read_text().splitlines()[:20]]
        bad = {**records[0], "uid": "invalid-tls", "ja4": "test"}
        records.append(bad)
        with patch("aegisflow.ingestion.passive_replay.normalize_encrypted_record",
                   side_effect=ZeekRecordError("bad metadata")):
            prepared = prepare_replay(json.dumps(records))
        self.assertEqual(prepared.quality.records_rejected, 1)
        self.assertFalse(any(e.flow_id == "invalid-tls" for e in prepared.events))

    def test_explicit_missing_model_fails_instead_of_silent_fallback(self):
        with self.assertRaises(OSError):
            AnalysisSession.from_root(ROOT, UPLOAD_DEMO, model_path=self.folder / "missing.json")
        with patch.dict(os.environ, {"DRASTHA_DNS_MODEL": str(self.folder / "missing.json")}):
            with self.assertRaises(OSError):
                AnalysisSession.from_root(ROOT, UPLOAD_DEMO)

    def test_provenance_survives_repository_restart_and_export(self):
        report = analyse_uploaded_replay(FIXTURE.name, FIXTURE.read_text(), self.repository)
        reopened = IncidentRepository(self.folder / "test.db")
        client = TestClient(create_app(reopened))
        exported = client.get(f'/api/incidents/{report["incidents"][0]["incident_id"]}/export').json()
        provenance = exported["incident"]["alerts"][0]["analysis_provenance"]
        self.assertEqual(provenance, wire(report["analysis_provenance"]))

    def test_provisional_stream_is_scoped_and_final_persistence_has_no_duplicates(self):
        content = FIXTURE.read_text()
        iterator = stream_replay(ROOT, self.repository, FIXTURE.name, content, profile=UPLOAD_DEMO)
        for value in iterator:
            item = json.loads(value.removeprefix("data: "))
            if item["type"] == "alert":
                self.assertTrue(item["provisional"])
                self.assertEqual(self.repository.list_alerts(), [])
                self.assertEqual(self.repository.get_analysis_run(item["run_id"])["status"], "running")
                break
        remaining = [json.loads(value.removeprefix("data: ")) for value in iterator]
        final = remaining[-1]
        self.assertEqual(len(self.repository.list_alerts()), 8)
        self.assertEqual(self.repository.get_analysis_run(final["run_id"])["status"], "completed")
        second = self.stream(content)[-1]
        self.assertNotEqual(final["run_id"], second["run_id"])
        self.assertEqual(final["findings"], second["findings"])
        self.assertEqual(len(self.repository.list_alerts()), 8)

    def test_zeek_directory_and_pcap_adapter_dispatch_all_logs(self):
        for src, dest in (("zeek_conn_beacon.jsonl", "conn.log"),
                          ("zeek_ssl_beacon.jsonl", "ssl.log"), ("zeek_dns_threats.jsonl", "dns.log")):
            (self.folder / dest).write_text((ROOT / "examples" / src).read_text(), encoding="utf-8")
        prepared = prepare_zeek_directory(self.folder)
        self.assertEqual(prepared.quality.duplicate_uid_count, 0)
        report_path = self.folder / "report.json"
        result = ZeekRunResult(self.folder / "conn.log", self.folder, "", "")
        with patch("aegisflow.cli._build_zeek_runner") as runner, redirect_stdout(io.StringIO()):
            runner.return_value.process_pcap.return_value = result
            code = main(["pcap", "--input", "controlled.pcap", "--zeek-output", str(self.folder),
                         "--all-threats", "--profile", "upload-demo", "--root", str(ROOT),
                         "--health-output", str(report_path)])
        self.assertEqual(code, 0)
        report = json.loads(report_path.read_text())
        families = {a["threat_type"] for a in report["alerts"]}
        self.assertIn("command_and_control", families)
        self.assertIn("dns_threat", families)
        self.assertIn("encrypted_session_threat", families)

    def test_legacy_detector_selection_and_flags_remain_effective(self):
        output = self.folder / "alerts.jsonl"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main(["replay", "--input", str(ROOT / "examples/zeek_conn_scan.jsonl"),
                         "--detectors", "recon", "--port-threshold", "5", "--host-threshold", "5",
                         "--output", str(output)])
        self.assertEqual(code, 0)
        alerts = [json.loads(line) for line in output.read_text().splitlines()]
        self.assertTrue(alerts)
        self.assertTrue(all(a["threat_type"] == "reconnaissance" for a in alerts))
        self.assertEqual(alerts[0]["analysis_provenance"]["configuration"]["recon"]["unique_port_threshold"], 5)


if __name__ == "__main__":
    unittest.main()
