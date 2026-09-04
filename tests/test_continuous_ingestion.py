import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO, DEPLOYMENT_BASELINE
from aegisflow.api_store import IncidentRepository
from aegisflow.continuous_ingestion import ContinuousIngestor, StreamLimits, StreamStopped
from aegisflow.cli import main
from aegisflow.upload_analysis import analyse_uploaded_replay


def connection(index, timestamp=None):
    return {"ts": 1000 + index if timestamp is None else timestamp, "uid": f"S{index}",
            "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.2",
            "id.orig_p": 40000, "id.resp_p": 100 + index, "proto": "tcp", "conn_state": "S0"}


def encode(records):
    return ("".join(json.dumps(r) + "\n" for r in records)).encode()


class ContinuousIngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "traffic.jsonl"
        self.source.write_bytes(b"")
        self.checkpoint = self.root / "journal.db"
        self.factory = lambda: AnalysisSession(UPLOAD_DEMO)

    def worker(self, **kwargs):
        return ContinuousIngestor(self.source, self.checkpoint, self.factory, **kwargs)

    def append(self, data):
        with self.source.open("ab") as stream:
            stream.write(data)

    def drain(self, worker):
        while True:
            report = worker.poll()
            if report["status"] != "following" or not report["stream"]["backlog_bytes"]:
                return report

    def test_alerts_are_emitted_before_eof_and_survive_resume(self):
        self.append(encode(connection(i) for i in range(4)))
        with self.worker() as worker:
            self.assertEqual(worker.poll()["alerts"], [])
        self.append(encode([connection(4), connection(5)]))
        with self.worker() as worker:
            self.assertEqual(worker.recovered_records, 4)
            report = worker.poll()
            self.assertTrue(any(a["threat_type"] == "reconnaissance" for a in report["alerts"]))
        with self.worker() as worker:
            replayed = worker.poll()
            self.assertEqual(replayed["alerts"], report["alerts"])
            self.assertEqual(replayed["quality"]["records_accepted"], 6)

    def test_bounded_queue_drains_without_drops(self):
        self.append(encode(connection(i) for i in range(12)))
        with self.worker(limits=StreamLimits(batch_records=2)) as worker:
            first = worker.poll()
            self.assertEqual(first["quality"]["records_accepted"], 2)
            self.assertGreater(first["stream"]["backlog_bytes"], 0)
            last = self.drain(worker)
            self.assertEqual(last["quality"]["records_accepted"], 12)
            self.assertEqual(last["stream"]["queue_high_watermark"], 2)

    def test_partial_line_is_not_committed_until_newline(self):
        raw = encode([connection(0)])
        self.append(raw[:-3])
        with self.worker() as worker:
            result = worker.poll()
            self.assertEqual(result["status"], "awaiting_partial_line")
            self.assertEqual(result["stream"]["committed_offset"], 0)
        self.append(raw[-3:])
        with self.worker() as worker:
            self.assertEqual(worker.poll()["quality"]["records_accepted"], 1)

    def test_malformed_late_duplicate_and_nonfinite_records_are_quarantined(self):
        rows = [connection(i) for i in range(30)]
        self.append(encode(rows) + b'{broken}\n' + encode([rows[-1], connection(100, 900)]) + b'{"ts":NaN}\n')
        with self.worker() as worker:
            report = worker.poll()
        q = report["quality"]
        self.assertEqual(q["records_seen"], 34)
        self.assertEqual(q["records_accepted"], 30)
        self.assertEqual(q["records_rejected"], 4)
        self.assertEqual(q["out_of_order_records"], 1)
        self.assertEqual(q["duplicate_uid_count"], 1)
        self.assertEqual(q["status"], "unusable")  # Existing >10% rejection standard.
        with self.worker() as worker:
            self.assertEqual(worker.poll()["quality"], q)
        with contextlib.closing(sqlite3.connect(self.checkpoint)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM stream_records WHERE disposition='quarantined'").fetchone()[0], 4)

    def test_degraded_quality_is_not_suppressed(self):
        self.append(encode(connection(i) for i in range(20)) + b'bad\n')
        with self.worker() as worker:
            self.assertEqual(worker.poll()["quality"]["status"], "degraded")

    def test_conflicting_uid_is_not_reprocessed(self):
        self.append(encode([connection(0), {**connection(0), "id.resp_p": 999}]))
        with self.worker() as worker:
            q = worker.poll()["quality"]
            self.assertEqual(q["conflicting_duplicate_uid_count"], 1)
            self.assertEqual(q["records_accepted"], 1)

    def test_same_uid_across_dns_and_connection_is_legitimate(self):
        dns = {**connection(0), "query": "example.org", "qtype_name": "A"}
        self.append(encode([dns, connection(0)]))
        with self.worker() as worker:
            self.assertEqual(worker.poll()["quality"]["duplicate_uid_count"], 0)

    def test_bom_comments_and_invalid_utf8(self):
        self.append(b'\xef\xbb\xbf# header\n\n' + encode([connection(0)]) + b'\xff\n')
        with self.worker() as worker:
            q = worker.poll()["quality"]
            self.assertEqual((q["records_seen"], q["records_accepted"], q["records_rejected"]), (2, 1, 1))

    def test_containers_and_invalid_timestamp_are_not_silently_accepted(self):
        self.append(encode([{"records": [connection(0)]}, {**connection(1), "ts": "invalid"}]))
        with self.worker() as worker:
            q = worker.poll()["quality"]
            self.assertEqual(q["records_rejected"], 2)
            self.assertEqual(q["invalid_timestamp_count"], 1)

    def test_capacity_stops_without_dropping_remaining_lines(self):
        raw = encode(connection(i) for i in range(5))
        self.append(raw)
        limits = StreamLimits(max_journal_records=3)
        with self.worker(limits=limits) as worker:
            report = worker.poll()
            self.assertEqual(report["status"], "capacity_reached")
            self.assertEqual(report["quality"]["records_accepted"], 3)
            self.assertGreater(report["stream"]["backlog_bytes"], 0)
        self.assertEqual(self.source.read_bytes(), raw)
        with self.worker(limits=limits) as worker:
            self.assertEqual(worker.poll()["stream"]["committed_lines"], 3)

    def test_byte_budget_and_oversized_lines_do_not_advance_checkpoint(self):
        raw = encode([connection(0)])
        self.append(raw)
        with self.worker(limits=StreamLimits(max_journal_bytes=len(raw) - 1)) as worker:
            result = worker.poll()
            self.assertEqual(result["status"], "capacity_reached")
            self.assertEqual(result["stream"]["committed_offset"], 0)
        other = self.root / "short-lines.db"
        with ContinuousIngestor(self.source, other, self.factory, limits=StreamLimits(max_line_bytes=20)) as worker:
            with self.assertRaisesRegex(StreamStopped, "Line exceeds"):
                worker.poll()

    def test_source_truncation_and_same_size_edit_fail_closed(self):
        self.append(encode([connection(0)]))
        original = self.source.read_bytes()
        with self.worker() as worker:
            worker.poll()
            self.source.write_bytes(b"")
            with self.assertRaisesRegex(StreamStopped, "truncated"):
                worker.poll()
        self.source.write_bytes(original.replace(b'S0', b'X0', 1))
        with self.assertRaisesRegex(StreamStopped, "prefix changed"):
            self.worker()

    def test_rotation_and_provenance_change_fail_closed(self):
        self.append(encode([connection(0)]))
        with self.worker() as worker:
            worker.poll()
        with self.assertRaisesRegex(StreamStopped, "profile"):
            ContinuousIngestor(self.source, self.checkpoint, lambda: AnalysisSession(DEPLOYMENT_BASELINE))
        self.source.rename(self.root / "old.jsonl")
        self.source.write_bytes((self.root / "old.jsonl").read_bytes())
        with self.assertRaisesRegex(StreamStopped, "source"):
            self.worker()

    def test_single_writer_lock_and_release(self):
        with self.worker():
            with self.assertRaisesRegex(StreamStopped, "Another worker"):
                self.worker()
        with self.worker() as worker:
            worker.poll()

    def test_failure_mid_batch_rolls_back_and_requires_recovery(self):
        self.append(encode(connection(i) for i in range(8)))
        with self.worker() as worker:
            original = worker._consume
            def fail(raw, line):
                if line == 4:
                    raise RuntimeError("injected inference failure")
                return original(raw, line)
            with patch.object(worker, "_consume", side_effect=fail):
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    worker.poll()
            with self.assertRaises(StreamStopped):
                worker.poll()
        with self.worker() as worker:
            self.assertEqual(worker.recovered_records, 0)
            self.assertEqual(worker.poll()["quality"]["records_accepted"], 8)

    def test_projection_failure_recovers_without_duplicate_alerts(self):
        repository = IncidentRepository(self.root / "analyst.db")
        self.append(encode(connection(i) for i in range(8)))
        with self.worker(repository=repository) as worker:
            with patch.object(repository, "_save_analysis_run", side_effect=OSError("disk unavailable")):
                with self.assertRaises(OSError):
                    worker.poll()
        # Atomic projection rolls back incident/alert upserts together with the
        # failed report write; the committed journal remains the recovery source.
        self.assertEqual(repository.list_incidents(), [])
        with self.worker(repository=repository) as worker:
            report = worker.poll()
            self.assertEqual(worker.recovered_records, 8)
            self.assertEqual(len(repository.list_incidents()), len(report["incidents"]))
            self.assertEqual(repository.get_analysis_run(report["run_id"])["stream"]["committed_lines"], 8)

    def test_source_paths_and_hardlinks_cannot_be_written(self):
        self.append(encode([connection(0)]))
        with self.assertRaises(ValueError):
            ContinuousIngestor(self.source, self.source, self.factory)
        alias = self.root / "alias.db"
        os.link(self.source, alias)
        with self.assertRaises(ValueError):
            ContinuousIngestor(self.source, alias, self.factory)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["follow", "--input", str(self.source), "--checkpoint", str(self.checkpoint),
                                   "--database", str(self.source), "--once"]), 2)
        self.assertEqual(self.source.read_bytes(), encode([connection(0)]))

    def test_journal_corruption_fails_closed(self):
        self.append(encode([connection(0)]))
        with self.worker() as worker:
            worker.poll()
        with contextlib.closing(sqlite3.connect(self.checkpoint)) as db:
            with db:
                db.execute("UPDATE stream_records SET raw=?", (b'{}\n',))
        with self.assertRaisesRegex(StreamStopped, "continuity"):
            self.worker()

    def test_cli_once_resume_and_capacity_exit_codes(self):
        self.append(encode(connection(i) for i in range(4)))
        command = ["follow", "--input", str(self.source), "--checkpoint", str(self.checkpoint),
                   "--profile", "upload-demo", "--root", str(ROOT), "--once", "--batch-records", "2"]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(command), 0)
        self.assertEqual(json.loads(output.getvalue().splitlines()[-1])["quality"]["records_accepted"], 4)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(command), 0)
        with contextlib.redirect_stdout(io.StringIO()):
            code = main([*command[:4], str(self.root / "capped.db"), *command[5:], "--max-journal-records", "2"])
        self.assertEqual(code, 2)

    def test_invalid_limits_are_rejected(self):
        for values in ({"batch_records": 0}, {"batch_records": 4097}, {"max_line_bytes": -1}, {"max_journal_records": True}):
            with self.assertRaises(ValueError):
                StreamLimits(**values)

    def test_abrupt_process_exit_rolls_back_and_releases_writer_lock(self):
        self.append(encode(connection(i) for i in range(8)))
        code = """
import os, sys
from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO
from aegisflow.continuous_ingestion import ContinuousIngestor
worker = ContinuousIngestor(sys.argv[1], sys.argv[2], lambda: AnalysisSession(UPLOAD_DEMO))
original = worker._consume
def crash(raw, line):
    if line == 4:
        os._exit(73)
    return original(raw, line)
worker._consume = crash
worker.poll()
"""
        result = subprocess.run([sys.executable, "-c", code, str(self.source), str(self.checkpoint)],
                                cwd=ROOT, capture_output=True, timeout=20,
                                env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
        self.assertEqual(result.returncode, 73, result.stderr.decode())
        with self.worker() as worker:
            self.assertEqual(worker.recovered_records, 0)
            self.assertEqual(worker.poll()["quality"]["records_accepted"], 8)

    def test_projection_backpressure_does_not_consume_appended_records(self):
        repository = IncidentRepository(self.root / "backpressure.db")
        self.append(encode([connection(0)]))
        with self.worker(repository=repository) as worker:
            worker.poll()
            self.append(encode([connection(1)]))
            with patch.object(repository, "project_analysis_run", side_effect=OSError("unavailable")):
                with self.assertRaises(OSError):
                    worker.poll()
        with self.worker(repository=repository) as worker:
            self.assertEqual(worker.recovered_records, 1)
            self.assertEqual(worker.poll()["quality"]["records_accepted"], 2)

    def test_analyst_review_survives_republication(self):
        repository = IncidentRepository(self.root / "reviews.db")
        self.append(encode(connection(i) for i in range(8)))
        with self.worker(repository=repository) as worker:
            report = worker.poll()
            incident = report["incidents"][0]["incident_id"]
            repository.set_status(incident, "investigating", 1234)
            worker.poll()
        with self.worker(repository=repository) as worker:
            worker.poll()
            self.assertEqual(repository.get_incident(incident)["status"], "investigating")

    def test_mixed_fixture_restart_matches_actual_upload_and_api(self):
        from fastapi.testclient import TestClient
        from aegisflow.api import create_app
        fixture = ROOT / "examples/drastha_mixed_evaluation_v3.jsonl"
        raw = fixture.read_bytes()
        lines = raw.splitlines(keepends=True)
        self.factory = lambda: AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
        repository = IncidentRepository(self.root / "mixed.db")
        limits = StreamLimits(batch_records=17)
        self.append(b"".join(lines[:47]))
        with self.worker(limits=limits, repository=repository) as worker:
            self.drain(worker)
        self.append(b"".join(lines[47:]))
        with self.worker(limits=limits, repository=repository) as worker:
            report = self.drain(worker)
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            upload = analyse_uploaded_replay(fixture.name, raw.decode(), IncidentRepository(self.root / "upload.db"))
        self.assertEqual(report["quality"]["records_accepted"], 452)
        self.assertEqual(report["quality"]["status"], "healthy")
        self.assertEqual(len(report["alerts"]), 8)
        self.assertEqual(len(report["incidents"]), 8)
        self.assertEqual({a["subtype"] for a in report["alerts"]}, {a["subtype"] for a in upload["alerts"]})
        from aegisflow.evaluation_scoring import score_ground_truth
        from aegisflow.incidents import alert_from_dict
        score = score_ground_truth([json.loads(line) for line in lines], [alert_from_dict(a) for a in report["alerts"]])
        self.assertEqual((score["true_positive"], score["false_positive"], score["false_negative"], score["true_negative"]), (8, 0, 0, 86))
        with TestClient(create_app(repository)) as client:
            result = client.get("/api/analysis-runs/" + report["run_id"])
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json()["stream"]["committed_lines"], 452)
            self.assertEqual(len(client.get("/api/incidents").json()), 8)
