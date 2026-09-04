import contextlib
import copy
from hashlib import sha256
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
from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO
from aegisflow.api_store import IncidentRepository
from aegisflow.audited_store import AuditedIncidentRepository, EvidenceIntegrityError
from aegisflow.continuous_ingestion import ContinuousIngestor, StreamStopped, StreamLimits
from aegisflow.ingestion.passive_replay import prepare_replay, prepare_stream_record, ReplayQualityError
from aegisflow.operations import verify_database

KEY = sha256(b"public-sprint16-test-key").digest()


def conn(i):
    return {"ts": 1000 + i / 10, "uid": f"S{i}", "proto": "tcp", "conn_state": "S0",
            "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",
            "id.orig_p": 40000 + i, "id.resp_p": 1000 + i}


class ScalingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.jsonl"
        self.source.write_text("".join(json.dumps(conn(i)) + "\n" for i in range(8)), encoding="utf-8")
        self.db = self.root / "analyst.db"
        self.repo = AuditedIncidentRepository(self.db, KEY)
        self.factory = lambda: AnalysisSession(UPLOAD_DEMO)
        with ContinuousIngestor(self.source, self.root / "fixture-journal.db", self.factory) as worker:
            self.report = worker.poll()

    def test_projection_uses_one_verified_transaction_and_one_audit_event(self):
        head = self.repo.verify_evidence()["head"]
        with patch.object(self.repo, "_verify", wraps=self.repo._verify) as verify:
            self.repo.project_analysis_run(self.report)
        self.assertEqual(verify.call_count, 1)
        after = verify_database(self.db, KEY)
        self.assertEqual(after["head"]["sequence"], head["sequence"] + 1)
        self.assertEqual(after["rows"]["incidents"], 1)
        self.assertEqual(after["rows"]["analysis_runs"], 1)
        self.assertEqual(self.repo.get_analysis_run(self.report["run_id"]), json.loads(json.dumps(self.report)))

    def test_signed_and_unsigned_projection_equal_legacy_result(self):
        legacy = IncidentRepository(self.root / "legacy.db")
        unsigned = IncidentRepository(self.root / "unsigned.db")
        legacy.import_records(self.report["incidents"], self.report["alerts"])
        legacy.save_analysis_run(self.report["run_id"], self.report)
        for repo in (unsigned, self.repo):
            repo.project_analysis_run(self.report)
            self.assertEqual(repo.list_incidents(), legacy.list_incidents())
            self.assertEqual(repo.list_alerts(), legacy.list_alerts())
            self.assertEqual(repo.get_analysis_run(self.report["run_id"]), legacy.get_analysis_run(self.report["run_id"]))

    def test_failure_after_evidence_upserts_rolls_back_everything(self):
        head = self.repo.verify_evidence()["head"]
        with patch.object(self.repo, "_save_analysis_run", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                self.repo.project_analysis_run(self.report)
        self.assertEqual(verify_database(self.db, KEY)["head"], head)
        self.assertEqual(self.repo.list_incidents(), [])
        self.assertEqual(self.repo.list_alerts(), [])
        self.assertIsNone(self.repo.get_analysis_run(self.report["run_id"]))

    def test_signing_failure_rolls_back_report_and_evidence(self):
        head = self.repo.verify_evidence()["head"]
        with patch.object(self.repo, "_append", side_effect=OSError("signing storage failed")):
            with self.assertRaises(OSError):
                self.repo.project_analysis_run(self.report)
        self.assertEqual(verify_database(self.db, KEY)["head"], head)
        self.assertEqual(self.repo.list_alerts(), [])

    def test_readers_do_not_observe_partial_projection(self):
        original = self.repo._save_analysis_run
        def inspect(connection, run_id, report):
            with contextlib.closing(sqlite3.connect(self.db)) as reader:
                self.assertEqual(reader.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 0)
                self.assertEqual(reader.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0], 0)
            return original(connection, run_id, report)
        with patch.object(self.repo, "_save_analysis_run", side_effect=inspect):
            self.repo.project_analysis_run(self.report)
        self.assertEqual(len(self.repo.list_incidents()), 1)

    def test_duplicate_publication_still_verifies_and_does_not_append_audit(self):
        self.repo.project_analysis_run(self.report)
        before = self.repo.verify_evidence()["head"]
        with patch.object(self.repo, "_verify", wraps=self.repo._verify) as verify:
            self.repo.project_analysis_run(self.report)
            self.repo.project_analysis_run(self.report)
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(self.repo.verify_evidence()["head"], before)

    def test_old_audit_link_tampering_is_detected_on_duplicate_publication(self):
        self.repo.project_analysis_run(self.report)
        with contextlib.closing(sqlite3.connect(self.db)) as db, db:
            db.execute("UPDATE evidence_audit SET mac=? WHERE sequence=1", ("0" * 64,))
        with self.assertRaises(EvidenceIntegrityError):
            self.repo.project_analysis_run(self.report)

    def test_current_state_tampering_cannot_be_repaired_and_resigned(self):
        self.repo.project_analysis_run(self.report)
        with contextlib.closing(sqlite3.connect(self.db)) as db, db:
            db.execute("DELETE FROM alerts")
        with self.assertRaises(EvidenceIntegrityError):
            self.repo.project_analysis_run(self.report)

    def test_analyst_status_feedback_and_hold_survive_projection(self):
        self.repo.project_analysis_run(self.report)
        identity = self.report["incidents"][0]["incident_id"]
        self.repo.set_status(identity, "investigating", 2000)
        self.repo.add_feedback({"feedback_id": "review", "incident_id": identity, "analyst": "tester",
                                "timestamp": 2000, "disposition": "needs_review", "notes": "preserve"})
        self.repo.set_retention_hold(self.report["run_id"], True)
        self.repo.project_analysis_run(self.report)
        detail = self.repo.get_incident(identity)
        self.assertEqual(detail["status"], "investigating")
        self.assertEqual(detail["feedback"][0]["notes"], "preserve")
        with self.repo._connect() as db:
            self.assertEqual(db.execute("SELECT held FROM evidence_retention").fetchone()[0], 1)

    def test_worker_keeps_backpressure_verification_before_consumption(self):
        journal = self.root / "worker.db"
        with ContinuousIngestor(self.source, journal, self.factory, repository=self.repo) as worker:
            worker.poll()
            with self.source.open("a") as source:
                source.write(json.dumps(conn(8)) + "\n")
            with contextlib.closing(sqlite3.connect(self.db)) as db, db:
                db.execute("DELETE FROM alerts")
            with self.assertRaises(EvidenceIntegrityError):
                worker.poll()
        with contextlib.closing(sqlite3.connect(journal)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM stream_records").fetchone()[0], 8)

    def test_full_source_prefix_check_still_runs_on_idle_poll(self):
        with ContinuousIngestor(self.source, self.root / "worker.db", self.factory, repository=self.repo) as worker:
            worker.poll()
            self.source.write_bytes(self.source.read_bytes().replace(b"S0", b"SF", 1))
            with self.assertRaisesRegex(StreamStopped, "prefix changed"):
                worker.poll()

    def test_abrupt_exit_during_atomic_projection_leaves_no_partial_analyst_state(self):
        code = '''
import json, os, sys
from aegisflow.audited_store import AuditedIncidentRepository
repo = AuditedIncidentRepository(sys.argv[1], bytes.fromhex(sys.argv[2]))
repo._save_analysis_run = lambda *args: os._exit(74)
repo.project_analysis_run(json.loads(sys.argv[3]))
'''
        result = subprocess.run([sys.executable, "-c", code, str(self.db), KEY.hex(), json.dumps(self.report)],
            cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")}, timeout=20, capture_output=True)
        self.assertEqual(result.returncode, 74, result.stderr)
        self.assertEqual(verify_database(self.db, KEY)["rows"]["incidents"], 0)
        self.repo.project_analysis_run(self.report)
        self.assertEqual(len(self.repo.list_alerts()), 1)

    def test_stream_preparation_matches_upload_normalizers_for_all_452_records(self):
        records = [json.loads(line) for line in (ROOT / "examples/drastha_mixed_evaluation_v3.jsonl").read_text().splitlines()]
        for record in records:
            original = copy.deepcopy(record)
            old = prepare_replay(json.dumps(record), "source.jsonl", maximum_records=1)
            new = prepare_stream_record(record, "source.jsonl")
            self.assertEqual(new.ordered_events(), old.ordered_events())
            self.assertEqual(new.accepted_records, old.accepted_records)
            self.assertEqual(new.quality.to_dict(), old.quality.to_dict())
            self.assertEqual(record, original)

    def test_stream_and_upload_rejections_match(self):
        for changes in ({"ts": "invalid"}, {"id.orig_h": "not-an-ip"}, {"id.resp_p": 70000}, {"proto": "bad"}):
            record = {**conn(0), **changes}
            with self.assertRaises(ReplayQualityError) as old:
                prepare_replay(json.dumps(record), "source.jsonl", maximum_records=1)
            with self.assertRaises(ReplayQualityError) as new:
                prepare_stream_record(record, "source.jsonl")
            self.assertEqual(new.exception.quality.to_dict(), old.exception.quality.to_dict())
            self.assertEqual(str(new.exception), str(old.exception))

    def test_nonfinite_values_in_unused_metadata_remain_rejected(self):
        for value in (float("inf"), float("nan"), -float("inf")):
            with self.assertRaises(ValueError):
                prepare_stream_record({**conn(0), "unused": {"values": [value]}}, "source.jsonl")
        with self.source.open("a") as source:
            source.write(json.dumps({**conn(8), "unused": "OVERFLOW"}).replace('"OVERFLOW"', '1e999') + "\n")
        with ContinuousIngestor(self.source, self.root / "overflow.db", self.factory) as worker:
            result = worker.poll()
        self.assertEqual(result["quality"]["records_rejected"], 1)

    def test_stream_containers_still_fail(self):
        for value in ([conn(0)], {"records": [conn(0)]}):
            with self.assertRaises(ValueError):
                prepare_stream_record(value, "source.jsonl")

    def test_engine_mismatch_still_requires_explicit_migration(self):
        journal = self.root / "worker.db"
        with patch("aegisflow.continuous_ingestion._engine_digest", return_value="old-engine"):
            with ContinuousIngestor(self.source, journal, self.factory) as worker:
                worker.poll()
        with self.assertRaisesRegex(StreamStopped, "engine"):
            ContinuousIngestor(self.source, journal, self.factory)

    def test_legacy_repository_compatibility_is_retained(self):
        class Legacy:
            def __init__(self): self.calls = []
            def import_records(self, incidents, alerts): self.calls.append("import")
            def save_analysis_run(self, run_id, report): self.calls.append("report")
        legacy = Legacy()
        with ContinuousIngestor(self.source, self.root / "legacy-journal.db", self.factory, repository=legacy) as worker:
            worker.poll()
        self.assertEqual(legacy.calls, ["import", "report"])

    def test_explicit_batch256_remains_bounded_and_recovers_without_lost_records(self):
        self.source.write_text("".join(json.dumps(conn(i)) + "\n" for i in range(300)), encoding="utf-8")
        journal = self.root / "batch256.db"
        limits = StreamLimits(batch_records=256)
        with ContinuousIngestor(self.source, journal, self.factory, repository=self.repo, limits=limits) as worker:
            first = worker.poll()
            self.assertEqual(first["quality"]["records_accepted"], 256)
            self.assertEqual(first["stream"]["queue_high_watermark"], 256)
        with ContinuousIngestor(self.source, journal, self.factory, repository=self.repo, limits=limits) as worker:
            self.assertEqual(worker.recovered_records, 256)
            report = worker.poll()
            self.assertEqual(report["quality"]["records_accepted"], 300)
            self.assertEqual(report["quality"]["records_rejected"], 0)
            self.assertEqual(report["stream"]["backlog_bytes"], 0)
            self.assertEqual(report["stream"]["queue_high_watermark"], 256)

    def test_read_transaction_keeps_full_before_and_after_state_scans(self):
        from aegisflow.audited_store import snapshot
        self.repo.project_analysis_run(self.report)
        with patch("aegisflow.audited_store.snapshot", wraps=snapshot) as scan, \
                patch.object(self.repo, "_verify", wraps=self.repo._verify) as verify:
            self.repo.get_analysis_run(self.report["run_id"])
        self.assertEqual(scan.call_count, 2)
        self.assertEqual(verify.call_count, 1)


if __name__ == "__main__":
    unittest.main()
