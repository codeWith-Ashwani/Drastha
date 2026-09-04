import contextlib
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO, DEPLOYMENT_BASELINE
from aegisflow.audited_store import AuditedIncidentRepository, EvidenceIntegrityError
from aegisflow.continuous_ingestion import ContinuousIngestor, StreamStopped
from aegisflow.operations import file_digest, verify_database
from aegisflow.stream_recovery import backup_stream, restore_stream, check_stream
from operate import main

KEY = sha256(b"public-sprint17-test-key-not-for-deployment").digest()


def record(i):
    return {"ts": 1000 + i / 10, "uid": f"S17-{i}", "proto": "tcp", "conn_state": "S0",
            "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.20",
            "id.orig_p": 40000 + i, "id.resp_p": 1000 + i}


class StreamRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "sensor.jsonl"
        self.source.write_text("".join(json.dumps(record(i)) + "\n" for i in range(8)), encoding="utf-8")
        self.journal = self.root / "journal.db"
        self.db = self.root / "analyst.db"
        self.repo = AuditedIncidentRepository(self.db, KEY)
        self.factory = lambda: AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
        with ContinuousIngestor(self.source, self.journal, self.factory, repository=self.repo) as worker:
            self.report = worker.poll()
        self.incident = self.report["incidents"][0]["incident_id"]
        self.repo.set_status(self.incident, "investigating", 2000)
        self.repo.add_feedback({"feedback_id": "review", "incident_id": self.incident, "analyst": "tester",
                                "timestamp": 2000, "disposition": "needs_review", "notes": "preserve at cut"})
        self.repo.set_retention_hold(self.report["run_id"], True)
        self.bundle, self.restored = self.root / "bundle", self.root / "restored"

    def backup(self):
        return backup_stream(self.source, self.journal, self.db, self.bundle, KEY, self.factory)

    def restore(self, anchor, **overrides):
        args = dict(bundle=self.bundle, source=self.source, destination=self.restored, key=KEY,
                    expected_anchor=anchor, factory=self.factory)
        args.update(overrides)
        return restore_stream(**args)

    def test_restore_exact_review_hold_and_resume_appended_tail(self):
        original = {p: file_digest(p) for p in (self.source, self.journal, self.db)}
        before = self.repo.get_incident(self.incident)
        cut = self.backup()
        self.assertEqual({p.name for p in self.bundle.iterdir()}, {"journal.db", "analyst.db", "manifest.json", "anchor.json"})
        self.assertEqual({p: file_digest(p) for p in original}, original)
        with self.source.open("a") as out:
            out.write(json.dumps(record(8)) + "\n")
        result = self.restore(cut["anchor"])
        self.assertEqual(result["lines"], 8)
        restored = AuditedIncidentRepository(self.restored / "analyst.db", KEY)
        self.assertEqual(restored.get_incident(self.incident), before)
        self.assertEqual(restored.verify_evidence()["head"], cut["head"])
        with ContinuousIngestor(self.source, self.restored / "journal.db", self.factory, repository=restored) as worker:
            self.assertEqual(worker.recovered_records, 8)
            report = worker.poll()
        self.assertEqual(report["quality"]["records_accepted"], 9)
        self.assertEqual(report["quality"]["duplicate_uid_count"], 0)
        self.assertEqual(restored.get_incident(self.incident)["status"], "investigating")
        self.assertEqual(restored.get_incident(self.incident)["feedback"][0]["notes"], "preserve at cut")
        with restored._connect() as db:
            self.assertEqual(db.execute("SELECT held FROM evidence_retention").fetchone()[0], 1)

    def test_active_worker_refused_no_completed_manifest(self):
        with ContinuousIngestor(self.source, self.journal, self.factory, repository=self.repo):
            with self.assertRaisesRegex(EvidenceIntegrityError, "Stop the worker"):
                self.backup()
        self.assertFalse((self.bundle / "manifest.json").exists())

    def test_active_analyst_writer_refused(self):
        with contextlib.closing(sqlite3.connect(self.db)) as db:
            db.execute("BEGIN IMMEDIATE")
            with self.assertRaises(EvidenceIntegrityError):
                self.backup()
        self.assertFalse((self.bundle / "manifest.json").exists())

    def test_projection_behind_journal_is_not_silently_repaired(self):
        with self.source.open("a") as out:
            out.write(json.dumps(record(8)) + "\n")
        with ContinuousIngestor(self.source, self.journal, self.factory) as worker:
            worker.poll()
        with self.assertRaisesRegex(EvidenceIntegrityError, "projection is not at journal cut"):
            self.backup()
        self.assertEqual(self.repo.get_analysis_run(self.report["run_id"])["quality"]["records_accepted"], 8)

    def test_check_uses_copies_and_preserves_input_bytes(self):
        anchor = self.backup()["anchor"]
        inputs = [self.source, self.journal, self.db, *self.bundle.iterdir()]
        before = {p: file_digest(p) for p in inputs}
        result = check_stream(self.bundle, self.source, KEY, anchor, self.factory)
        self.assertTrue(result["compatible"])
        self.assertFalse(result["cross_version_migration"])
        self.assertEqual({p: file_digest(p) for p in inputs}, before)

    def test_engine_upgrade_fails_closed_without_hash_rewrite(self):
        anchor = self.backup()["anchor"]
        before = file_digest(self.bundle / "journal.db")
        with patch("aegisflow.stream_recovery._engine_digest", return_value="candidate-different-engine"):
            with self.assertRaisesRegex(EvidenceIntegrityError, "Engine mismatch"):
                self.restore(anchor)
        self.assertEqual(file_digest(self.bundle / "journal.db"), before)
        self.assertFalse((self.restored / "restore-receipt.json").exists())

    def test_wrong_profile_refused(self):
        anchor = self.backup()["anchor"]
        with self.assertRaisesRegex(EvidenceIntegrityError, "provenance mismatch"):
            self.restore(anchor, factory=lambda: AnalysisSession.from_root(ROOT, DEPLOYMENT_BASELINE))

    def test_wrong_key_refused_before_destination_creation(self):
        anchor = self.backup()["anchor"]
        with self.assertRaises(EvidenceIntegrityError):
            self.restore(anchor, key=b"x" * 32)
        self.assertFalse(self.restored.exists())

    def test_independent_anchor_required_and_old_bundle_cannot_match_new_cut(self):
        old = self.backup()["anchor"]
        self.repo.set_status(self.incident, "resolved", 2100)
        newer = backup_stream(self.source, self.journal, self.db, self.root / "newer", KEY, self.factory)["anchor"]
        self.assertNotEqual(old, newer)
        for anchor in (None, {}, newer):
            with self.assertRaisesRegex(EvidenceIntegrityError, "checkpoint anchor"):
                self.restore(anchor)
        self.assertFalse(self.restored.exists())

    def test_manifest_tamper_refused(self):
        anchor = self.backup()["anchor"]
        path = self.bundle / "manifest.json"
        value = json.loads(path.read_text())
        value["cut"]["lines"] = 0
        path.write_text(json.dumps(value))
        with self.assertRaises(EvidenceIntegrityError):
            self.restore(anchor)

    def test_both_snapshot_files_are_hash_checked(self):
        anchor = self.backup()["anchor"]
        for name in ("journal.db", "analyst.db"):
            path = self.bundle / name
            original = path.read_bytes()
            path.write_bytes(original + b"tampered")
            with self.assertRaisesRegex(EvidenceIntegrityError, "size/hash mismatch"):
                self.restore(anchor, destination=self.root / ("bad-" + name))
            path.write_bytes(original)

    def test_bundle_sidecars_refused(self):
        anchor = self.backup()["anchor"]
        (self.bundle / "journal.db-wal").write_bytes(b"untrusted")
        with self.assertRaisesRegex(EvidenceIntegrityError, "standalone"):
            self.restore(anchor)

    def test_original_source_prefix_required(self):
        anchor = self.backup()["anchor"]
        raw = self.source.read_bytes()
        for i, changed in enumerate((raw.replace(b"S17-0", b"S17-X"), raw[:-2])):
            self.source.write_bytes(changed)
            with self.assertRaises(EvidenceIntegrityError):
                self.restore(anchor, destination=self.root / f"bad-source-{i}")
        self.source.write_bytes(raw)

    def test_source_path_rebinding_refused_even_for_identical_bytes(self):
        anchor = self.backup()["anchor"]
        other = self.root / "other.jsonl"
        other.write_bytes(self.source.read_bytes())
        with self.assertRaisesRegex(EvidenceIntegrityError, "path/identity"):
            self.restore(anchor, source=other)

    def test_backup_rejects_journal_disposition_corruption(self):
        with contextlib.closing(sqlite3.connect(self.journal)) as db, db:
            db.execute("UPDATE stream_records SET disposition='ignored' WHERE start_offset=0")
        with self.assertRaisesRegex(StreamStopped, "outcome changed"):
            self.backup()
        self.assertFalse((self.bundle / "manifest.json").exists())

    def test_snapshot_quality_is_reconstructed_not_trusted(self):
        with contextlib.closing(sqlite3.connect(self.journal)) as db, db:
            report = json.loads(db.execute("SELECT payload FROM stream_snapshot").fetchone()[0])
            report["quality"]["records_accepted"] = 999
            db.execute("UPDATE stream_snapshot SET payload=?", (json.dumps(report),))
        with self.assertRaisesRegex(EvidenceIntegrityError, "Reconstructed quality"):
            self.backup()

    def test_journal_trigger_rejected_before_worker_copy_opens(self):
        with contextlib.closing(sqlite3.connect(self.journal)) as db, db:
            db.execute("CREATE TRIGGER unexpected AFTER UPDATE ON stream_meta BEGIN DELETE FROM stream_records; END")
        with self.assertRaisesRegex(EvidenceIntegrityError, "Unexpected journal"):
            self.backup()

    def test_tampered_analyst_state_never_resigned(self):
        with contextlib.closing(sqlite3.connect(self.db)) as db, db:
            db.execute("DELETE FROM analyst_feedback")
        with self.assertRaises(EvidenceIntegrityError):
            self.backup()

    def test_existing_or_nested_destinations_never_overwritten(self):
        anchor = self.backup()["anchor"]
        with self.assertRaises(FileExistsError):
            self.backup()
        for destination in (self.bundle, self.bundle / "nested", self.root):
            with self.assertRaises(ValueError):
                self.restore(anchor, destination=destination)
        self.restored.mkdir()
        with self.assertRaises(FileExistsError):
            self.restore(anchor)

    def test_partial_copy_failure_never_writes_completion_receipt(self):
        anchor = self.backup()["anchor"]
        with patch("aegisflow.stream_recovery._copy_checked", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.restore(anchor)
        self.assertTrue(self.restored.exists())
        self.assertFalse((self.restored / "restore-receipt.json").exists())

    def test_committed_wal_included_and_analyst_reviews_preserved(self):
        with contextlib.closing(sqlite3.connect(self.db)) as reader:
            reader.execute("PRAGMA journal_mode=WAL")
            reader.execute("BEGIN")
            reader.execute("SELECT COUNT(*) FROM incidents").fetchone()
            self.repo.set_status(self.incident, "resolved", 2200)
            head = self.repo.verify_evidence()["head"]
            anchor = self.backup()["anchor"]
        self.restore(anchor)
        self.assertEqual(verify_database(self.restored / "analyst.db", KEY)["head"], head)
        self.assertEqual(AuditedIncidentRepository(self.restored / "analyst.db", KEY).get_incident(self.incident)["status"], "resolved")

    def test_quarantine_and_ignored_lines_preserved(self):
        with self.source.open("a") as out:
            out.write("# sensor comment\n\n{bad json}\n" + json.dumps(record(0)) + "\n")
        with ContinuousIngestor(self.source, self.journal, self.factory, repository=self.repo) as worker:
            report = worker.poll()
        anchor = self.backup()["anchor"]
        self.restore(anchor)
        restored = AuditedIncidentRepository(self.restored / "analyst.db", KEY)
        self.assertEqual(restored.get_analysis_run(report["run_id"])["quality"], report["quality"])
        self.assertEqual(report["quality"]["records_rejected"], 2)

    def test_cli_backup_check_restore_and_wrong_anchor_exit(self):
        keyfile = self.root / "test.key"
        keyfile.write_text(KEY.hex())
        shared = ["--source", str(self.source), "--audit-key", str(keyfile), "--profile", "upload-demo"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["stream-backup", *shared, "--journal", str(self.journal), "--database", str(self.db),
                                   "--destination", str(self.bundle)]), 0)
            args = [*shared, "--bundle", str(self.bundle), "--expected-anchor", str(self.bundle / "anchor.json")]
            self.assertEqual(main(["stream-check", *args]), 0)
            self.assertEqual(main(["stream-restore", *args, "--destination", str(self.restored)]), 0)
        # CLI does not discover/read bundle anchor implicitly; option is mandatory.
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                main(["stream-check", *shared, "--bundle", str(self.bundle)])
        self.assertEqual(error.exception.code, 2)

    def test_mixed_fixture_signed_recovery_and_upload_api_drill(self):
        from check_stream_recovery import check
        result = check()
        self.assertTrue(result["passed"])
        self.assertEqual(result["records_at_cut"], 452)
        self.assertTrue(all(result["gates"].values()))
        self.assertEqual(result["upload_analysis"]["quality"]["status"], "healthy")
        self.assertEqual(result["upload_analysis"]["evaluation"]["true_negative"], 86)

    def test_missing_lock_is_not_created_and_no_bundle_written(self):
        Path(str(self.journal) + ".lock").unlink()
        with self.assertRaises(ValueError):
            self.backup()
        self.assertFalse(Path(str(self.journal) + ".lock").exists())
        self.assertFalse(self.bundle.exists())

    def test_source_cannot_alias_database_or_sqlite_sidecar(self):
        alias = self.root / "alias.jsonl"
        os.link(self.db, alias)
        with self.assertRaisesRegex(ValueError, "distinct"):
            backup_stream(alias, self.journal, self.db, self.bundle, KEY, self.factory)
        sidecar = Path(str(self.db) + "-journal")
        sidecar.write_bytes(b"must not overwrite source")
        with self.assertRaisesRegex(ValueError, "distinct"):
            backup_stream(sidecar, self.journal, self.db, self.bundle, KEY, self.factory)
        self.assertEqual(sidecar.read_bytes(), b"must not overwrite source")

    def test_snapshot_deadline_or_size_failure_has_no_manifest(self):
        with patch("aegisflow.stream_recovery.MAX_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "copy budget"):
                self.backup()
        self.assertFalse((self.bundle / "manifest.json").exists())

    def test_abrupt_backup_exit_leaves_only_incomplete_output_and_releases_locks(self):
        code = '''
import os, sys
from pathlib import Path
from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO
import aegisflow.stream_recovery as recovery
original = recovery._snapshot
def interrupted(source, target):
    original(source, target)
    os._exit(74)
recovery._snapshot = interrupted
recovery.backup_stream(*sys.argv[1:5], bytes.fromhex(sys.argv[5]),
    lambda: AnalysisSession.from_root(Path.cwd(), UPLOAD_DEMO))
'''
        original = {p: file_digest(p) for p in (self.source, self.journal, self.db)}
        result = subprocess.run([sys.executable, "-c", code, str(self.source), str(self.journal), str(self.db),
                                 str(self.bundle), KEY.hex()], cwd=ROOT,
                                env={**os.environ, "PYTHONPATH": str(ROOT / "src")}, timeout=20, capture_output=True)
        self.assertEqual(result.returncode, 74, result.stderr)
        self.assertFalse((self.bundle / "manifest.json").exists())
        self.assertEqual(original, {p: file_digest(p) for p in original})
        retry = backup_stream(self.source, self.journal, self.db, self.root / "retry", KEY, self.factory)
        self.assertTrue(retry["completed"])


if __name__ == "__main__":
    unittest.main()
