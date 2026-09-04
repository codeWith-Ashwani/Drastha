import contextlib
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from aegisflow.audited_store import AuditedIncidentRepository, EvidenceIntegrityError
from aegisflow.api_store import IncidentRepository
from aegisflow.operations import backup_database, restore_database, verify_database, preflight, read_key
from aegisflow.security import AccessSettings
from operate import main

KEY = sha256(b"public-sprint15-test-key-not-for-deployment").digest()


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "source.db"
        self.store = AuditedIncidentRepository(self.database, KEY)
        self.store.save_analysis_run("test", {"status": "completed", "evidence": "original"})
        self.head = self.store.verify_evidence()["head"]
        self.keyfile = self.root / "audit.key"
        self.keyfile.write_text(KEY.hex(), encoding="ascii")
        self.bundle = self.root / "backup"
        self.restored = self.root / "restored"

    def backup(self):
        return backup_database(self.database, self.bundle, KEY)

    def test_backup_restore_preserves_all_rows_and_source_bytes(self):
        before = self.database.read_bytes()
        result = self.backup()
        self.assertTrue(result["completed"])
        self.assertEqual(result["manifest"]["head"], self.head)
        self.assertEqual({p.name for p in self.bundle.iterdir()}, {"analyst.db", "manifest.json", "head.json"})
        self.assertEqual(self.database.read_bytes(), before)
        restored = restore_database(self.bundle, self.restored, KEY, self.head)
        self.assertTrue(restored["completed"])
        self.assertFalse(restored["automatic_cutover"])
        self.assertEqual(restored["rows"]["analysis_runs"], 1)
        self.assertEqual(verify_database(self.restored / "analyst.db", KEY)["head"], self.head)

    def test_online_backup_includes_committed_wal_records(self):
        with contextlib.closing(sqlite3.connect(self.database)) as keep_open:
            self.assertEqual(keep_open.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            keep_open.execute("BEGIN")
            keep_open.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()
            self.store.save_analysis_run("wal-record", {"status": "completed"})
            head = self.store.verify_evidence()["head"]
            self.assertTrue(Path(str(self.database) + "-wal").exists())
            self.backup()
        self.assertEqual(verify_database(self.bundle / "analyst.db", KEY, head)["rows"]["analysis_runs"], 2)
        self.assertFalse(Path(str(self.bundle / "analyst.db") + "-wal").exists())

    def test_verify_is_read_only_and_never_enrolls_unsigned_data(self):
        before = self.database.read_bytes()
        self.assertEqual(verify_database(self.database, KEY)["head"], self.head)
        self.assertEqual(self.database.read_bytes(), before)
        unsigned = self.root / "unsigned.db"
        IncidentRepository(unsigned)
        raw = unsigned.read_bytes()
        with self.assertRaises(EvidenceIntegrityError):
            verify_database(unsigned, KEY)
        self.assertEqual(unsigned.read_bytes(), raw)

    def test_missing_database_is_not_created(self):
        missing = self.root / "missing.db"
        with self.assertRaises(FileNotFoundError):
            verify_database(missing, KEY)
        self.assertFalse(missing.exists())

    def test_tampered_source_cannot_produce_completed_backup(self):
        with contextlib.closing(sqlite3.connect(self.database)) as db, db:
            db.execute("UPDATE analysis_runs SET payload='{}'")
        with self.assertRaises(EvidenceIntegrityError):
            self.backup()
        self.assertFalse((self.bundle / "manifest.json").exists())

    def test_wrong_key_fails_verification_and_restore(self):
        with self.assertRaises(EvidenceIntegrityError):
            verify_database(self.database, b"x" * 32)
        self.backup()
        with self.assertRaises(EvidenceIntegrityError):
            restore_database(self.bundle, self.restored, b"x" * 32, self.head)
        self.assertFalse(self.restored.exists())

    def test_backups_and_restore_never_overwrite_existing_directories(self):
        self.backup()
        before = (self.bundle / "manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.backup()
        self.restored.mkdir()
        marker = self.restored / "operator.txt"
        marker.write_text("preserve")
        with self.assertRaises(FileExistsError):
            restore_database(self.bundle, self.restored, KEY, self.head)
        self.assertEqual(marker.read_text(), "preserve")
        self.assertEqual((self.bundle / "manifest.json").read_bytes(), before)

    def test_nested_restore_destination_is_refused(self):
        self.backup()
        with self.assertRaises(ValueError):
            restore_database(self.bundle, self.bundle / "child", KEY, self.head)

    def test_snapshot_byte_tampering_fails_before_restore_receipt(self):
        self.backup()
        with (self.bundle / "analyst.db").open("ab") as file:
            file.write(b"tamper")
        with self.assertRaises(EvidenceIntegrityError):
            restore_database(self.bundle, self.restored, KEY, self.head)
        self.assertFalse((self.restored / "restore-receipt.json").exists())

    def test_manifest_tampering_including_paths_is_refused(self):
        self.backup()
        path = self.bundle / "manifest.json"
        original = json.loads(path.read_text())
        for change in ({"file": "../source.db"}, {"sha256": "0" * 64}, {"scope": "everything"}):
            path.write_text(json.dumps({**original, **change}))
            with self.assertRaises(EvidenceIntegrityError):
                restore_database(self.bundle, self.restored, KEY, self.head)
        self.assertFalse(self.restored.exists())

    def test_independent_head_detects_old_valid_backup(self):
        self.backup()
        self.store.save_analysis_run("later", {"status": "completed"})
        latest = self.store.verify_evidence()["head"]
        with self.assertRaises(EvidenceIntegrityError):
            restore_database(self.bundle, self.restored, KEY, latest)
        self.assertFalse(self.restored.exists())
        # Deliberately selecting the historical checkpoint is explicit, not hidden.
        restore_database(self.bundle, self.restored, KEY, self.head)
        self.assertEqual(verify_database(self.restored / "analyst.db", KEY)["rows"]["analysis_runs"], 1)

    def test_expected_head_is_required_even_for_authentic_backup(self):
        self.backup()
        with self.assertRaises(EvidenceIntegrityError):
            restore_database(self.bundle, self.restored, KEY, None)

    def test_bundle_sidecars_are_not_silently_ignored(self):
        self.backup()
        (self.bundle / "analyst.db-wal").touch()
        with self.assertRaises(EvidenceIntegrityError):
            restore_database(self.bundle, self.restored, KEY, self.head)

    def test_unexpected_sqlite_trigger_is_refused(self):
        with contextlib.closing(sqlite3.connect(self.database)) as db, db:
            db.execute("CREATE TRIGGER untrusted AFTER INSERT ON analysis_runs BEGIN SELECT 1; END")
        with self.assertRaises(EvidenceIntegrityError):
            verify_database(self.database, KEY)

    def test_unsigned_extra_table_is_refused(self):
        with contextlib.closing(sqlite3.connect(self.database)) as db, db:
            db.execute("CREATE TABLE unsigned_extra (value TEXT)")
        with self.assertRaises(EvidenceIntegrityError):
            verify_database(self.database, KEY)

    def test_backup_byte_budget_is_not_bypassed(self):
        with patch("aegisflow.operations.MAX_BACKUP_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "budget"):
                self.backup()
        self.assertFalse((self.bundle / "manifest.json").exists())

    def test_backup_deadline_has_no_success_manifest(self):
        with patch("aegisflow.operations.time.monotonic", side_effect=[0, 100]):
            with self.assertRaises(TimeoutError):
                self.backup()
        self.assertFalse((self.bundle / "manifest.json").exists())

    def config(self):
        auth, cert, tls_key = (self.root / name for name in ("auth.json", "cert.pem", "tls.key"))
        auth.write_text(json.dumps({"credentials": [{"principal": r, "role": r,
            "token_sha256": sha256(r.encode()).hexdigest(), "expires_at": time.time() + 3600}
            for r in ("viewer", "analyst", "admin")], "allowed_origins": ["https://localhost:8443"]}))
        cert.write_text("test-placeholder")
        tls_key.write_text("test-placeholder")
        web = self.root / "web"
        web.mkdir(exist_ok=True)
        (web / "index.html").write_text("test")
        return dict(database=self.database, audit_key=self.keyfile, auth=auth, cert=cert, tls_key=tls_key,
                    web=web, root=ROOT)

    def test_preflight_checks_do_not_claim_production_readiness(self):
        config = self.config()
        with patch("aegisflow.operations.ssl.SSLContext"):
            result = preflight(**config)
        self.assertTrue(result["local_checks_passed"])
        self.assertFalse(result["production_ready"])
        self.assertFalse(result["proxy_headers"])
        self.assertEqual(result["workers"], 1)

    def test_invalid_tls_key_pair_is_not_accepted(self):
        with self.assertRaises(Exception):
            preflight(**self.config())

    def test_expired_credentials_fail_preflight(self):
        config = self.config()
        content = json.loads(config["auth"].read_text())
        content["credentials"][0]["expires_at"] = 1
        config["auth"].write_text(json.dumps(content))
        with self.assertRaisesRegex(ValueError, "Expired"):
            preflight(**config)

    def test_missing_required_role_fails_preflight(self):
        config = self.config()
        content = json.loads(config["auth"].read_text())
        content["credentials"].pop()
        config["auth"].write_text(json.dumps(content))
        with self.assertRaisesRegex(ValueError, "roles"):
            preflight(**config)

    def test_origin_port_mismatch_is_refused(self):
        config = self.config()
        with self.assertRaisesRegex(ValueError, "matching listening port"):
            preflight(**config, port=8444)

    def test_invalid_model_configuration_is_not_hidden(self):
        config = self.config()
        with patch.dict(os.environ, {"DRASTHA_DNS_MODEL": str(self.root / "missing-model.json")}), \
                patch("aegisflow.operations.ssl.SSLContext"):
            with self.assertRaises(FileNotFoundError):
                preflight(**config)

    def test_public_binding_and_invalid_port_are_refused(self):
        config = self.config()
        with self.assertRaisesRegex(ValueError, "loopback"):
            preflight(**config, host="0.0.0.0")
        with self.assertRaisesRegex(ValueError, "Port"):
            preflight(**config, port=0)

    def test_web_directory_cannot_expose_secrets(self):
        config = self.config()
        leaked = config["web"] / "audit.key"
        leaked.write_bytes(self.keyfile.read_bytes())
        config["audit_key"] = leaked
        with self.assertRaisesRegex(ValueError, "served web"):
            preflight(**config)

    def test_missing_web_build_is_refused(self):
        config = self.config()
        config["web"] = self.root
        with self.assertRaisesRegex(ValueError, "Built dashboard"):
            preflight(**config)

    def test_explicit_auth_loader_does_not_mutate_environment(self):
        config = self.config()
        before = dict(os.environ)
        self.assertEqual(AccessSettings.from_file(config["auth"]).mode, "required")
        self.assertEqual(dict(os.environ), before)

    def test_key_loader_rejects_bad_and_oversized_keys(self):
        for value in ("invalid", "0" * 300):
            self.keyfile.write_text(value)
            with self.assertRaises(ValueError):
                read_key(self.keyfile)

    def test_cli_verify_and_create_only_initialization(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["verify", "--database", str(self.database), "--audit-key", str(self.keyfile)]), 0)
        self.assertTrue(json.loads(output.getvalue())["verified"])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["init-store", "--directory", str(self.root), "--audit-key", str(self.keyfile)]), 2)

    def test_launcher_pins_protected_settings_and_disables_proxy_headers(self):
        config = self.config()
        argv = ["serve"]
        for name, value in config.items():
            argv.extend(["--" + name.replace("_", "-"), str(value)])
        with patch.dict(os.environ), patch("operate.preflight", return_value={"local_checks_passed": True}), \
                patch("uvicorn.run") as serve, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(argv), 0)
            self.assertEqual(os.environ["DRASTHA_AUTH_MODE"], "required")
            self.assertEqual(os.environ["DRASTHA_ANALYSIS_PROFILE"], "deployment-baseline")
            self.assertFalse(serve.call_args.kwargs["proxy_headers"])
            self.assertFalse(serve.call_args.kwargs["reload"])
            self.assertEqual(serve.call_args.kwargs["workers"], 1)

    def test_recovery_drill_does_not_block_on_unread_child_log_pipe(self):
        from unittest.mock import Mock
        import subprocess
        from check_operational_recovery import server
        child = Mock()
        child.poll.return_value = 0
        with patch("check_operational_recovery.subprocess.Popen", return_value=child) as start:
            with server(self.root, self.database, self.root, self.root / "cert.pem", self.keyfile, 8443):
                log = start.call_args.kwargs["stdout"]
                self.assertNotEqual(log, subprocess.PIPE)
                self.assertIs(start.call_args.kwargs["stderr"], log)
                log.write(b"x" * 65536)  # More than the Windows anonymous-pipe buffer.
            self.assertTrue(log.closed)
            child.wait.assert_called_once()


if __name__ == "__main__":
    unittest.main()
