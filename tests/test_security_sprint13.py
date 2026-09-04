import base64
import contextlib
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient
from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository, repository_from_url
from aegisflow.audited_store import AuditedIncidentRepository, EvidenceIntegrityError
from aegisflow.security import AccessSettings, Credential, audit_actor

# Public deterministic test credentials ONLY; never suitable for a deployed app.
KEY = b"public-test-key-not-for-real-use!"
KEY = sha256(KEY).digest()
TOKENS = {role: role + "-public-test-token-" + "X" * 40 for role in ("viewer", "analyst", "admin")}


def settings(expired=False):
    return AccessSettings("required", tuple(Credential(role, role, sha256(token.encode()).hexdigest(),
                          1 if expired else time.time() + 3600) for role, token in TOKENS.items()),
                          ("https://testserver",))


class Sprint13SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "signed.db"
        self.store = AuditedIncidentRepository(self.path, KEY)
        self.client = TestClient(create_app(self.store, access=settings()), base_url="https://testserver")
        self.addCleanup(self.client.close)

    def headers(self, role="analyst"):
        return {"Authorization": "Bearer " + TOKENS[role]}

    def mutate_database(self, sql, parameters=()):
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            with db:
                db.execute(sql, parameters)

    def save_run(self, identity="old", status="completed", at=100):
        with patch("aegisflow.audited_store.time.time", return_value=at):
            self.store.save_analysis_run(identity, {"run_id": identity, "status": status, "alerts": []})

    def upload(self):
        content = (ROOT / "examples/judge_attack_replay.jsonl").read_text(encoding="utf-8")
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            result = self.client.post("/api/replays/analyse", headers=self.headers(),
                                      json={"filename": "traffic.jsonl", "content": content})
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def test_all_data_static_and_docs_require_authentication(self):
        for path in ("/", "/api/health", "/api/incidents", "/api/analysis-runs/secret", "/docs", "/openapi.json"):
            self.assertEqual(self.client.get(path).status_code, 401, path)
        self.assertEqual(self.client.post("/api/replays/analyse", content=b"malformed").status_code, 401)

    def test_bad_expired_query_and_duplicate_tokens_are_denied(self):
        self.assertEqual(self.client.get("/api/health?token=" + TOKENS["admin"]).status_code, 401)
        self.assertEqual(self.client.get("/api/health", headers={"Authorization": "Bearer " + "z" * 40}).status_code, 401)
        with TestClient(create_app(self.store, access=settings(expired=True)), base_url="https://testserver") as client:
            self.assertEqual(client.get("/api/health", headers=self.headers()).status_code, 401)
        self.assertEqual(self.client.get("/api/health", headers=[("Authorization", "Bearer " + TOKENS["admin"]),
                                                                   ("Authorization", "Bearer " + TOKENS["viewer"])]).status_code, 401)

    def test_https_is_mandatory_and_forwarded_header_not_trusted_by_middleware(self):
        with TestClient(create_app(self.store, access=settings()), base_url="http://testserver") as client:
            self.assertEqual(client.get("/api/health", headers={**self.headers(), "X-Forwarded-Proto": "https"}).status_code, 403)

    def test_viewer_cannot_mutate_or_start_legacy_get_stream(self):
        for method, path in (("POST", "/api/replays/analyse"), ("PATCH", "/api/incidents/x/status"),
                             ("POST", "/api/demo/run"), ("GET", "/api/stream/simulated")):
            self.assertEqual(self.client.request(method, path, headers=self.headers("viewer")).status_code, 403)
        self.assertEqual(self.client.get("/api/metrics", headers=self.headers("viewer")).status_code, 200)

    def test_admin_only_security_endpoints(self):
        for role in ("viewer", "analyst"):
            self.assertEqual(self.client.get("/api/security/audit", headers=self.headers(role)).status_code, 403)
            self.assertEqual(self.client.post("/api/security/retention", headers=self.headers(role), json={}).status_code, 403)
        result = self.client.get("/api/security/audit", headers=self.headers("admin"))
        self.assertTrue(result.json()["verified"])
        self.assertEqual(result.headers["X-Content-Type-Options"], "nosniff")

    def test_basic_browser_credentials_and_csrf_guard(self):
        basic = "Basic " + base64.b64encode(("analyst:" + TOKENS["analyst"]).encode()).decode()
        headers = {"Authorization": basic}
        self.assertEqual(self.client.get("/api/health", headers=headers).status_code, 200)
        for origin in (None, "https://evil.example", "null"):
            attempt = {**headers, **({"Origin": origin} if origin else {})}
            self.assertEqual(self.client.patch("/api/incidents/missing/status", headers=attempt,
                                               json={"status": "resolved"}).status_code, 403)
            self.assertEqual(self.client.get("/api/stream/simulated", headers=attempt).status_code, 403)
        result = self.client.patch("/api/incidents/missing/status", headers={**headers, "Origin": "https://testserver"},
                                   json={"status": "resolved"})
        self.assertEqual(result.status_code, 404)  # Authorized; actual route ran.

    def test_preflight_cannot_mutate_or_grant_unknown_origin(self):
        for origin, expected in (("https://testserver", 200), ("https://evil.example", 400)):
            result = self.client.options("/api/replays/analyse", headers={"Origin": origin,
                                         "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization"})
            self.assertEqual(result.status_code, expected)
        self.assertEqual(self.store.metrics()["total_incidents"], 0)

    def test_authenticated_identity_overrides_forged_analyst_and_is_audited(self):
        run = self.upload()
        identity = run["incidents"][0]["incident_id"]
        result = self.client.post(f"/api/incidents/{identity}/feedback", headers=self.headers(),
                                  json={"disposition": "needs_review", "analyst": "forged-admin", "notes": "check"})
        self.assertEqual(result.status_code, 201)
        self.assertEqual(result.json()["analyst"], "analyst")
        with self.store._connect() as db:
            rows = [json.loads(r["payload"]) for r in db.execute("SELECT payload FROM evidence_audit").fetchall()]
        self.assertTrue(any(r["actor"] == "analyst" and "feedback" in r["operation"] for r in rows))
        self.assertNotIn(TOKENS["analyst"], json.dumps(rows))

    def test_signed_export_receipt_detects_changed_export_bytes(self):
        run = self.upload()
        result = self.client.get("/api/incidents/" + run["incidents"][0]["incident_id"] + "/export",
                                 headers=self.headers("viewer"))
        exported = result.json()
        receipt = exported.pop("integrity")
        self.assertTrue(self.store.verify_export(exported, receipt))
        exported["incident"]["confidence"] = 0
        self.assertFalse(self.store.verify_export(exported, receipt))

    def test_payload_edit_insert_delete_are_detected(self):
        self.save_run()
        self.mutate_database("UPDATE analysis_runs SET payload='{}'")
        with self.assertRaises(EvidenceIntegrityError):
            self.store.get_analysis_run("old")
        self.assertEqual(self.client.get("/api/analysis-runs/old", headers=self.headers()).status_code, 503)

    def test_unsigned_row_insertion_and_protected_table_drop_are_detected(self):
        self.mutate_database("INSERT INTO runtime_state VALUES ('forged', '{}', 1)")
        with self.assertRaises(EvidenceIntegrityError):
            self.store.verify_evidence()
        self.mutate_database("DELETE FROM runtime_state")
        self.mutate_database("DROP TABLE alerts")
        self.assertEqual(self.client.get("/api/incidents", headers=self.headers()).status_code, 503)

    def test_hold_and_retention_delete_are_audited_as_admin(self):
        self.save_run()
        response = self.client.put("/api/security/retention/holds/old", headers=self.headers("admin"), json={"held": True})
        self.assertEqual(response.status_code, 200)
        self.client.put("/api/security/retention/holds/old", headers=self.headers("admin"), json={"held": False})
        plan = self.client.get("/api/security/retention?before=200", headers=self.headers("admin")).json()
        self.client.post("/api/security/retention", headers=self.headers("admin"),
                         json={"before": 200, "plan_sha256": plan["plan_sha256"]})
        with self.store._connect() as db:
            record = json.loads(db.execute("SELECT payload FROM evidence_audit ORDER BY sequence DESC LIMIT 1").fetchone()["payload"])
        self.assertEqual(record["actor"], "admin")
        self.assertEqual(record["event"], "retention_applied")
        self.assertTrue(any(c["table"] == "analysis_runs" and c["after"] is None for c in record["changes"]))

    def test_bootstrap_is_random_create_only_and_does_not_print_tokens(self):
        destination = Path(self.temp.name) / "private"
        command = [sys.executable, str(ROOT / "scripts/init_security.py"), "--directory", str(destination),
                   "--origin", "https://localhost:8443"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads((destination / "auth.json").read_text())
        tokens = json.loads((destination / "bootstrap-tokens.json").read_text())["tokens"]
        for credential in config["credentials"]:
            token = tokens[credential["principal"]]
            self.assertGreaterEqual(len(token), 32)
            self.assertEqual(credential["token_sha256"], sha256(token.encode()).hexdigest())
            self.assertNotIn(token, result.stdout)
        self.assertEqual(len((destination / "audit.key").read_text().strip()), 64)
        again = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(again.returncode, 2)

    def test_protected_simulated_stream_has_signed_persistence(self):
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            result = self.client.get("/api/stream/simulated?interval=0", headers=self.headers())
        self.assertEqual(result.status_code, 200)
        self.assertIn("text/event-stream", result.headers["content-type"])
        self.assertTrue(self.store.verify_evidence()["verified"])
        self.assertGreater(self.store.metrics()["total_incidents"], 0)

    def test_chain_edit_and_wrong_key_fail_closed(self):
        self.save_run()
        with self.assertRaises(EvidenceIntegrityError):
            AuditedIncidentRepository(self.path, b"Z" * 32)
        self.mutate_database("UPDATE evidence_audit SET mac=? WHERE sequence=1", ("f" * 64,))
        with self.assertRaises(EvidenceIntegrityError):
            self.store.verify_evidence()

    def test_independent_head_detects_tail_truncation(self):
        head = self.store.verify_evidence()["head"]
        self.store.record_audit_event("export")
        anchored = self.store.verify_evidence()["head"]
        self.mutate_database("DELETE FROM evidence_audit WHERE sequence > ?", (head["sequence"],))
        self.assertTrue(self.store.verify_evidence()["verified"])  # Honest database-only limitation.
        with self.assertRaises(EvidenceIntegrityError):
            self.store.verify_evidence(anchored)

    def test_unsigned_reopen_and_silent_enrollment_are_forbidden(self):
        with self.assertRaises(RuntimeError):
            IncidentRepository(self.path)
        unsigned = Path(self.temp.name) / "legacy.db"
        legacy = IncidentRepository(unsigned)
        legacy.save_analysis_run("x", {"status": "completed"})
        with self.assertRaises(EvidenceIntegrityError):
            AuditedIncidentRepository(unsigned, KEY)

    def test_failed_write_rolls_back_data_and_ledger(self):
        before = self.store.verify_evidence()["head"]
        with patch.object(self.store, "_append", side_effect=RuntimeError("failed signing")):
            with self.assertRaises(RuntimeError):
                self.store.save_analysis_run("x", {"status": "completed"})
        self.assertIsNone(self.store.get_analysis_run("x"))
        self.assertEqual(self.store.verify_evidence()["head"], before)

    def test_runtime_state_and_idempotent_writes_are_guarded(self):
        self.store.put_runtime_state("state", {"window": [1, 2]}, 100)
        before = self.store.verify_evidence()["head"]
        self.store.put_runtime_state("state", {"window": [1, 2]}, 100)
        self.assertEqual(before, self.store.verify_evidence()["head"])
        self.assertTrue(self.store.delete_runtime_state("state"))
        self.assertTrue(self.store.verify_evidence()["verified"])

    def test_retention_dry_run_hold_and_completed_only(self):
        self.save_run("old")
        self.save_run("held")
        self.save_run("active", "following")
        self.save_run("recent", at=time.time())
        self.store.set_retention_hold("held", True)
        plan = self.store.retention_plan(200)
        self.assertEqual(plan["run_ids"], ["old"])
        self.assertIsNotNone(self.store.get_analysis_run("old"))
        result = self.store.apply_retention(200, plan["plan_sha256"])
        self.assertEqual(result["deleted_reports"], 1)
        self.assertIsNone(self.store.get_analysis_run("old"))
        for identity in ("held", "active", "recent"):
            self.assertIsNotNone(self.store.get_analysis_run(identity))
        self.assertTrue(self.store.verify_evidence()["verified"])

    def test_stale_plan_cannot_delete_new_or_held_evidence(self):
        self.save_run()
        plan = self.store.retention_plan(200)
        self.store.set_retention_hold("old", True)
        with self.assertRaisesRegex(ValueError, "stale"):
            self.store.apply_retention(200, plan["plan_sha256"])
        self.assertIsNotNone(self.store.get_analysis_run("old"))

    def test_retention_uses_storage_time_not_uploaded_timestamps(self):
        self.store.save_analysis_run("new", {"status": "completed", "timestamp": 1, "created_at": 1})
        self.assertEqual(self.store.retention_plan(200)["run_ids"], [])
        for cutoff in (float("nan"), float("inf"), -1, time.time() + 1000):
            with self.assertRaises(ValueError):
                self.store.retention_plan(cutoff)

    def test_retention_api_and_unsigned_demo_denial(self):
        self.save_run()
        headers = self.headers("admin")
        plan = self.client.get("/api/security/retention?before=200", headers=headers).json()
        result = self.client.post("/api/security/retention", headers=headers,
                                  json={"before": 200, "plan_sha256": plan["plan_sha256"]})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["deleted_reports"], 1)
        with TestClient(create_app(self.store, access=AccessSettings())) as client:
            self.assertEqual(client.get("/api/security/retention?before=200").status_code, 403)

    def test_protected_mode_requires_key_and_valid_configuration(self):
        plain = IncidentRepository(Path(self.temp.name) / "plain.db")
        with self.assertRaises(ValueError):
            create_app(plain, access=settings())
        for env in ({"DRASTHA_AUTH_MODE": "required"}, {"DRASTHA_AUTH_MODE": "oops"},
                    {"DRASTHA_AUTH_MODE": "local-demo", "DRASTHA_AUTH_FILE": "unused"}):
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(ValueError):
                    AccessSettings.from_environment()

    def test_config_file_hashed_credentials_and_key_loading(self):
        config = Path(self.temp.name) / "credentials.json"
        config.write_text(json.dumps({"credentials": [c.__dict__ for c in settings().credentials],
                                      "allowed_origins": ["https://testserver"]}), encoding="utf-8")
        key = Path(self.temp.name) / "audit.key"
        key.write_text(KEY.hex(), encoding="ascii")
        with patch.dict(os.environ, {"DRASTHA_AUTH_MODE": "required", "DRASTHA_AUTH_FILE": str(config),
                                     "DRASTHA_AUDIT_KEY_FILE": str(key)}):
            self.assertEqual(len(AccessSettings.from_environment().credentials), 3)
            self.assertIsInstance(repository_from_url(self.path), AuditedIncidentRepository)
            with self.assertRaises(ValueError):
                repository_from_url("postgresql://example.invalid/db")

    def test_continuous_recovery_projects_into_signed_store(self):
        from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO
        from aegisflow.continuous_ingestion import ContinuousIngestor
        source = Path(self.temp.name) / "records.jsonl"
        source.write_bytes((ROOT / "examples/judge_attack_replay.jsonl").read_bytes())
        checkpoint = Path(self.temp.name) / "checkpoint.db"
        factory = lambda: AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
        with ContinuousIngestor(source, checkpoint, factory, repository=self.store) as worker:
            report = worker.poll()
        with ContinuousIngestor(source, checkpoint, factory, repository=self.store) as worker:
            again = worker.poll()
        self.assertEqual(report["alerts"], again["alerts"])
        self.assertTrue(self.store.verify_evidence()["verified"])

    def test_protected_mixed_http_replay_retains_all_eight_behaviours(self):
        content = (ROOT / "examples/drastha_mixed_evaluation_v3.jsonl").read_text(encoding="utf-8")
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            response = self.client.post("/api/replays/analyse", headers=self.headers(),
                                        json={"filename": "mixed.jsonl", "content": content})
        self.assertEqual(response.status_code, 200, response.text)
        report = response.json()
        self.assertEqual(report["quality"]["records_accepted"], 452)
        self.assertEqual(report["quality"]["status"], "healthy")
        self.assertEqual((len(report["alerts"]), len(report["incidents"])), (8, 8))
        score = report["evaluation"]
        self.assertEqual((score["true_positive"], score["false_positive"], score["false_negative"], score["true_negative"]), (8, 0, 0, 86))
        self.assertTrue(self.store.verify_evidence()["verified"])
