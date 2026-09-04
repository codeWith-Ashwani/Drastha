"""Finite signed coordinated-cut/recovery and actual upload-ASGI parity drill."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from fastapi.testclient import TestClient
from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO
from aegisflow.api import create_app
from aegisflow.audited_store import AuditedIncidentRepository
from aegisflow.continuous_ingestion import ContinuousIngestor, _engine_digest
from aegisflow.evaluation_scoring import score_ground_truth
from aegisflow.incidents import alert_from_dict
from aegisflow.operations import file_digest
from aegisflow.security import AccessSettings, Credential
from aegisflow.stream_recovery import backup_stream, restore_stream, check_stream


def check():
    fixture = ROOT / "examples/drastha_mixed_evaluation_v3.jsonl"
    raw = fixture.read_bytes()
    records = [json.loads(line) for line in raw.splitlines()]
    key, token = secrets.token_bytes(32), secrets.token_urlsafe(48)
    access = AccessSettings("required", (Credential("drill-analyst", "analyst", sha256(token.encode()).hexdigest(),
                                                time.time() + 3600),), ("https://testserver",))
    headers = {"Authorization": "Bearer " + token}
    factory = lambda: AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
    with tempfile.TemporaryDirectory(prefix="drastha-sprint17-") as folder:
        root = Path(folder)
        source, journal, database = root / "sensor.jsonl", root / "journal.db", root / "analyst.db"
        source.write_bytes(raw)
        repo = AuditedIncidentRepository(database, key)
        with ContinuousIngestor(source, journal, factory, repository=repo) as worker:
            while True:
                report = worker.poll()
                if not report["stream"]["backlog_bytes"]:
                    break
        incident = report["incidents"][0]["incident_id"]
        repo.set_status(incident, "investigating", time.time())
        repo.add_feedback({"feedback_id": "cut-review", "incident_id": incident, "analyst": "drill-analyst",
                           "timestamp": time.time(), "disposition": "needs_review", "notes": "review present at selected cut"})
        repo.set_retention_hold(report["run_id"], True)
        detail_at_cut = repo.get_incident(incident)
        before = {p: file_digest(p) for p in (source, journal, database)}
        started = time.perf_counter()
        cut = backup_stream(source, journal, database, root / "bundle", key, factory)
        backup_ms = (time.perf_counter() - started) * 1000
        assert before == {p: file_digest(p) for p in before}
        # Anchor is explicitly retained away from the bundle; not auto-discovered.
        anchor = json.loads(json.dumps(cut["anchor"]))
        preflight = check_stream(root / "bundle", source, key, anchor, factory)
        assert preflight["compatible"]
        repo.set_status(incident, "resolved", time.time())  # Later review is outside this selected recovery point.
        started = time.perf_counter()
        restore_stream(root / "bundle", source, root / "restored", key, anchor, factory)
        restore_ms = (time.perf_counter() - started) * 1000
        restored = AuditedIncidentRepository(root / "restored/analyst.db", key)
        with TestClient(create_app(restored, access=access), base_url="https://testserver") as client:
            assert client.get("/api/incidents").status_code == 401
            actual = client.get("/api/analysis-runs/" + report["run_id"], headers=headers)
            assert actual.status_code == 200
            assert actual.json() == json.loads(json.dumps(report))
            detail = client.get("/api/incidents/" + incident, headers=headers)
            assert detail.status_code == 200 and detail.json() == detail_at_cut
        assert restored.verify_evidence()["head"] == cut["head"]
        with restored._connect() as connection:
            assert connection.execute("SELECT held FROM evidence_retention WHERE run_id=?", (report["run_id"],)).fetchone()[0] == 1
        with TestClient(create_app(AuditedIncidentRepository(root / "upload.db", key), access=access),
                        base_url="https://testserver") as client, patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            response = client.post("/api/replays/analyse", headers=headers,
                                   json={"filename": fixture.name, "content": raw.decode()})
            assert response.status_code == 200, response.text
            uploaded = response.json()
        score = score_ground_truth(records, [alert_from_dict(item) for item in report["alerts"]])
        assert (score["true_positive"], score["false_positive"], score["false_negative"], score["true_negative"]) == (8, 0, 0, 86)
        assert len(report["alerts"]) == len(report["incidents"]) == 8
        assert {a["subtype"] for a in uploaded["alerts"]} == {a["subtype"] for a in report["alerts"]}
        assert report["quality"]["records_accepted"] == 452 and report["quality"]["records_rejected"] == 0
        assert report["quality"]["status"] == "healthy"
        upload_score = score_ground_truth(records, [alert_from_dict(item) for item in uploaded["alerts"]])
        assert len(uploaded["alerts"]) == len(uploaded["incidents"]) == 8
        assert uploaded["quality"]["records_accepted"] == 452 and uploaded["quality"]["records_rejected"] == 0
        assert uploaded["quality"]["status"] == "healthy"
        assert uploaded["quality"]["out_of_order_records"] == 0
        assert uploaded["quality"]["duplicate_uid_count"] == 0
        assert (upload_score["true_positive"], upload_score["false_positive"],
                upload_score["false_negative"], upload_score["true_negative"]) == (8, 0, 0, 86)
        # Reopen without consuming input; then append one explicitly benign new identity.
        started = time.perf_counter()
        with ContinuousIngestor(source, root / "restored/journal.db", factory, repository=restored) as worker:
            recovered = worker.recovered_records
            assert recovered == 452
            extra = {"ts": 2000000000, "uid": "S17-BENIGN-TAIL", "proto": "tcp", "conn_state": "SF",
                     "id.orig_h": "192.0.2.210", "id.resp_h": "198.51.100.210", "id.orig_p": 40000,
                     "id.resp_p": 443, "orig_bytes": 1000, "resp_bytes": 1000, "duration": 1}
            with source.open("ab") as producer:
                producer.write((json.dumps(extra) + "\n").encode())
            continued = worker.poll()
        resume_ms = (time.perf_counter() - started) * 1000
        assert continued["quality"]["records_accepted"] == 453 and continued["quality"]["status"] == "healthy"
        assert len(continued["alerts"]) == 8
        assert restored.get_incident(incident)["status"] == "investigating"
        assert fixture.read_bytes() == raw
        return {"experiment": "sprint17-signed-coordinated-cut-api-recovery-v1", "passed": True,
                "engine_sha256": _engine_digest(), "fixture_sha256": sha256(raw).hexdigest(),
                "records_at_cut": 452, "recovered_records": recovered, "accepted_after_explicit_append": 453,
                "findings": 8, "incidents": 8, "quality": report["quality"], "evaluation": score,
                "upload_analysis": {"findings": len(uploaded["alerts"]), "incidents": len(uploaded["incidents"]),
                                    "quality": uploaded["quality"], "evaluation": upload_score},
                "gates": {"source_journal_analyst_unchanged_by_backup": True, "same_engine_check": True,
                          "exact_authenticated_api_readback": True, "upload_analysis_parity": True,
                          "review_feedback_hold_preserved": True, "selected_head_exact": True,
                          "later_review_not_silently_merged": True, "resume_without_duplicate_records": True,
                          "original_fixture_unchanged": True},
                "measurement_ms": {"backup": round(backup_ms, 3), "restore": round(restore_ms, 3),
                                   "reconstruct_and_append": round(resume_ms, 3)},
                "limitations": ["Finite synthetic same-engine drill, not cross-version migration or production RTO",
                                "ASGI TestClient runs auth/API code, not TCP/TLS/browser transport",
                                "Original source path/inode required; no relocation, rotation or source disaster restore",
                                "Chosen cut excludes later reviews; manual reconciliation/cutover required",
                                "No production data, external network access, key export or live service changes"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-output", type=Path, required=True)
    args = parser.parse_args()
    if args.report_output.exists():
        parser.error("Choose a new report filename")
    result = check()
    with args.report_output.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps(result, indent=2, sort_keys=True))
