"""Repeatable finite Sprint 12 smoke measurement; never uses the live analyst DB."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient
from aegisflow.analysis_session import AnalysisSession, UPLOAD_DEMO
from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository
from aegisflow.continuous_ingestion import ContinuousIngestor, StreamLimits
from aegisflow.evaluation_scoring import score_ground_truth
from aegisflow.incidents import alert_from_dict


def check():
    fixture = ROOT / "examples/drastha_mixed_evaluation_v3.jsonl"
    raw = fixture.read_bytes()
    lines = raw.splitlines(keepends=True)
    latencies = []
    limits = StreamLimits(batch_records=17)
    factory = lambda: AnalysisSession.from_root(ROOT, UPLOAD_DEMO)
    with tempfile.TemporaryDirectory(prefix="drastha-sprint12-") as folder:
        root = Path(folder)
        source, checkpoint = root / "sensor.jsonl", root / "journal.db"
        source.write_bytes(b"")
        repository = IncidentRepository(root / "analyst.db")

        def drain(worker):
            while True:
                tick = time.perf_counter()
                result = worker.poll()
                latencies.append((time.perf_counter() - tick) * 1000)
                if not result["stream"]["backlog_bytes"]:
                    return result

        started = time.perf_counter()
        with ContinuousIngestor(source, checkpoint, factory, limits=limits, repository=repository) as worker:
            with source.open("ab") as producer:  # Simulated local sensor, NOT the read-only worker.
                producer.write(b"".join(lines[:47]))
            drain(worker)
        recovery_start = time.perf_counter()
        with ContinuousIngestor(source, checkpoint, factory, limits=limits, repository=repository) as worker:
            recovery_ms = (time.perf_counter() - recovery_start) * 1000
            recovered = worker.recovered_records
            for start in range(47, len(lines), 35):
                with source.open("ab") as producer:
                    producer.write(b"".join(lines[start:start + 35]))
                report = drain(worker)
        elapsed = time.perf_counter() - started
        score = score_ground_truth([json.loads(line) for line in lines],
                                   [alert_from_dict(a) for a in report["alerts"]])
        with TestClient(create_app(repository)) as client:
            persisted = client.get("/api/analysis-runs/" + report["run_id"])
            assert persisted.status_code == 200
            assert persisted.json()["quality"] == report["quality"]
            assert len(client.get("/api/incidents").json()) == 8
        with TestClient(create_app(IncidentRepository(root / "upload.db"))) as client:
            response = client.post("/api/replays/analyse", json={"filename": fixture.name, "content": raw.decode()})
            assert response.status_code == 200, response.text
            upload = response.json()
        assert source.read_bytes() == raw
        assert fixture.read_bytes() == raw
        assert report["quality"]["records_accepted"] == 452
        assert report["quality"]["records_rejected"] == 0
        assert report["quality"]["status"] == "healthy"
        assert len(report["alerts"]) == len(report["incidents"]) == 8
        assert {a["subtype"] for a in report["alerts"]} == {a["subtype"] for a in upload["alerts"]}
        assert (score["true_positive"], score["false_positive"], score["false_negative"], score["true_negative"]) == (8, 0, 0, 86)
        ordered = sorted(latencies)
        return {"experiment": "sprint12-finite-append-restart-sqlite-http-v1",
                "fixture_sha256": sha256(raw).hexdigest(), "fixture_records": len(lines),
                "quality": report["quality"], "findings": len(report["alerts"]),
                "incidents": len(report["incidents"]), "evaluation": score,
                "recovered_records": recovered, "queue_high_watermark": report["stream"]["queue_high_watermark"],
                "upload_http_parity": True, "analyst_api_readback": True,
                "source_bytes_unchanged": True, "profile": report["analysis_provenance"]["profile"],
                "measurement": {"elapsed_seconds": round(elapsed, 4),
                                "records_per_second": round(len(lines) / elapsed, 2),
                                "recovery_ms": round(recovery_ms, 3),
                                "poll_p50_ms": round(statistics.median(latencies), 3),
                                "poll_p95_ms": round(ordered[min(len(ordered) - 1, int(.95 * len(ordered)))], 3),
                                "poll_count": len(latencies)},
                "limitations": ["Finite 452-record synthetic smoke run, not sustained throughput or a capacity guarantee",
                                "Elapsed includes local appends, startup, one recovery, inference, durable journal and analyst projection",
                                "Post-run HTTP comparison/evaluation excluded from elapsed time",
                                "Polling duration is not packet-to-alert latency; no production source timestamps or live sensor tested",
                                "Unbounded retention/state compaction, rotation handoff and long-run capacity remain open"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    if args.report_output and args.report_output.exists():
        parser.error("Report is create-only; choose a new filename")
    result = check()
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        with args.report_output.open("x", encoding="utf-8") as output:
            output.write(rendered + "\n")
    print(rendered)
