"""Finite single-thread hotspot diagnostic; never a sustained throughput claim."""
import argparse
import cProfile
import json
from pathlib import Path
import pstats
import secrets
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aegisflow.analysis_session import AnalysisSession, DEPLOYMENT_BASELINE
from aegisflow.audited_store import AuditedIncidentRepository
from aegisflow.continuous_ingestion import ContinuousIngestor, StreamLimits, _engine_digest
from check_sustained_ingestion import LoadConfig, workload


def profile_stream(records=10000):
    if type(records) is not int or not 1 <= records <= 20000:
        raise ValueError("Diagnostic requires 1..20000 records")
    raw = b"".join(json.dumps(r).encode() + b"\n" for r in workload(LoadConfig(rate=1000, seconds=records / 1000)))
    with tempfile.TemporaryDirectory(prefix="drastha-profile-") as folder:
        root = Path(folder)
        source = root / "sensor.jsonl"
        source.write_bytes(raw)
        repository = AuditedIncidentRepository(root / "analyst.db", secrets.token_bytes(32))
        profiler = cProfile.Profile()
        started = time.perf_counter()
        with profiler, ContinuousIngestor(source, root / "journal.db", lambda: AnalysisSession(DEPLOYMENT_BASELINE),
                limits=StreamLimits(batch_records=64), repository=repository) as worker:
            while True:
                report = worker.poll()
                persisted = repository.get_analysis_run(report["run_id"])
                if persisted != json.loads(json.dumps(report)):
                    raise RuntimeError("Analyst readback differs")
                if not report["stream"]["backlog_bytes"]:
                    break
        elapsed = time.perf_counter() - started
        stats = pstats.Stats(profiler)
        names = {"poll", "_publish", "_verify_source", "_consume", "snapshot", "verify_connection",
                 "__enter__", "__exit__", "import_records", "project_analysis_run", "save_analysis_run"}
        rows = [{"file": Path(file).name, "function": name, "calls": data[1],
                 "self_seconds": data[2], "cumulative_seconds": data[3]}
                for (file, line, name), data in stats.stats.items() if name in names and "aegisflow" in file]
        return {"experiment": "finite-signed-hotspot-profile-v1", "records": records,
                "engine_sha256": _engine_digest(), "elapsed_with_profiler_seconds": elapsed,
                "quality": report["quality"], "findings": len(report["alerts"]),
                "functions": sorted(rows, key=lambda row: row["cumulative_seconds"], reverse=True),
                "limitations": ["cProfile changes timings; cumulative values overlap and must not be added",
                                "Preloaded finite conn workload and direct repository readback, not paced load/API/TLS",
                                "Full integrity/source checks enabled; no result is a capacity certification"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=10000)
    parser.add_argument("--report-output", type=Path, required=True)
    args = parser.parse_args()
    if args.report_output.exists():
        parser.error("Choose a new report filename")
    report = profile_stream(args.records)
    with args.report_output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(json.dumps(report, indent=2))
