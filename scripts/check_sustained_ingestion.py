"""Paced, bounded synthetic load through the real worker, SQLite and analyst API.

Run each experiment in a fresh process. This is a measurement harness, not a
production capacity claim. TestClient exercises ASGI, not TCP/TLS or rendering.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import secrets
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.analysis_session import AnalysisSession, DEPLOYMENT_BASELINE
from aegisflow.api_store import IncidentRepository
from aegisflow.audited_store import AuditedIncidentRepository
from aegisflow.continuous_ingestion import ContinuousIngestor, StreamLimits
from aegisflow.security import AccessSettings, Credential


@dataclass(frozen=True)
class LoadConfig:
    rate: int = 100
    seconds: float = 60
    batch_records: int = 64
    signed: bool = False
    drain_seconds: float = 30
    latency_budget_ms: float = 1000
    producer_lag_budget_ms: float = 100
    rss_budget_mib: float = 512
    disk_budget_mib: float = 512
    protocol_mix: str = "conn"

    def __post_init__(self):
        if type(self.rate) is not int or not 1 <= self.rate <= 5000:
            raise ValueError("rate must be an integer in [1, 5000]")
        for name in ("seconds", "drain_seconds", "latency_budget_ms", "producer_lag_budget_ms",
                     "rss_budget_mib", "disk_budget_mib"):
            value = getattr(self, name)
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        if self.seconds > 300 or self.drain_seconds > 120 or not 1 <= self.records <= 100_000:
            raise ValueError("Bounded run: <=300 seconds, <=120 seconds drain, 1..100000 records")
        StreamLimits(batch_records=self.batch_records)
        if self.protocol_mix not in {"conn", "mixed"}:
            raise ValueError("protocol_mix must be conn or mixed")

    @property
    def records(self):
        return int(self.rate * self.seconds)


def distribution(values):
    """Nearest-rank quantiles; missing observations never become zero latency."""
    ordered = sorted(values)
    if not ordered:
        return {"count": 0, "p50": None, "p95": None, "max": None}
    return {"count": len(ordered), "p50": ordered[math.ceil(.5 * len(ordered)) - 1],
            "p95": ordered[math.ceil(.95 * len(ordered)) - 1], "max": ordered[-1]}


def resident_bytes():
    """Current process RSS/working set, including producer and ASGI threads."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        *[(name, ctypes.c_size_t) for name in (
                            "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                            "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                            "PagefileUsage", "PeakPagefileUsage")]]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")
        return counters.WorkingSetSize
    if sys.platform.startswith("linux"):
        return int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    raise RuntimeError("RSS measurement currently supports Windows and Linux only")


def _connection_record(config, index):
    scan = index % 10 == 0
    return {"ts": 1_788_336_000 + index / config.rate, "uid": f"LOAD{index:08d}",
               "id.orig_h": "192.0.2.250" if scan else f"192.0.2.{1 + index % 32}",
               "id.resp_h": "198.51.100.250" if scan else f"198.51.100.{1 + (index // 32) % 16}",
               "id.orig_p": 40000 + index % 20000,
               "id.resp_p": 1000 + (index // 10) % 256 if scan else 443,
               "proto": "tcp", "conn_state": "S0" if scan else "SF",
               "duration": 0 if scan else .1 + (index % 7) / 100,
               "orig_bytes": 0 if scan else 500 + index % 701,
               "resp_bytes": 0 if scan else 1500 + index % 1601,
               "orig_pkts": 1 if scan else 5, "resp_pkts": 0 if scan else 8}


def workload(config):
    """Deterministic telemetry load with no labels or supplied detector scores."""
    for index in range(config.records):
        if config.protocol_mix != "mixed":
            yield _connection_record(config, index)
            continue
        kind = index % 10
        timestamp = 1_788_336_000 + index / config.rate
        if kind in {0, 1}:
            yield {
                "ts": timestamp, "uid": f"DNSLOAD{index:08d}",
                "id.orig_h": f"10.40.0.{1 + index % 200}", "id.resp_h": "10.40.0.53",
                "id.orig_p": 53000 + index % 1000, "id.resp_p": 53, "proto": "udp",
                "query": f"node-{index}.service-{index % 100}.example",
                "qtype_name": "A", "rcode_name": "NOERROR", "answers": ["198.51.100.8"],
            }
        elif kind == 2:
            row = _connection_record(config, index)
            row["id.orig_h"] = f"10.50.0.{1 + index % 200}"
            row.update({
                "uid": f"TLSLOAD{index:08d}", "service": "ssl", "transport": "tls",
                "ja4": f"t13d1516h2_{index % 20:02d}", "server_name": f"service-{index % 50}.example",
                "version": "TLSv13", "cipher": "TLS_AES_128_GCM_SHA256",
                "next_protocol": "h2", "established": True,
                "packet_observations": [
                    {"ts": timestamp - .003 + position * .001, "ip_bytes": size,
                     "direction": "orig" if position % 2 == 0 else "resp"}
                    for position, size in enumerate((120, 1400, 90, 1100))
                ],
            })
            yield row
        else:
            row = _connection_record(config, index)
            row["id.orig_h"] = (
                "10.50.0.250" if index % 10 == 0 else f"10.50.0.{1 + index % 200}"
            )
            yield row


@contextmanager
def fair_thread_scheduling(interval_seconds=.001):
    """Scope a shorter GIL switch interval to the same-process load harness."""
    previous = sys.getswitchinterval()
    sys.setswitchinterval(interval_seconds)
    try:
        yield
    finally:
        sys.setswitchinterval(previous)


@contextmanager
def isolated_api(directory):
    # api.py creates a default app on first import. Prevent that import from
    # opening an operator's configured DB/key; restore environment before work.
    names = ("DRASTHA_DB", "AEGISFLOW_DB", "DRASTHA_AUTH_MODE", "DRASTHA_AUTH_FILE", "DRASTHA_AUDIT_KEY_FILE")
    previous = {name: os.environ.get(name) for name in names}
    try:
        for name in names:
            os.environ.pop(name, None)
        os.environ["DRASTHA_DB"] = str(directory / "bootstrap.db")
        from aegisflow.api import create_app
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    yield create_app


def assess(config, *, emitted, observed, quality, lag, latency, rss, disk, errors, source_matches):
    """Do not award a passing rate for drained-only, lost or unobserved traffic."""
    gates = {
        "all_offered_records_emitted": emitted == config.records,
        "all_records_api_observed": observed == config.records,
        "no_rejections_healthy": quality.get("records_accepted") == config.records
            and quality.get("records_rejected") == 0 and quality.get("status") == "healthy",
        "producer_kept_schedule": lag["count"] == config.records
            and lag["max"] is not None and lag["max"] <= config.producer_lag_budget_ms,
        "api_visibility_p95_within_budget": latency["count"] == config.records
            and latency["p95"] is not None and latency["p95"] <= config.latency_budget_ms,
        "rss_within_budget": rss <= config.rss_budget_mib,
        "disk_within_budget": disk <= config.disk_budget_mib,
        "source_bytes_preserved": source_matches,
        "no_runtime_errors": not errors,
    }
    return gates


def run(config):
    from fastapi.testclient import TestClient
    harness_sha256 = sha256(Path(__file__).read_bytes()).hexdigest()
    recorded_at = datetime.now(timezone.utc).isoformat()
    lines = [json.dumps(record, separators=(",", ":")).encode() + b"\n" for record in workload(config)]
    raw = b"".join(lines)
    with tempfile.TemporaryDirectory(prefix="drastha-load-") as folder:
        directory = Path(folder)
        source = directory / "sensor.jsonl"
        source.touch()
        repo = (AuditedIncidentRepository(directory / "analyst.db", secrets.token_bytes(32))
                if config.signed else IncidentRepository(directory / "analyst.db"))
        token = secrets.token_urlsafe(32)
        access = (AccessSettings("required", (Credential("load-reader", "viewer", sha256(token.encode()).hexdigest(),
                                                        time.time() + 3600),), ())
                  if config.signed else AccessSettings())
        with isolated_api(directory) as create_app:
            app = create_app(repo, access=access)
        limits = StreamLimits(batch_records=config.batch_records, max_journal_records=max(1, config.records),
                              max_journal_bytes=max(1, len(raw)))
        times, lag, latencies, poll_ms, errors, samples = [], [], [], [], [], []
        alert_observations, seen_alerts = [], set()
        stop, done, lock = threading.Event(), threading.Event(), threading.Lock()
        producer_done_at = []
        observed = at_offer_end = max_backlog = 0
        last = {}
        rss_peak = resident_bytes() / 2**20
        disk_peak = 0
        started = cpu_start = 0.0

        def produce():
            try:
                with source.open("ab", buffering=0) as stream:
                    for index, line in enumerate(lines):
                        due = started + index / config.rate
                        if stop.wait(max(0, due - time.perf_counter())):
                            break
                        now = time.perf_counter()
                        # The offer window remains fixed. Permit only the stated
                        # scheduling-lag budget at the tail (e.g. OS timer jitter);
                        # expose the overrun and never move the measurement window.
                        if now > started + config.seconds + min(config.drain_seconds, config.producer_lag_budget_ms / 1000):
                            break
                        with lock:
                            stream.write(line)
                            times.append(now)
                            lag.append((now - due) * 1000)
            except Exception as exc:
                errors.append(f"producer: {type(exc).__name__}: {exc}")
            finally:
                producer_done_at.append(time.perf_counter())
                done.set()

        load_profile = (
            replace(DEPLOYMENT_BASELINE, name="sprint24-mixed-load-v1", internal_cidrs=("10.0.0.0/8",))
            if config.protocol_mix == "mixed" else DEPLOYMENT_BASELINE
        )
        with fair_thread_scheduling(), TestClient(
            app, base_url="https://load.test", headers={"Authorization": "Bearer " + token}
        ) as client:
            with ContinuousIngestor(source, directory / "journal.db", lambda: AnalysisSession(load_profile),
                                    limits=limits, repository=repo) as worker:
                cpu_start, started = time.process_time(), time.perf_counter()
                producer = threading.Thread(target=produce, name="paced-sensor", daemon=True)
                producer.start()
                try:
                    while True:
                        tick = time.perf_counter()
                        if tick > started + config.seconds + config.drain_seconds:
                            errors.append("drain deadline exceeded")
                            break
                        last = worker.poll()
                        poll_ms.append((time.perf_counter() - tick) * 1000)
                        response = client.get("/api/analysis-runs/" + last["run_id"])
                        response.raise_for_status()
                        persisted = response.json()
                        if persisted != json.loads(json.dumps(last)):
                            raise RuntimeError("API report does not match committed worker snapshot")
                        now = time.perf_counter()
                        committed = persisted["stream"]["committed_lines"]
                        with lock:
                            emitted = len(times)
                            latencies.extend((now - value) * 1000 for value in times[observed:committed])
                            for alert in persisted["alerts"]:
                                if alert["alert_id"] not in seen_alerts:
                                    seen_alerts.add(alert["alert_id"])
                                    supporting = [int(uid[4:]) for uid in alert["flow_ids"] if uid.startswith("LOAD")]
                                    alert_observations.append({
                                        "threat_class": alert["threat_class"], "elapsed_seconds": now - started,
                                        "before_offer_end": now < started + config.seconds,
                                        "latest_supporting_record_to_api_ms":
                                            (now - times[max(supporting)]) * 1000 if supporting else None})
                        observed = committed
                        if now <= started + config.seconds:
                            at_offer_end = observed
                        max_backlog = max(max_backlog, emitted - observed)
                        rss_peak = max(rss_peak, resident_bytes() / 2**20)
                        disk_peak = max(disk_peak, sum(p.stat().st_size for p in directory.iterdir() if p.is_file()) / 2**20)
                        if not samples or now - started >= samples[-1]["elapsed_seconds"] + 1:
                            samples.append({"elapsed_seconds": round(now - started, 3), "emitted": emitted,
                                            "api_observed": observed, "backlog_records": emitted - observed,
                                            "rss_mib": round(resident_bytes() / 2**20, 3)})
                        if rss_peak > config.rss_budget_mib or disk_peak > config.disk_budget_mib:
                            errors.append("resource budget exceeded")
                            break
                        if last["status"] == "capacity_reached":
                            errors.append("worker capacity reached")
                            break
                        if now > started + config.seconds + config.drain_seconds:
                            errors.append("drain deadline exceeded during poll/readback")
                            break
                        if done.is_set() and observed == emitted and now >= started + config.seconds:
                            break
                        if observed == emitted:
                            stop.wait(.01)
                except Exception as exc:
                    errors.append(f"consumer: {type(exc).__name__}: {exc}")
                finally:
                    stop.set()
                    producer.join(timeout=5)
                    if producer.is_alive():
                        raise RuntimeError("Producer did not stop; run cannot be trusted")
                elapsed, cpu_seconds = time.perf_counter() - started, time.process_time() - cpu_start
            try:
                response = client.get("/api/incidents")
                response.raise_for_status()
                incidents = response.json()
                if {item["incident_id"] for item in incidents} != {item["incident_id"] for item in last.get("incidents", [])}:
                    raise RuntimeError("Incident API projection differs from worker snapshot")
                for item in incidents:
                    detail = client.get("/api/incidents/" + item["incident_id"])
                    detail.raise_for_status()
                    if not detail.json().get("alerts"):
                        raise RuntimeError("Incident evidence missing on detail API")
            except Exception as exc:
                errors.append(f"final incident/evidence API verification: {exc}")
            if config.signed:
                try:
                    repo.verify_evidence()
                except Exception as exc:
                    errors.append(f"final integrity verification: {exc}")
        quality = last.get("quality", {})
        latency, scheduling = distribution(latencies), distribution(lag)
        source_matches = source.read_bytes() == raw
        decoded = [json.loads(line) for line in lines]
        kinds = {
            "connection_records": sum("query" not in item for item in decoded),
            "dns_records": sum("query" in item for item in decoded),
            "tls_records": sum("ja4" in item for item in decoded),
        }
        gates = assess(config, emitted=len(times), observed=observed, quality=quality, lag=scheduling,
                       latency=latency, rss=rss_peak, disk=disk_peak, errors=errors, source_matches=source_matches)
        feature_coverage = last.get("feature_coverage", {})
        event_counts = feature_coverage.get("normalized_event_counts", {})
        expected_event_counts = {
            "connection": config.records - kinds["dns_records"],
            "dns": kinds["dns_records"],
            "encrypted": kinds["tls_records"],
        }
        gates["protocol_event_counts_match"] = (
            event_counts == expected_event_counts if config.protocol_mix == "mixed"
            else event_counts.get("connection") == config.records
        )
        gates["network_boundary_applied"] = (
            feature_coverage.get("network_direction_status") == "configured"
            and feature_coverage.get("network_direction_counts", {}).get("outbound") == expected_event_counts["connection"]
            if config.protocol_mix == "mixed" else True
        )
        return {"experiment": "paced-passive-sqlite-asgi-v2", "config": asdict(config),
                "recorded_at": recorded_at, "harness_sha256": harness_sha256,
                "environment": {"platform": platform.platform(), "python": platform.python_version(),
                                "logical_cpus": os.cpu_count(), "harness_thread_switch_interval_seconds": .001},
                "workload": {"name": ("synthetic-70conn-only-20dns-10tls-plus-conn-v1" if config.protocol_mix == "mixed"
                                        else "synthetic-conn-90pct-balanced-10pct-scan-v1"),
                             "sha256": sha256(raw).hexdigest(), "records": config.records,
                             "record_kinds": kinds, "bytes": len(raw)},
                "provenance": last.get("analysis_provenance"), "quality": quality,
                "feature_coverage": feature_coverage,
                "findings": len(last.get("alerts", [])), "incidents": len(last.get("incidents", [])),
                "emitted": len(times), "api_observed": observed, "unobserved": config.records - observed,
                "producer_elapsed_seconds": producer_done_at[0] - started,
                "producer_overrun_seconds": max(0, producer_done_at[0] - started - config.seconds),
                "api_observed_before_offer_end": at_offer_end,
                "offer_window_observed_records_per_second": at_offer_end / config.seconds,
                "completed_records_per_second_including_drain": observed / elapsed,
                "elapsed_seconds": elapsed, "drain_seconds": max(0, elapsed - config.seconds),
                "cpu_seconds": cpu_seconds, "cpu_percent_one_core": 100 * cpu_seconds / elapsed,
                "sampled_peak_rss_mib": rss_peak, "sampled_peak_disk_mib": disk_peak,
                "max_sampled_backlog_records": max_backlog, "final_backlog_records": len(times) - observed,
                "queue_high_watermark": last.get("stream", {}).get("queue_high_watermark"),
                "producer_scheduling_lag_ms": scheduling, "write_to_api_observation_ms": latency,
                "first_alert_observations": alert_observations,
                "worker_poll_ms": distribution(poll_ms), "samples": samples, "gates": gates,
                "passed": all(gates.values()), "sustained_run": config.seconds >= 60,
                "sustained_target_demonstrated": config.seconds >= 60 and all(gates.values()), "errors": errors,
                "limitations": [
                    "Single-process independent paced producer thread; scheduling lag is a release gate",
                    "Fixed offer window; tail timer jitter may use at most the stated scheduling-lag/drain budget, with overrun reported",
                    "Synthetic passive records; not accuracy evaluation, production traffic, PCAP conversion or network throughput",
                    "Write-start to first ASGI readback is an upper-bound visibility observation, not packet-to-alert latency",
                    "First-alert latency starts at latest supporting input record, not the start of the detector observation window",
                    "TestClient runs actual API/auth code but no TCP, TLS handshake, proxy or browser rendering",
                    "RSS/disk/backlog sampled per poll; peaks between samples and transient SQLite sidecars may be higher",
                    "CPU includes producer, worker and API; prepared workload and setup excluded from elapsed, included in RSS",
                    "Final incident/detail readback and final ledger verification are correctness gates outside timed interval",
                    "Deadlines/resource stops checked between bounded polls; not preemptive process limits",
                    "No state resets or disabled quality/integrity checks; finite journal only, not an unlimited-service soak"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rate", type=int, default=100)
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--batch-records", type=int, default=64)
    parser.add_argument("--signed", action="store_true")
    parser.add_argument("--drain-seconds", type=float, default=30)
    parser.add_argument("--latency-budget-ms", type=float, default=1000)
    parser.add_argument("--report-output", type=Path)
    parser.add_argument("--protocol-mix", choices=("conn", "mixed"), default="conn")
    args = parser.parse_args()
    if args.report_output and args.report_output.exists():
        parser.error("Report is create-only; choose a new filename")
    try:
        config = LoadConfig(**{key: value for key, value in vars(args).items() if key != "report_output"})
        report = run(config)
    except ValueError as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2, sort_keys=True, allow_nan=False)
    if args.report_output:
        args.report_output.parent.mkdir(parents=True, exist_ok=True)
        with args.report_output.open("x", encoding="utf-8") as output:
            output.write(rendered + "\n")
    print(rendered)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
