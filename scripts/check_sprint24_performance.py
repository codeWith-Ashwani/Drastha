"""Verify immutable Sprint 24 mixed-protocol sustained-load evidence."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "passing_50rps": ("sprint24_signed_mixed_50rps_60s.json", "114808308d5f827e0c206f050ac2a35d8753b6565f339682879316307e53cff5"),
    "failed_100rps_initial": ("sprint24_signed_mixed_100rps_60s_attempt1_failed.json", "676e62b5126e003393195b379cc2e6cf59b066513ec365f2fa32f4ce9ddf0e48"),
    "failed_100rps_fair_boundary": ("sprint24_signed_mixed_100rps_60s_attempt2_failed.json", "8dd6f5370ac784b0b734b2abc7d40efd0edb2de2ce691e0698418c7ccb5a2074"),
}


def _read(root: Path, descriptor: tuple[str, str]) -> dict:
    name, expected = descriptor
    raw = (root / "output" / name).read_bytes()
    if sha256(raw).hexdigest() != expected:
        raise ValueError(f"Sprint 24 evidence checksum mismatch: {name}")
    return json.loads(raw)


def audit(root: Path = ROOT) -> dict:
    root = root.resolve()
    reports = {name: _read(root, descriptor) for name, descriptor in FILES.items()}
    passed = reports["passing_50rps"]
    failed = [reports["failed_100rps_initial"], reports["failed_100rps_fair_boundary"]]
    counts = passed["feature_coverage"]["normalized_event_counts"]
    gates = {
        "passing_report_is_60_seconds": passed["config"]["seconds"] == 60,
        "signed_store_exercised": passed["config"]["signed"] is True,
        "fifty_records_per_second_demonstrated": passed["config"]["rate"] == 50 and passed["sustained_target_demonstrated"] is True,
        "all_passing_gates_true": passed["passed"] is True and all(passed["gates"].values()),
        "all_3000_records_observed": passed["emitted"] == passed["api_observed"] == 3000 and passed["unobserved"] == 0,
        "mixed_protocol_counts_exact": counts == {"connection": 2400, "dns": 600, "encrypted": 300},
        "healthy_zero_rejection": passed["quality"]["status"] == "healthy" and passed["quality"]["records_rejected"] == 0,
        "zero_final_backlog": passed["final_backlog_records"] == 0,
        "source_preserved": passed["gates"]["source_bytes_preserved"] is True,
        "explicit_boundary_applied": passed["gates"]["network_boundary_applied"] is True,
        "failed_100rps_runs_remain_failed": all(item["passed"] is False and item["config"]["rate"] == 100 for item in failed),
        "failure_reason_not_hidden": all(item["gates"]["producer_kept_schedule"] is False for item in failed),
    }
    return {
        "schema_version": "drastha-sprint24-performance-audit-v1",
        "passed": all(gates.values()),
        "gates": gates,
        "demonstrated_target": {
            "records_per_second": 50,
            "duration_seconds": 60,
            "records": 3000,
            "record_mix": counts,
            "visibility_p95_ms": passed["write_to_api_observation_ms"]["p95"],
            "producer_lag_max_ms": passed["producer_scheduling_lag_ms"]["max"],
            "peak_rss_mib": passed["sampled_peak_rss_mib"],
            "peak_disk_mib": passed["sampled_peak_disk_mib"],
            "max_backlog_records": passed["max_sampled_backlog_records"],
        },
        "undemonstrated_target": {
            "records_per_second": 100,
            "attempts": 2,
            "reason": "producer max scheduling lag exceeded the strict 100 ms gate",
            "records_observed_each_attempt": [item["api_observed"] for item in failed],
            "producer_lag_max_ms": [item["producer_scheduling_lag_ms"]["max"] for item in failed],
        },
        "evidence_sha256": {name: descriptor[1] for name, descriptor in FILES.items()},
        "production_ready": False,
        "limitations": passed["limitations"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    report = audit(args.repo_root)
    output = args.report_output or args.repo_root / "output" / "sprint24_performance_audit.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "demonstrated": report["demonstrated_target"],
                      "report": str(output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
