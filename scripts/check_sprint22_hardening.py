"""Reproduce Sprint 22 context hardening through the shared benchmark path."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.benchmark import run_benchmark  # noqa: E402
from aegisflow.context_policy import load_context_policy_file  # noqa: E402


POLICY_SHA256 = "222973548e6cebe123b5901b9333b91e731eb8e836a51949dd6240b22c154cf7"
EXPECTED_WITHOUT_CONTEXT = {"tp": 9, "fp": 3, "fn": 0, "tn": 2}
EXPECTED_WITH_CONTEXT = {"tp": 9, "fp": 0, "fn": 0, "tn": 5}


def _counts(report: dict) -> dict:
    return {name: report["pooled_binary_alert_coverage"][name] for name in ("tp", "fp", "fn", "tn")}


def audit(root: Path = ROOT) -> dict:
    root = root.resolve()
    manifest = root / "data" / "manifests" / "sih26145-lab-v1.json"
    policy_path = root / "config" / "sih26145_lab_context_policy.json"
    payload = policy_path.read_bytes()
    policy_digest = sha256(payload).hexdigest()
    if policy_digest != POLICY_SHA256:
        raise ValueError("Sprint 22 context policy checksum mismatch")
    policy = load_context_policy_file(policy_path)
    baseline = run_benchmark(manifest, data_root=root / "data")
    hardened = run_benchmark(manifest, data_root=root / "data", context_policy=policy)
    baseline_counts, hardened_counts = _counts(baseline), _counts(hardened)
    runs = {item["artifact_id"]: item for item in hardened["runs"]}
    benign = ("benign-load-control", "benign-health-control", "benign-backup-control",
              "authorized-scanner-control")
    attacks = ("syn-flood", "udp-reflection-amplification", "slow-http-exhaustion",
               "c2-beacon", "dga-domains", "dns-tunnel", "encrypted-session-anomaly",
               "reconnaissance", "data-exfiltration")
    suppressed = {
        name: runs[name]["context_policy"]["suppressed_by_detector"]
        for name in ("benign-health-control", "benign-backup-control", "authorized-scanner-control")
    }
    expected_suppression = {
        "benign-health-control": {"command_and_control": 8, "data_exfiltration": 0, "reconnaissance": 0},
        "benign-backup-control": {"command_and_control": 0, "data_exfiltration": 3, "reconnaissance": 0},
        "authorized-scanner-control": {"command_and_control": 0, "data_exfiltration": 0, "reconnaissance": 22},
    }
    gates = {
        "policy_checksum_pinned": policy_digest == POLICY_SHA256,
        "empty_context_baseline_reproduced": baseline_counts == EXPECTED_WITHOUT_CONTEXT,
        "hardened_metrics_reproduced": hardened_counts == EXPECTED_WITH_CONTEXT,
        "all_benign_controls_remain_benign": all(
            runs[name]["scores"]["binary_alert_coverage"]["tn"] >= 1 for name in benign
        ),
        "all_nine_attack_controls_detected": all(
            runs[name]["scores"]["binary_alert_coverage"]["tp"] >= 1 for name in attacks
        ),
        "slow_http_specific_subtype": runs["slow-http-exhaustion"]["observed_subtypes"] == {
            "slow_http_connection_exhaustion": 1
        },
        "only_expected_context_records_suppressed": suppressed == expected_suppression,
        "all_quality_healthy": all(
            run["quality"]["status"] == "healthy"
            and run["quality"]["records_rejected"] == 0 for run in hardened["runs"]
        ),
        "no_threshold_selection_on_test": hardened["threshold_selection_performed"] is False,
    }
    return {
        "schema_version": "drastha-sprint22-hardening-v1",
        "passed": all(gates.values()),
        "gates": gates,
        "policy": {"path": "config/sih26145_lab_context_policy.json", "sha256": policy_digest,
                   "rules": hardened["context_policy"]},
        "before_context": baseline_counts,
        "after_context": hardened_counts,
        "suppressed_records": suppressed,
        "hardened_benchmark": hardened,
        "limitations": [
            "This deterministic lab corpus is small and is not a production accuracy claim.",
            "Operator context must be independently governed; an incorrect allowlist can suppress real attacks.",
            "Slow HTTP classification is behavioural and cannot identify a particular attack tool.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    report = audit(args.repo_root)
    output = args.report_output or args.repo_root / "output" / "sprint22_hardening_audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "before": report["before_context"],
                      "after": report["after_context"], "report": str(output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
