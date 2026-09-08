"""Audit and execute the immutable SIH-26145 lab corpus."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from aegisflow.benchmark import load_corpus, run_benchmark  # noqa: E402
from build_sih_lab_corpus import VERSION, REQUIRED, build, scenarios  # noqa: E402


EXPECTED_BASELINE = {"tp": 9, "fp": 3, "fn": 0, "tn": 2}
CONTEXT_TARGETS = {
    "benign-health-control": "periodic_beacon",
    "benign-backup-control": "outbound_volume_anomaly",
    "authorized-scanner-control": "vertical_port_scan",
}


def audit(repo_root: Path) -> dict:
    repo_root = repo_root.resolve()
    data_root = repo_root / "data"
    manifest_path = data_root / "manifests" / f"{VERSION}.json"
    generated = build(repo_root)
    reproducible = all(path.is_file() and path.read_bytes() == payload for path, payload in generated.items())
    manifest, manifest_digest, loaded = load_corpus(manifest_path, data_root)
    benchmark = run_benchmark(manifest_path, data_root=data_root, split="test")

    total_records = 0
    timestamp_regressions = 0
    missing_required = 0
    duplicate_uids = 0
    leaked_truth_fields = 0
    seen_uids: set[str] = set()
    truth_tokens = {"evaluation_label", "evaluation_threat_class", "evaluation_id",
                    "ml_evidence", "expected_classes", "label"}
    for entry, prepared, _units, _details in loaded:
        rows = prepared.accepted_records
        total_records += len(rows)
        timestamps = [float(row["ts"]) for row in rows]
        timestamp_regressions += sum(right < left for left, right in zip(timestamps, timestamps[1:]))
        for row in rows:
            missing_required += sum(field not in row for field in REQUIRED)
            uid = row["uid"]
            duplicate_uids += uid in seen_uids
            seen_uids.add(uid)
            leaked_truth_fields += len(set(row) & truth_tokens)

    sensor = manifest["sensor_anchor"]
    sensor_path = repo_root / sensor["path"]
    sensor_payload = sensor_path.read_bytes()
    sensor_report = json.loads(sensor_payload)
    anchor_valid = (sha256(sensor_payload).hexdigest() == sensor["sha256"] and
                    sensor_report.get("passed") is True and
                    all(sensor_report.get("gates", {}).get(name) is True for name in
                        ("zeek_dns_log_observed", "zeek_tls_log_observed", "connections_present")))
    pooled = benchmark["pooled_binary_alert_coverage"]
    baseline = {name: pooled[name] for name in EXPECTED_BASELINE}
    run_map = {run["artifact_id"]: run for run in benchmark["runs"]}
    contextual_targets_visible = all(
        run_map[name]["observed_subtypes"].get(subtype) == 1
        and run_map[name]["scores"]["binary_alert_coverage"]["fp"] == 1
        for name, subtype in CONTEXT_TARGETS.items()
    )
    slow_http_covered = (
        run_map["slow-http-exhaustion"]["observed_subtypes"].get(
            "slow_http_connection_exhaustion"
        ) == 1
    )
    quality_healthy = all(run["quality"]["status"] == "healthy" and
                          run["quality"]["records_rejected"] == 0 and
                          run["quality"]["out_of_order_records"] == 0
                          for run in benchmark["runs"])
    gates = {
        "deterministic_files_match_generator": reproducible,
        "thirteen_isolated_scenarios": len(loaded) == len(scenarios()) == 13,
        "all_quality_healthy": quality_healthy,
        "zero_timestamp_regressions": timestamp_regressions == 0,
        "zero_missing_required_fields": missing_required == 0,
        "zero_duplicate_uids": duplicate_uids == 0,
        "ground_truth_is_sidecar_only": leaked_truth_fields == 0 and manifest["safety"]["ground_truth_in_telemetry"] is False,
        "no_active_attack_execution": manifest["safety"]["active_network_transmission"] is False and manifest["safety"]["attack_tools_executed"] is False,
        "no_payload_decryption": manifest["safety"]["payload_decryption"] is False,
        "real_zeek_sensor_anchor_valid": anchor_valid,
        "nine_supported_attacks_detected": baseline["tp"] == 9,
        "slow_http_gap_closed": slow_http_covered,
        "three_context_hardening_targets_exposed": contextual_targets_visible,
        "baseline_metrics_unchanged": baseline == EXPECTED_BASELINE,
    }
    return {"schema_version": "drastha-sih-lab-audit-v1", "corpus_id": manifest["corpus_id"],
            "manifest_sha256": manifest_digest, "passed": all(gates.values()), "gates": gates,
            "integrity": {"artifacts": len(loaded), "records": total_records,
                          "timestamp_regressions": timestamp_regressions,
                          "missing_required_fields": missing_required,
                          "duplicate_uids": duplicate_uids,
                          "truth_fields_in_telemetry": leaked_truth_fields},
            "sensor_anchor": {"valid": anchor_valid, "experiment": sensor_report.get("experiment"),
                              "pcap_sha256": sensor_report.get("pcap_sha256")},
            "baseline": {"metrics": pooled, "expected_counts": EXPECTED_BASELINE,
                         "interpretation": "Three policy-context controls remain visible without operator context; Sprint 22 closes the Slow HTTP metadata coverage gap."},
            "benchmark": benchmark}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    report = audit(args.repo_root)
    output = args.report_output or args.repo_root / "output" / "sprint20_lab_corpus_audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "records": report["integrity"]["records"],
                      "metrics": report["baseline"]["expected_counts"], "report": str(output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
