from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.upload_analysis import analyse_uploaded_replay


class _Repository:
    def import_records(self, incidents, alerts, feedback=None):
        return {"incidents": len(incidents), "alerts": len(alerts), "feedback": 0}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evidence(alert: dict) -> dict[str, object]:
    return {item["name"]: item["observed"] for item in alert["evidence"]}


def build_report() -> dict:
    manifest_path = ROOT / "data/manifests/sih26145-real-tools-v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixture_info = manifest["derived_fixture"]
    fixture = ROOT / fixture_info["path"]
    if digest(fixture) != fixture_info["sha256"]:
        raise SystemExit("Committed Sprint 34 fixture checksum mismatch")

    rows = [json.loads(line) for line in fixture.read_text(encoding="utf-8").splitlines() if line]
    if any(any(key.startswith("evaluation_") for key in row) or "ml_evidence" in row for row in rows):
        raise SystemExit("Real-tool evidence must not contain evaluation labels or injected ML evidence")
    sources = Counter(str(row.get("_drastha_source", "")) for row in rows)
    expected_sources = {
        "zeek:sprint34:conn": 79,
        "zeek:sprint34:dns": 52,
        "zeek:sprint34:benign-health": 10,
    }
    if dict(sources) != expected_sources:
        raise SystemExit(f"Unexpected Sprint 34 source counts: {sources}")

    result = analyse_uploaded_replay(fixture.name, fixture.read_text(encoding="utf-8"), _Repository())
    quality = result["quality"]
    expected = manifest["expected_upload_result"]
    quality_checks = {
        "records_accepted": quality["records_accepted"] == expected["records_accepted"],
        "records_rejected": quality["records_rejected"] == expected["records_rejected"],
        "out_of_order_records": quality["out_of_order_records"] == expected["out_of_order_records"],
        "duplicate_uid_count": quality["duplicate_uid_count"] == expected["duplicate_uid_count"],
        "quality_healthy": quality["status"] == expected["quality"],
    }
    alerts = {item["subtype"]: item for item in result["alerts"]}
    expected_subtypes = set(expected["subtypes"])
    if set(alerts) != expected_subtypes:
        raise SystemExit(f"Unexpected Sprint 34 detections: {sorted(alerts)}")
    benign_alerts = [item for item in result["alerts"] if item["src_ip"] == "10.34.1.2"]
    alert_checks = {
        "exact_subtypes": set(alerts) == expected_subtypes,
        "benign_health_remains_benign": not benign_alerts,
        "incident_count": len(result["incidents"]) == expected["incidents"],
        "slow_http_measured": evidence(alerts["slow_http_connection_exhaustion"])["minimum_connection_duration_seconds"] >= 120,
        "c2_periodicity_measured": evidence(alerts["periodic_beacon"])["connection_count"] == 11,
        "iodine_txt_tunnel_measured": evidence(alerts["dns_tunnelling"])["txt_query_ratio"] == 1.0,
    }
    if not all([*quality_checks.values(), *alert_checks.values()]):
        raise SystemExit(f"Sprint 34 acceptance failed: {quality_checks=}, {alert_checks=}")

    raw_checks = {}
    for item in manifest["raw_local_evidence"]:
        path = ROOT / item["path"]
        raw_checks[item["path"]] = {
            "available": path.is_file(),
            "checksum_matches": path.is_file() and digest(path) == item["sha256"],
            "committed": item["committed"],
        }

    return {
        "schema_version": "drastha-sprint34-real-tools-audit-v1",
        "passed": True,
        "manifest": str(manifest_path.relative_to(ROOT)).replace("\\", "/"),
        "manifest_sha256": digest(manifest_path),
        "fixture_sha256": digest(fixture),
        "quality": quality,
        "telemetry": result["telemetry"],
        "source_counts": dict(sources),
        "detections": [
            {
                "subtype": item["subtype"],
                "threat_class": item["threat_class"],
                "confidence": item["confidence"],
                "source": item["src_ip"],
                "evidence": evidence(item),
            }
            for item in result["alerts"]
        ],
        "incidents": len(result["incidents"]),
        "quality_checks": quality_checks,
        "alert_checks": alert_checks,
        "raw_local_evidence": raw_checks,
        "claims": {
            "actual_slowhttptest_slowloris_mode": True,
            "actual_iodine_tunnel_with_ping": True,
            "deterministic_sandboxed_c2_timing_emulator": True,
            "actual_jittered_health_control": True,
            "production_accuracy": False,
            "malware_family_c2_emulation": False,
        },
        "limitations": manifest["limitations"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Sprint 34 real-tool evidence")
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    report = build_report()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report_output:
        path = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
        path.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
