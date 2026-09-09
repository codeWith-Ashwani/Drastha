"""Validate the checksum-pinned final SIH prototype acceptance bundle."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_accuracy_fixture import check as check_accuracy  # noqa: E402
from check_sprint22_hardening import audit as audit_hardening  # noqa: E402
from check_sprint23_deployment import audit as audit_deployment  # noqa: E402
from check_sprint24_performance import audit as audit_performance  # noqa: E402


MANIFEST = Path("data/manifests/drastha-sih-release-v1.json")
MANIFEST_SHA256 = "8e46493ea622adbc47519634ce59488235ba095cd4b551fd01b3331a1185daab"
ALERT_FIELDS = {
    "schema_version", "timestamp", "flow_identifier", "threat_class",
    "confidence", "supporting_evidence", "confidence_semantics",
    "confidence_calibration_status", "confidence_is_probability",
}


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_evidence(root: Path, entries: list[dict]) -> tuple[dict[str, dict], dict[str, str]]:
    documents, digests = {}, {}
    seen: set[str] = set()
    for entry in entries:
        relative = str(entry["path"]).replace("\\", "/")
        if relative in seen:
            raise ValueError(f"Duplicate release evidence path: {relative}")
        seen.add(relative)
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise ValueError(f"Evidence escapes repository root: {relative}") from error
        raw = path.read_bytes()
        digest = sha256(raw).hexdigest()
        if digest != entry["sha256"]:
            raise ValueError(f"Release evidence checksum mismatch: {relative}")
        digests[relative] = digest
        if path.suffix in {".json", ".jsonl"} and path.suffix != ".jsonl":
            documents[relative] = json.loads(raw)
    return documents, digests


def audit(root: Path = ROOT) -> dict:
    root = root.resolve()
    manifest_path = root / MANIFEST
    manifest_raw = manifest_path.read_bytes()
    manifest_digest = sha256(manifest_raw).hexdigest()
    if manifest_digest != MANIFEST_SHA256:
        raise ValueError("Sprint 25 release manifest checksum mismatch")
    manifest = json.loads(manifest_raw)
    documents, digests = _safe_evidence(root, manifest["evidence"])

    hardening = audit_hardening(root)
    deployment = audit_deployment(root)
    performance = audit_performance(root)
    accuracy = check_accuracy(root / "examples" / "drastha_accuracy_fp_test_v2.jsonl")
    recovery = documents["output/sprint17_coordinated_recovery_final.json"]
    export = documents["output/sprint18_siem_export.json"]
    sensor = documents["output/sprint19_sensor_integration.json"]
    dga = documents["output/umudga_dns_holdout_v2_final.json"]

    # Exercise the public alert serializer rather than accepting documentation alone.
    from aegisflow.models import Alert, Evidence  # imported after project paths are configured
    sample = Alert(
        alert_id="release-schema-check", detector_id="release", detector_version="1",
        threat_type="reconnaissance", subtype="multi_host_port_scan", confidence=0.8,
        severity="high", window_start=1.0, window_end=2.0, src_ip="192.0.2.1",
        dst_ip=None, flow_ids=("release-flow",),
        evidence=(Evidence("fan_out", 20, ">= 20", "Schema contract check"),),
    ).to_dict()

    gates = {
        "manifest_schema_and_status": (
            manifest["schema_version"] == "drastha-sih-release-manifest-v1"
            and manifest["status"] == "submission_demo_ready"
            and manifest["production_ready"] is False
        ),
        "all_evidence_checksums_verified": len(digests) == len(manifest["evidence"]) == 10,
        "actual_upload_accuracy_replay_passed": (
            accuracy["passed"] and accuracy["records"] == 153
            and accuracy["findings"] == accuracy["incidents"] == 8
            and accuracy["quality"]["status"] == "healthy"
            and accuracy["evaluation"]["true_positive"] == 8
            and accuracy["evaluation"]["false_positive"] == 0
            and accuracy["evaluation"]["false_negative"] == 0
        ),
        "nine_threat_hardening_reproduced": (
            hardening["passed"] and hardening["after_context"]
            == {"tp": 9, "fp": 0, "fn": 0, "tn": 5}
        ),
        "standard_alert_schema_serialized": (
            ALERT_FIELDS <= set(sample)
            and sample["schema_version"] == "drastha-alert-v1"
            and sample["confidence_is_probability"] is False
        ),
        "real_zeek_passive_sensor_evidence": (
            sensor["passed"] and sensor["sensor"]["status"] == "available"
            and "8.0.10" in sensor["sensor"]["version"]
            and sensor["detector_network_attempts"] == []
            and sensor["gates"]["payload_not_decrypted"]
            and sensor["quality"]["status"] == "healthy"
        ),
        "siem_export_evidence": (
            export["passed"] and len(export["results"]) == 2
            and all(item["passed"] and item["events"] == 8 for item in export["results"])
        ),
        "signed_recovery_evidence": (
            recovery["passed"] and recovery["records_at_cut"] == recovery["recovered_records"] == 452
            and recovery["quality"]["status"] == "healthy"
        ),
        "deployment_remains_fail_closed_and_nonproduction": (
            deployment["passed"] and deployment["production_ready"] is False
            and deployment["confidence"]["is_probability"] is False
        ),
        "sustained_target_honestly_bounded": (
            performance["passed"] and performance["production_ready"] is False
            and performance["demonstrated_target"]["records_per_second"] == 50
            and performance["undemonstrated_target"]["records_per_second"] == 100
        ),
        "failed_dga_candidate_remains_excluded": (
            dga["production_approved"] is False
            and bool(dga["validation_gate_failures"] or dga["test_gate_failures"])
        ),
        "unsupported_claims_are_explicit": len(manifest["excluded_claims"]) >= 7,
    }
    return {
        "schema_version": "drastha-sprint25-release-audit-v1",
        "release_id": manifest["release_id"],
        "passed": all(gates.values()),
        "submission_demo_ready": all(gates.values()),
        "production_ready": False,
        "gates": gates,
        "manifest": {"path": MANIFEST.as_posix(), "sha256": manifest_digest},
        "verified_evidence_sha256": digests,
        "verified_results": {
            "accuracy_replay": {"records": accuracy["records"], "findings": accuracy["findings"],
                                "incidents": accuracy["incidents"], "tp": 8, "fp": 0, "fn": 0},
            "lab_hardening": hardening["after_context"],
            "performance": performance["demonstrated_target"],
            "zeek_version": sensor["sensor"]["version"],
        },
        "excluded_claims": manifest["excluded_claims"],
        "limitations": [
            "Acceptance is for the reproducible offline SIH prototype, not a production deployment.",
            "Accuracy figures are from small controlled lab fixtures and do not establish real-world accuracy.",
            "The 50 records/second result is a bounded same-host metadata test, not Mbps or live-mirror capacity.",
            "The DGA research candidate failed its promotion gates and is not loaded in deployment mode.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    report = audit(args.repo_root)
    output = args.report_output or args.repo_root / "output" / "sprint25_release_audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "release_id": report["release_id"],
                      "production_ready": report["production_ready"], "report": str(output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
