"""Verify the final checksum-pinned SIH submission and rerun current acceptance."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path("data/manifests/drastha-sih-release-v2.json")


def validate_manifest(root: Path, manifest: dict) -> dict[str, str]:
    if manifest.get("schema_version") != "drastha-sih-release-manifest-v2":
        raise ValueError("Unsupported Sprint 33 release manifest schema")
    if manifest.get("status") != "submission_demo_ready" or manifest.get("production_ready") is not False:
        raise ValueError("Release must be demo-ready and explicitly non-production")
    evidence = manifest.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("Release evidence must be a non-empty array")
    digests: dict[str, str] = {}
    for item in evidence:
        relative = str(item.get("path", "")).replace("\\", "/")
        pure = PurePosixPath(relative)
        if not relative or pure.is_absolute() or ".." in pure.parts or relative in digests:
            raise ValueError(f"Unsafe or duplicate evidence path: {relative}")
        path = (root / relative).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as error:
            raise ValueError(f"Evidence escapes repository root: {relative}") from error
        digest = sha256(path.read_bytes()).hexdigest()
        if digest != item.get("sha256"):
            raise ValueError(f"Release evidence checksum mismatch: {relative}")
        digests[relative] = digest
    return digests


def audit(root: Path = ROOT) -> dict:
    root = root.resolve()
    manifest_path = root / MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    digests = validate_manifest(root, manifest)
    with tempfile.TemporaryDirectory(prefix="drastha-sprint33-") as directory:
        current_report = Path(directory) / "sprint32-current.json"
        result = subprocess.run(
            [sys.executable, str(root / "scripts/check_sprint32_sih_validation.py"),
             "--report-output", str(current_report)],
            cwd=root, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Current SIH acceptance failed: {result.stderr or result.stdout}")
        current = json.loads(current_report.read_text(encoding="utf-8"))

    mixed = current["http_replays"]["drastha_mixed_evaluation_v3.jsonl"]["metrics"]
    separated = current["http_replays"]["drastha_accuracy_fp_test_v2.jsonl"]["metrics"]
    claims = manifest["accepted_claims"]
    expected_mixed = claims["mixed_replay"]
    expected_separated = claims["identity_separated_replay"]
    gates = {
        "all_evidence_checksums_verified": len(digests) == len(manifest["evidence"]) == 10,
        "current_sih_acceptance_passed": current["passed"],
        "mixed_replay_claim_exact": all(mixed[key] == value for key, value in expected_mixed.items()),
        "identity_separated_claim_exact": all(
            separated[key] == value for key, value in expected_separated.items()
        ),
        "lab_claim_exact": current["lab_hardening"]["after_context"] == claims["lab_corpus"],
        "throughput_claim_exact": (
            current["performance"]["records_per_second"] == claims["demonstrated_records_per_second"]
            and current["performance"]["duration_seconds"] == claims["demonstrated_duration_seconds"]
        ),
        "passive_input_formats_verified": current["gates"]["input_formats_pass"],
        "scientific_boundaries_preserved": len(manifest["excluded_claims"]) >= 7,
    }
    return {
        "schema_version": "drastha-sprint33-release-audit-v1",
        "release_id": manifest["release_id"],
        "passed": all(gates.values()),
        "submission_demo_ready": all(gates.values()),
        "production_ready": False,
        "gates": gates,
        "manifest": {"path": MANIFEST.as_posix(), "sha256": sha256(manifest_path.read_bytes()).hexdigest()},
        "verified_evidence_sha256": digests,
        "verified_results": {"mixed_replay": mixed, "identity_separated_replay": separated,
                             "lab_corpus": current["lab_hardening"]["after_context"],
                             "performance": current["performance"]},
        "excluded_claims": manifest["excluded_claims"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    report = audit(args.repo_root)
    output = args.report_output or args.repo_root / "output/sprint33_release_audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "release_id": report["release_id"],
                      "production_ready": report["production_ready"], "report": str(output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
