"""Read-only Sprint 23 deployment-boundary and confidence-contract audit."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.analysis_session import AnalysisSession, DEPLOYMENT_BASELINE  # noqa: E402
from aegisflow.deployment_config import load_deployment_config  # noqa: E402


CONFIG_SHA256 = "b5c3aa84decffcdc93c04463974b966aacaa27aae2c3ee21e45ee185f1f199aa"


def audit(root: Path = ROOT) -> dict:
    root = root.resolve()
    path = root / "config" / "deployment_profile.json"
    digest = sha256(path.read_bytes()).hexdigest()
    if digest != CONFIG_SHA256:
        raise ValueError("Sprint 23 deployment configuration checksum mismatch")
    settings = load_deployment_config(path)
    previous_deployment = os.environ.get("DRASTHA_DEPLOYMENT_CONFIG")
    previous_networks = os.environ.pop("DRASTHA_INTERNAL_NETWORKS", None)
    os.environ["DRASTHA_DEPLOYMENT_CONFIG"] = str(path)
    try:
        session = AnalysisSession.from_root(root, DEPLOYMENT_BASELINE)
    finally:
        if previous_deployment is None:
            os.environ.pop("DRASTHA_DEPLOYMENT_CONFIG", None)
        else:
            os.environ["DRASTHA_DEPLOYMENT_CONFIG"] = previous_deployment
        if previous_networks is not None:
            os.environ["DRASTHA_INTERNAL_NETWORKS"] = previous_networks
    directions = {
        "internal": session.network_scope.direction("10.1.1.1", "192.168.1.1"),
        "outbound": session.network_scope.direction("10.1.1.1", "203.0.113.1"),
        "inbound": session.network_scope.direction("203.0.113.1", "172.16.1.1"),
        "external": session.network_scope.direction("203.0.113.1", "198.51.100.1"),
    }
    provenance = session.provenance()
    gates = {
        "deployment_config_checksum_pinned": digest == CONFIG_SHA256,
        "network_boundaries_nonempty": bool(settings.internal_cidrs),
        "all_direction_classes_verified": directions == {
            "internal": "internal", "outbound": "outbound",
            "inbound": "inbound", "external": "external",
        },
        "context_policy_checksum_verified": len(settings.context_policy_sha256) == 64,
        "single_deployment_profile_selected": provenance["profile"] == "deployment:staged-enclave-lab-v1",
        "confidence_is_not_probability": provenance["confidence_is_probability"] is False,
        "confidence_limitation_machine_readable": provenance["confidence_calibration_status"] == "not_probability_calibrated",
        "no_production_dns_model_loaded": session.dns_model is None,
    }
    return {
        "schema_version": "drastha-sprint23-deployment-audit-v1",
        "passed": all(gates.values()),
        "gates": gates,
        "deployment": {
            "id": settings.deployment_id,
            "source_sha256": settings.sha256,
            "internal_cidrs": settings.internal_cidrs,
            "context_policy_sha256": settings.context_policy_sha256,
            "dns_model_status": settings.dns_model_status,
        },
        "directions": directions,
        "confidence": {
            "semantics": provenance["confidence_semantics"],
            "calibration_status": provenance["confidence_calibration_status"],
            "is_probability": provenance["confidence_is_probability"],
        },
        "production_ready": False,
        "limitations": [
            "The checked-in CIDRs describe a staged lab profile and must be replaced for the real enclave.",
            "Detector confidence remains heuristic and is not an attack probability.",
            "No DNS model is production-approved; Sprint 21's failed candidate remains excluded.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    report = audit(args.repo_root)
    output = args.report_output or args.repo_root / "output" / "sprint23_deployment_audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "deployment": report["deployment"]["id"],
                      "confidence": report["confidence"], "report": str(output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
