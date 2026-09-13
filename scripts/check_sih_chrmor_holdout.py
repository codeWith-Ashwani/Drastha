"""First-use external-publisher DNS control through the real upload API."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fastapi.testclient import TestClient
from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository
from freeze_sih_chrmor_holdout import LABELS, verify


def audit() -> dict:
    frozen = verify()
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    artifacts = {item["scenario"]: item for item in frozen["artifacts"]}
    reports = []
    with tempfile.TemporaryDirectory(prefix="drastha-chrmor-") as directory:
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            for scenario in labels["scenarios"]:
                name = scenario["name"]
                fixture = ROOT / artifacts[name]["path"]
                repository = IncidentRepository(Path(directory) / f"{name}.db")
                with TestClient(create_app(repository)) as client:
                    response = client.post("/api/replays/analyse", json={
                        "filename": fixture.name, "content": fixture.read_text(encoding="utf-8")})
                    if response.status_code != 200:
                        raise RuntimeError(f"Publisher holdout HTTP upload failed: {response.text}")
                    result = response.json()
                findings = [item for item in result["alerts"] if item["subtype"] == "dga_like_domain"]
                unexpected = sorted({item["subtype"] for item in result["alerts"]
                                     if item["subtype"] != "dga_like_domain"})
                expected = scenario["label"] == "dga"
                quality = result["quality"]
                reports.append({
                    "scenario": name, "records": artifacts[name]["records"],
                    "quality": quality["status"], "accepted": quality["records_accepted"],
                    "rejected": quality["records_rejected"], "dga_findings": len(findings),
                    "unexpected_alert_subtypes": unexpected,
                    "tp": int(expected and bool(findings)), "fn": int(expected and not findings),
                    "fp": int(not expected and bool(findings)), "tn": int(not expected and not findings),
                    "evidence": [{entry["name"]: entry["observed"] for entry in item["evidence"]}
                                 for item in findings],
                })
    totals = {key: sum(item[key] for item in reports) for key in ("tp", "fp", "fn", "tn")}
    return {
        "schema_version": "drastha-sih-chrmor-holdout-audit-v1",
        "source_commit": frozen["source_commit"], "source_sha256": frozen["source_sha256"],
        "reports": reports, "totals": totals,
        "quality_healthy": all(item["quality"] == "healthy" and item["accepted"] == item["records"]
                               and item["rejected"] == 0 for item in reports),
        "passed_behaviour_controls": (totals == {"tp": 1, "fp": 0, "fn": 0, "tn": 2}
                                      and all(not item["unexpected_alert_subtypes"] for item in reports)),
        "domain_only_model_promotion_supported": False,
        "actual_dns_responses_captured": False,
        "limitations": [
            "This is a first-use external publisher string sample; DNS response codes and timing are predeclared simulated controls.",
            "Behaviour-level campaign scoring is not per-domain accuracy or a live resolver validation.",
            "The pre-existing Vawtrak bare-domain 0/40 result remains a real model generalization gap.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-output", type=Path,
                        default=ROOT / "output/sih_chrmor_holdout_audit.json")
    args = parser.parse_args()
    report = audit()
    path = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")
    print(json.dumps({"quality_healthy": report["quality_healthy"],
                      "passed_behaviour_controls": report["passed_behaviour_controls"],
                      "totals": report["totals"]}))
    return 0 if report["quality_healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
