"""Evaluate new DNS campaign context through the actual HTTP upload path."""
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
from build_sih_dga_campaign_fixture import LABELS, verify


def audit() -> dict:
    manifest = verify()
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    sources = {item["scenario"]: item for item in manifest["artifacts"]}
    reports = []
    with tempfile.TemporaryDirectory(prefix="drastha-dga-campaign-") as directory:
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            for scenario in labels["scenarios"]:
                name = scenario["name"]
                fixture = ROOT / sources[name]["path"]
                repository = IncidentRepository(Path(directory) / f"{name}.db")
                with TestClient(create_app(repository)) as client:
                    response = client.post("/api/replays/analyse", json={
                        "filename": fixture.name, "content": fixture.read_text(encoding="utf-8")})
                    if response.status_code != 200:
                        raise RuntimeError(f"DGA campaign upload failed: {response.text}")
                    result = response.json()
                alerts = [item for item in result["alerts"] if item["subtype"] == "dga_like_domain"]
                unexpected = sorted({item["subtype"] for item in result["alerts"]
                                     if item["subtype"] != "dga_like_domain"})
                quality = result["quality"]
                reports.append({
                    "scenario": name, "expected": scenario["expected"],
                    "records": sources[name]["records"], "accepted": quality["records_accepted"],
                    "rejected": quality["records_rejected"], "quality": quality["status"],
                    "dga_alerts": len(alerts),
                    "unexpected_alert_subtypes": unexpected,
                    "behaviour_tp": int(scenario["expected"] == "dga_like_domain" and bool(alerts)),
                    "behaviour_fn": int(scenario["expected"] == "dga_like_domain" and not alerts),
                    "behaviour_fp": int(scenario["expected"] == "benign" and bool(alerts)),
                    "behaviour_tn": int(scenario["expected"] == "benign" and not alerts),
                    "evidence": [{entry["name"]: entry["observed"] for entry in alert["evidence"]}
                                 for alert in alerts],
                })
    totals = {key: sum(item[f"behaviour_{key}"] for item in reports)
              for key in ("tp", "fp", "fn", "tn")}
    return {
        "schema_version": "drastha-sih-dga-campaign-audit-v1",
        "quality_healthy": all(item["quality"] == "healthy" and item["accepted"] == item["records"]
                               and item["rejected"] == 0 for item in reports),
        "no_unexpected_alerts": all(not item["unexpected_alert_subtypes"] for item in reports),
        "reports": reports, "totals": totals,
        "domain_only_generalization_fixed": False,
        "actual_dns_responses_captured": False,
        "limitations": [
            "The publisher supplied domain strings, not DNS response telemetry; resolver outcomes were simulated and disclosed before inference.",
            "Campaign-context success cannot replace the failed bare-domain Vawtrak holdout or a field DNS capture.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-output", type=Path,
                        default=ROOT / "output/sih_dga_campaign_audit.json")
    args = parser.parse_args()
    result = audit()
    path = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")
    print(json.dumps({"quality_healthy": result["quality_healthy"], "totals": result["totals"]}))
    return 0 if result["quality_healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
