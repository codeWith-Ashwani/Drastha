"""Evaluate the deployed DGA demo model on frozen published-algorithm names."""
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
from freeze_sih_gate2_dga import verify


def audit() -> dict:
    freeze = verify()
    reports = []
    with tempfile.TemporaryDirectory(prefix="drastha-gate2-dga-") as temporary:
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            for item in freeze["artifacts"]:
                fixture = ROOT / item["fixture"]
                rows = [json.loads(line) for line in fixture.read_text(encoding="utf-8").splitlines()]
                repository = IncidentRepository(Path(temporary) / f"{item['label']}.db")
                with TestClient(create_app(repository)) as client:
                    response = client.post("/api/replays/analyse", json={
                        "filename": fixture.name, "content": fixture.read_text(encoding="utf-8")
                    })
                    if response.status_code != 200:
                        raise RuntimeError(f"HTTP DGA upload failed: {response.text}")
                    result = response.json()
                alerted = {flow for alert in result["alerts"] if alert["subtype"] == "dga_like_domain"
                           for flow in alert.get("flow_ids", [])}
                uids = {row["uid"] for row in rows}
                quality = result["quality"]
                reports.append({
                    "label": item["label"], "records": len(rows),
                    "quality": quality["status"], "accepted": quality["records_accepted"],
                    "rejected": quality["records_rejected"],
                    "unexpected_alert_subtypes": sorted({alert["subtype"] for alert in result["alerts"]
                                                         if alert["subtype"] != "dga_like_domain"}),
                    "dga_alerts": sum(alert["subtype"] == "dga_like_domain" for alert in result["alerts"]),
                    "detected_domain_uids": sorted(alerted & uids),
                    "tp": len(alerted & uids) if item["label"] == "dga" else 0,
                    "fn": len(uids - alerted) if item["label"] == "dga" else 0,
                    "fp": len(alerted & uids) if item["label"] == "benign" else 0,
                    "tn": len(uids - alerted) if item["label"] == "benign" else 0,
                })
    totals = {key: sum(item[key] for item in reports) for key in ("tp", "fp", "fn", "tn")}
    return {
        "schema_version": "drastha-sih-gate2-dga-audit-v1",
        "provenance_valid": True,
        "quality_healthy": all(item["quality"] == "healthy" and item["accepted"] == item["records"]
                               and item["rejected"] == 0 for item in reports),
        "labels_sha256": freeze["labels_sha256"],
        "reports": reports, "totals": totals,
        "recall": totals["tp"] / max(totals["tp"] + totals["fn"], 1),
        "fpr": totals["fp"] / max(totals["fp"] + totals["tn"], 1),
        "limitations": [
            "The deployed small n-gram model was trained on the separate bundled demo CSV, not UMUDGA.",
            "UMUDGA families were inspected in prior research, so this is not a virgin family holdout.",
            "Domain-level flow-ID attribution can undercount a campaign-level lexical alert; raw DGA alert count is also reported.",
            "No domain was resolved or contacted; publisher strings were converted to passive DNS-like records.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-output", type=Path,
                        default=ROOT / "output/sih_gate2_dga_audit.json")
    args = parser.parse_args()
    report = audit()
    path = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"quality_healthy": report["quality_healthy"], "totals": report["totals"],
                      "recall": report["recall"], "fpr": report["fpr"]}, sort_keys=True))
    return 0 if report["quality_healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
