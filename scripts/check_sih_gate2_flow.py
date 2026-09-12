"""Run frozen, independently labelled PS-tool captures through HTTP upload."""
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
from freeze_sih_gate2_flow import verify


def audit() -> dict:
    freeze = verify()
    labels = json.loads((ROOT / freeze["labels"]).read_text(encoding="utf-8"))
    artifacts = {item["scenario"]: item for item in freeze["artifacts"]}
    reports = []
    with tempfile.TemporaryDirectory(prefix="drastha-gate2-flow-") as temporary:
        with patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
            for scenario in labels["scenarios"]:
                name = scenario["name"]
                item = artifacts[name]
                path = ROOT / item["fixture"]
                repository = IncidentRepository(Path(temporary) / f"{name}.db")
                with TestClient(create_app(repository)) as client:
                    response = client.post("/api/replays/analyse", json={
                        "filename": path.name, "content": path.read_text(encoding="utf-8")
                    })
                    if response.status_code != 200:
                        raise RuntimeError(f"HTTP upload failed for {name}: {response.text}")
                    result = response.json()
                expected = set(scenario["expected"])
                actual = {alert["subtype"] for alert in result["alerts"]}
                quality = result["quality"]
                reports.append({
                    "scenario": name,
                    "source": scenario["source"],
                    "interpretation": scenario["interpretation"],
                    "fixture_sha256": item["fixture_sha256"],
                    "raw_pcap_sha256": item["raw_pcap_sha256"],
                    "records": item["records"],
                    "accepted": quality["records_accepted"],
                    "rejected": quality["records_rejected"],
                    "out_of_order": quality["out_of_order_records"],
                    "duplicate_uids": quality["duplicate_uid_count"],
                    "quality": quality["status"],
                    "expected": sorted(expected),
                    "detected": sorted(actual),
                    "tp": sorted(expected & actual),
                    "fp": sorted(actual - expected),
                    "fn": sorted(expected - actual),
                    "tn": int(not expected and not actual),
                    "findings": len(result["alerts"]),
                    "incidents": len(result["incidents"]),
                    "evidence": {alert["subtype"]: {
                        evidence["name"]: evidence["observed"] for evidence in alert["evidence"]
                    } for alert in result["alerts"]},
                })
    passed = all(item["quality"] == "healthy" and item["accepted"] == item["records"]
                 and item["rejected"] == item["out_of_order"] == item["duplicate_uids"] == 0
                 and not item["fp"] and not item["fn"] for item in reports)
    return {
        "schema_version": "drastha-sih-gate2-flow-audit-v1",
        "passed": passed,
        "capture_id": freeze["capture_id"],
        "labels_sha256": freeze["labels_sha256"],
        "raw_captures_committed": False,
        "reports": reports,
        "totals": {
            "records": sum(item["records"] for item in reports),
            "tp": sum(len(item["tp"]) for item in reports),
            "fp": sum(len(item["fp"]) for item in reports),
            "fn": sum(len(item["fn"]) for item in reports),
            "tn": sum(item["tn"] for item in reports),
        },
        "limitations": [
            "Controlled private lab traffic, not independent production-network accuracy.",
            "A valid lab UDP amplification-shaped response is not proof of spoofing or third-party reflection.",
            "iperf3 bulk asymmetry demonstrates a volume behaviour, not malicious data theft intent.",
            "The hping3 UDP burst contained crafted packets; it is evaluated as a flood, not a valid application exchange.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-output", type=Path,
                        default=ROOT / "output/sih_gate2_flow_audit.json")
    args = parser.parse_args()
    report = audit()
    path = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"passed": report["passed"], "totals": report["totals"],
                      "report": str(path)}, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
