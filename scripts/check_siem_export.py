"""Exercise protected upload -> saved snapshot -> JSON/NDJSON SIEM export."""
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import secrets
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient
from aegisflow.audited_store import AuditedIncidentRepository
from aegisflow.security import AccessSettings, Credential
from check_sustained_ingestion import isolated_api


def check():
    with tempfile.TemporaryDirectory(prefix="drastha-siem-") as name:
        directory = Path(name)
        store = AuditedIncidentRepository(directory / "analyst.db", secrets.token_bytes(32))
        token = secrets.token_urlsafe(32)
        settings = AccessSettings("required", (
            Credential("export-check", "analyst", sha256(token.encode()).hexdigest(), time.time() + 600),), ())
        with isolated_api(directory) as create_app:
            app = create_app(store, access=settings)
        results = []
        with TestClient(app, base_url="https://export.test") as client:
            headers = {"Authorization": "Bearer " + token}
            for filename, expected_records, expected_tn in (
                ("drastha_accuracy_fp_test_v2.jsonl", 153, 107),
                ("drastha_mixed_evaluation_v3.jsonl", 452, 86),
            ):
                path = ROOT / "examples" / filename
                original = path.read_bytes()
                with patch.dict("os.environ", {"DRASTHA_ROOT": str(ROOT)}):
                    response = client.post("/api/replays/analyse", headers=headers,
                                           json={"filename": filename, "content": original.decode("utf-8")})
                response.raise_for_status()
                report = response.json()
                endpoint = "/api/analysis-runs/" + report["run_id"] + "/export"
                started = time.perf_counter()
                response = client.get(endpoint, headers=headers)
                response.raise_for_status()
                export = response.json()
                elapsed = (time.perf_counter() - started) * 1000
                payload = {key: export[key] for key in ("manifest", "events")}
                ndjson = client.get(endpoint + "?format=ndjson", headers=headers)
                ndjson.raise_for_status()
                lines = [json.loads(line) for line in ndjson.text.splitlines()]
                reconstructed = {"manifest": lines[0]["manifest"],
                                 "events": [line["event"] for line in lines[1:]]}
                changed = deepcopy(payload)
                changed["events"][0]["risk_score"] = -1
                quality, evaluation = report["quality"], report["evaluation"]
                gates = {
                    "requires_authentication": client.get(endpoint).status_code == 401,
                    "eight_incidents_exported": len(export["events"]) == len(report["incidents"]) == 8,
                    "all_evidence_preserved": {item["alert_id"] for event in export["events"] for item in event["alerts"]}
                        == {item["alert_id"] for item in report["alerts"]},
                    "json_ndjson_equivalent": reconstructed == payload,
                    "json_receipt_verified": store.verify_export(payload, export["integrity"]),
                    "ndjson_receipt_verified": store.verify_export(reconstructed, lines[0]["integrity"]),
                    "changed_export_rejected": not store.verify_export(changed, export["integrity"]),
                    "stable_event_ids": [item["event_id"] for item in reconstructed["events"]]
                        == [item["event_id"] for item in payload["events"]],
                    "accepted_expected_records": quality["records_accepted"] == expected_records,
                    "healthy_without_rejections": quality["status"] == "healthy" and quality["records_rejected"] == 0,
                    "expected_behavior_metrics": (evaluation["true_positive"], evaluation["false_positive"],
                                                   evaluation["false_negative"], evaluation["true_negative"])
                        == (8, 0, 0, expected_tn),
                    "overall_risk_preserved": export["manifest"]["overall_risk"] == report["overall_risk"],
                    "source_preserved": path.read_bytes() == original,
                    "saved_snapshot_preserved": store.get_analysis_run(report["run_id"]) == report,
                }
                results.append({"fixture": filename, "fixture_sha256": sha256(original).hexdigest(),
                                "records": expected_records, "events": len(export["events"]),
                                "ndjson_lines": len(lines), "json_bytes": len(response.content),
                                "ndjson_bytes": len(ndjson.content), "quality": quality,
                                "evaluation": evaluation, "overall_risk": report["overall_risk"],
                                "export_elapsed_ms": round(elapsed, 3), "gates": gates,
                                "passed": all(gates.values())})
        store.verify_evidence()
    return {"sprint": 18, "format": "drastha-siem-export-v1", "results": results,
            "passed": all(item["passed"] for item in results),
            "limitations": ["Synthetic fixtures; ASGI API/authentication checked without real SIEM, TCP or browser.",
                            "Export timings are small-fixture observations, not sustained-throughput measurements.",
                            "No external delivery, CEF/ECS compatibility or automatic blocking is claimed."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-output", type=Path, required=True)
    args = parser.parse_args()
    if args.report_output.exists():
        parser.error("Report is create-only; choose a new filename")
    result = check()
    with args.report_output.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)
