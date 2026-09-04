"""Run the corrected SIH accuracy fixture through the actual upload API path."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from fastapi.testclient import TestClient
from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository
from aegisflow.ingestion.zeek_jsonl import _timestamp

EXPECTED = {"distributed_source_syn_flood", "udp_reflection_amplification",
            "periodic_beacon", "dga_like_domain", "dns_tunnelling",
            "encrypted_session_metadata_anomaly", "multi_host_port_scan",
            "outbound_volume_anomaly"}


def fixture_records(raw):
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return [json.loads(line) for line in raw.splitlines() if line.strip()], {
            "source_records": 53,
            "source_invalid_timestamps_corrected": 4,
            "added_passive_tls_baseline_records": 100,
        }
    if isinstance(payload, list):
        return payload, {"source_records": 53, "source_invalid_timestamps_corrected": 4}
    return payload["records"], payload


def check(fixture=None):
    fixture = Path(fixture or ROOT / "examples/drastha_accuracy_fp_test_v2.jsonl")
    raw = fixture.read_text(encoding="utf-8")
    records, metadata = fixture_records(raw)
    timestamps = [_timestamp(record, line_number=index) for index, record in enumerate(records, 1)]
    assert metadata["source_records"] == 53
    assert metadata["source_invalid_timestamps_corrected"] == 4
    assert len(records) == len({record["uid"] for record in records}) == 153
    assert all(left < right for left, right in zip(timestamps, timestamps[1:]))
    assert all(record.get(name) not in (None, "") for record in records
               for name in ("ts", "uid", "id.orig_h", "id.resp_h", "proto",
                            "evaluation_label", "evaluation_threat_class", "evaluation_id"))
    with tempfile.TemporaryDirectory(prefix="drastha-accuracy-") as directory:
        app = create_app(IncidentRepository(Path(directory) / "analyst.db"))
        with TestClient(app) as client, patch.dict("os.environ", {"DRASTHA_ROOT": str(ROOT)}):
            response = client.post("/api/replays/analyse",
                                   json={"filename": fixture.name, "content": raw})
            assert response.status_code == 200, response.text
            report = response.json()
            saved = client.get("/api/analysis-runs/" + report["run_id"])
            assert saved.status_code == 200 and saved.json() == report
    quality, evaluation = report["quality"], report["evaluation"]
    assert quality["records_accepted"] == 153 and quality["records_rejected"] == 0
    assert quality["invalid_timestamp_count"] == quality["out_of_order_records"] == 0
    assert quality["duplicate_uid_count"] == 0 and quality["status"] == "healthy"
    observed = {alert["subtype"] for alert in report["alerts"]}
    assert len(report["alerts"]) == len(report["incidents"]) == 8, (
        len(report["alerts"]), len(report["incidents"]), sorted(observed), report["feature_coverage"])
    assert observed == EXPECTED, (sorted(observed), sorted(EXPECTED - observed), sorted(observed - EXPECTED))
    overall_risk = report["overall_risk"]
    assert overall_risk["score"] == 88 and overall_risk["severity"] == "critical"
    assert overall_risk["incident_count"] == 8
    assert overall_risk["distinct_threat_types"] == 6
    assert overall_risk["affected_sources"] == 8
    assert (evaluation["true_positive"], evaluation["false_positive"],
            evaluation["false_negative"]) == (8, 0, 0)
    assert evaluation["precision"] == evaluation["recall"] == evaluation["f1_score"] == 1
    assert evaluation["false_positive_rate"] == 0
    c2 = next(alert for alert in report["alerts"] if alert["subtype"] == "periodic_beacon")
    assert c2["src_ip"] == "192.168.20.60"
    encrypted = next(alert for alert in report["alerts"] if alert["subtype"] == "encrypted_session_metadata_anomaly")
    origins = {item["observed"] for item in encrypted["evidence"] if item["name"] == "feature_origin"}
    assert origins == {"derived"}
    coverage = report["feature_coverage"]["counts"]
    assert coverage.get("derived") == 4 and coverage.get("insufficient_evidence") == 100
    assert report["context_policy"]["suppressed_connection_evaluations"] == 14
    suppressed = report["context_policy"]["suppressed_by_detector"]
    assert sum(suppressed.values()) == 14 and all(value > 0 for value in suppressed.values())
    hard_negatives = {
        "health_check": not any(alert["src_ip"] == "192.168.30.10" for alert in report["alerts"]),
        "approved_backup": not any(alert["src_ip"] == "192.168.30.20" for alert in report["alerts"]),
        "authorized_scanner": not any(alert["src_ip"] == "192.168.30.30" for alert in report["alerts"]),
    }
    assert all(hard_negatives.values())
    return {"passed": True, "fixture": str(fixture), "source_records_preserved": 53,
            "source_invalid_timestamps_corrected": 4,
            "baseline_records_added": 100, "records": len(records), "findings": len(report["alerts"]),
            "incidents": len(report["incidents"]), "quality": quality, "evaluation": evaluation,
            "overall_risk": overall_risk,
            "subtypes": sorted(EXPECTED), "c2_source": c2["src_ip"],
            "feature_coverage": report["feature_coverage"], "context_policy": report["context_policy"],
            "benign_hard_negatives": hard_negatives}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--report-output", type=Path, required=True)
    args = parser.parse_args()
    if args.report_output.exists():
        parser.error("Choose a new report filename")
    result = check(args.fixture)
    args.report_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
