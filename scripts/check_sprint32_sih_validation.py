from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fastapi.testclient import TestClient
from aegisflow.api import create_app
from aegisflow.api_store import IncidentRepository
from check_sprint22_hardening import audit as hardening_audit


EXPECTED_CLASSES = {
    "distributed_source_syn_flood": "Volumetric DDoS - Distributed-Source SYN Flood",
    "udp_reflection_amplification": "Volumetric DDoS - UDP Reflection/Amplification",
    "multi_host_port_scan": "Reconnaissance - Multi-Host/Port Scan",
    "periodic_beacon": "Botnet C2 Beaconing",
    "dga_like_domain": "DGA Domain Activity",
    "dns_tunnelling": "DNS Tunnelling",
    "encrypted_session_metadata_anomaly": "Encrypted-session metadata anomaly",
    "outbound_volume_anomaly": "Data Exfiltration - Outbound Volume Anomaly",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metric_summary(report: dict) -> dict:
    evaluation = report["evaluation"]
    return {
        "records": report["quality"]["records_accepted"],
        "rejected": report["quality"]["records_rejected"],
        "quality": report["quality"]["status"],
        "findings": len(report["alerts"]),
        "incidents": len(report["incidents"]),
        "tp": evaluation["true_positive"],
        "fp": evaluation["false_positive"],
        "fn": evaluation["false_negative"],
        "tn": evaluation["true_negative"],
        "precision": evaluation["precision"],
        "recall": evaluation["recall"],
        "f1": evaluation["f1_score"],
        "fpr": evaluation["false_positive_rate"],
        "identity_overlap": evaluation["identity_overlap"]["sources_present_in_attack_and_benign_units"],
    }


def validate_report(report: dict, *, records: int, tn: int) -> dict[str, bool]:
    metrics = metric_summary(report)
    alerts = report["alerts"]
    incidents = report["incidents"]
    alert_ids = {alert["alert_id"] for alert in alerts}
    incident_alert_ids = [item for incident in incidents for item in incident["alert_ids"]]
    subtype_map = {alert["subtype"]: alert for alert in alerts}
    distributed = subtype_map.get("distributed_source_syn_flood", {})
    distributed_evidence = {item["name"] for item in distributed.get("evidence", [])}
    distributed_limits = " ".join(distributed.get("limitations", [])).lower()
    return {
        "record_and_metric_contract": all(metrics[key] == value for key, value in {
            "records": records, "rejected": 0, "quality": "healthy", "findings": 8,
            "incidents": 8, "tp": 8, "fp": 0, "fn": 0, "tn": tn,
            "precision": 1.0, "recall": 1.0, "f1": 1.0, "fpr": 0.0,
        }.items()),
        "all_required_subtypes_exact": set(subtype_map) == set(EXPECTED_CLASSES),
        "presentation_classes_exact": all(
            subtype_map.get(subtype, {}).get("threat_class") == name
            for subtype, name in EXPECTED_CLASSES.items()
        ),
        "standard_alert_schema_complete": all(
            alert.get("schema_version") == "drastha-alert-v1"
            and alert.get("timestamp") is not None
            and alert.get("flow_identifier")
            and alert.get("flow_ids")
            and alert.get("threat_class")
            and 0 <= alert.get("confidence", -1) <= 1
            and alert.get("supporting_evidence")
            and alert.get("limitations")
            and alert.get("confidence_is_probability") is False
            for alert in alerts
        ),
        "alerts_map_once_to_incidents": (
            len(incident_alert_ids) == len(set(incident_alert_ids))
            and set(incident_alert_ids) == alert_ids
        ),
        "incident_conclusions_complete": all(
            incident.get("conclusion", {}).get(field)
            for incident in incidents
            for field in ("assessment", "likely_objective", "attack_stage", "potential_impact",
                          "confidence_basis", "uncertainty", "inference_basis")
        ),
        "aggregate_risk_is_bounded_priority": (
            0 <= report["overall_risk"]["score"] <= 100
            and report["overall_risk"]["incident_count"] == len(incidents)
            and "not an attack probability" in report["overall_risk"]["uncertainty"].lower()
        ),
        "passive_safety_contract": report.get("safety") == {
            "ingest_mode": "read_only", "passive_observation_only": True,
            "return_path_required": False, "source_or_destination_contacted": False,
            "payload_decryption_performed": False, "mitigation_command_issued": False,
        },
        "ground_truth_is_post_inference": report["evaluation"]["ground_truth_isolation"] == (
            "evaluation fields used only after detector inference"
        ),
        "spoofing_claim_is_cautious": (
            "normalized_source_ip_entropy" in distributed_evidence
            and "does not prove ip spoofing" in distributed_limits
        ),
        "encrypted_claim_is_cautious": any(
            "not malware proof" in item.lower()
            for item in subtype_map.get("encrypted_session_metadata_anomaly", {}).get("limitations", [])
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run final Sprint 32 SIH validation")
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    manifest_path = ROOT / "data/manifests/sih26145-final-validation-v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    integrity = {
        entry["path"]: digest(ROOT / entry["path"]) == entry["sha256"]
        for entry in manifest["artifacts"]
    }

    with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"DRASTHA_ROOT": str(ROOT)}):
        repository = IncidentRepository(Path(temporary) / "sprint32.db")
        with TestClient(create_app(repository)) as client:
            reports = {}
            api_gates = {}
            for name, expected_records, expected_tn in (
                ("drastha_mixed_evaluation_v3.jsonl", 452, 86),
                ("drastha_accuracy_fp_test_v2.jsonl", 153, 107),
            ):
                source = ROOT / "examples" / name
                response = client.post("/api/replays/analyse", json={
                    "filename": name, "content": source.read_text(encoding="utf-8")
                })
                if response.status_code != 200:
                    raise SystemExit(f"HTTP upload failed for {name}: {response.text}")
                report = response.json()
                reports[name] = {
                    "metrics": metric_summary(report),
                    "subtype_classes": {a["subtype"]: a["threat_class"] for a in report["alerts"]},
                    "overall_risk": report["overall_risk"],
                }
                gates = validate_report(report, records=expected_records, tn=expected_tn)
                saved = client.get(f"/api/analysis-runs/{report['run_id']}")
                export = client.get(f"/api/analysis-runs/{report['run_id']}/export?format=json")
                incident_details = [
                    client.get(f"/api/incidents/{incident['incident_id']}").json()
                    for incident in report["incidents"]
                ]
                gates.update({
                    "saved_run_snapshot_exact": saved.status_code == 200 and saved.json() == report,
                    "siem_export_available": (
                        export.status_code == 200
                        and export.headers.get("x-drastha-export-schema") == "drastha-siem-export-v1"
                    ),
                    "incident_evidence_api_exact": all(
                        set(detail["alert_ids"]) == {alert["alert_id"] for alert in detail["alerts"]}
                        for detail in incident_details
                    ),
                })
                api_gates[name] = gates

            stream = client.get("/api/stream/simulated?interval=0")
            messages = [
                json.loads(line.removeprefix("data: ")) for line in stream.text.splitlines()
                if line.startswith("data: ")
            ]
            completed = messages[-1]
            stream_gates = {
                "http_success": stream.status_code == 200,
                "incremental_records_exact": sum(item["type"] == "traffic" for item in messages) == 67,
                "alerts_emitted_before_completion": any(item["type"] == "alert" for item in messages[:-1]),
                "bounded_near_real_time": (
                    completed.get("type") == "complete" and completed.get("bounded_latency") is True
                    and completed.get("near_real_time") is True
                ),
                "passive_no_return_path": (
                    completed.get("passive") is True and completed.get("return_path_required") is False
                ),
            }

    hardening = hardening_audit(ROOT)
    performance = json.loads((ROOT / "output/sprint24_performance_audit.json").read_text())
    input_compliance = json.loads((ROOT / "output/sprint31_input_compliance_audit.json").read_text())
    separated = reports["drastha_accuracy_fp_test_v2.jsonl"]["metrics"]
    cross_gates = {
        "all_manifest_checksums": all(integrity.values()),
        "both_http_replays_pass": all(all(gates.values()) for gates in api_gates.values()),
        "identity_separated_corroboration": separated["identity_overlap"] == [],
        "context_hardening_9tp_0fp_0fn": (
            hardening["passed"] and hardening["after_context"] == {"tp": 9, "fp": 0, "fn": 0, "tn": 5}
        ),
        "all_lab_quality_healthy": hardening["gates"]["all_quality_healthy"],
        "streaming_contract": all(stream_gates.values()),
        "sustained_50rps_60s": (
            performance["passed"]
            and performance["demonstrated_target"]["records_per_second"] == 50
            and performance["demonstrated_target"]["duration_seconds"] == 60
        ),
        "input_formats_pass": input_compliance["passed"],
    }
    report = {
        "schema_version": "drastha-sprint32-sih-validation-v1",
        "passed": all(cross_gates.values()),
        "manifest": "data/manifests/sih26145-final-validation-v1.json",
        "manifest_sha256": digest(manifest_path),
        "integrity": integrity,
        "http_replays": reports,
        "http_replay_gates": api_gates,
        "streaming_gates": stream_gates,
        "lab_hardening": {"after_context": hardening["after_context"], "gates": hardening["gates"]},
        "performance": performance["demonstrated_target"],
        "input_compliance_claims": input_compliance["claims"],
        "gates": cross_gates,
        "limitations": manifest["scientific_boundaries"],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report_output:
        output = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
        output.write_text(rendered, encoding="utf-8", newline="\n")
    print(json.dumps({"passed": report["passed"], "gates": cross_gates}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
