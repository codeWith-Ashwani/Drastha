"""Evaluate actual TLS sessions using PCAP-derived features, never supplied scores."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from aegisflow.api_store import IncidentRepository
from aegisflow.analysis_session import DEPLOYMENT_BASELINE
from aegisflow.replay_service import analyse_replay_file
from aegisflow.ingestion.passive_replay import prepare_replay
from aegisflow.ingestion.capture_join import attach_capture
from aegisflow.passive_features import PassiveFeatureExtractor
from freeze_sih_gate2_tls import UID_LABELS, RAW, verify as verify_v1
from freeze_sih_gate2_tls_v2 import FIXTURE, verify as verify_adapter


def audit() -> dict:
    freeze = verify_v1()
    verify_adapter()
    uid_labels = json.loads(UID_LABELS.read_text(encoding="utf-8"))
    prepared = attach_capture(prepare_replay(FIXTURE.read_text(encoding="utf-8"), FIXTURE.name),
                              RAW / "traffic.pcap")
    extractor = PassiveFeatureExtractor()
    measured_scores = {"benign": [], "anomalous-lab": []}
    for event in sorted(prepared.encrypted_events, key=lambda item: item.timestamp):
        enriched = extractor.enrich(event)
        measured_scores[uid_labels[event.flow_id]].append({
            "status": enriched.raw["feature_provenance"]["status"],
            "features": enriched.raw.get("features", {}),
            "packet_count": len(enriched.raw.get("packet_observations", [])),
            "fingerprint": enriched.client_fingerprint,
        })
    with tempfile.TemporaryDirectory(prefix="drastha-gate2-tls-") as temporary:
        repository = IncidentRepository(Path(temporary) / "tls.db")
        result = analyse_replay_file(FIXTURE, repository, root=ROOT,
                                     profile=DEPLOYMENT_BASELINE,
                                     packet_capture=RAW / "traffic.pcap")
    anomaly_alerts = [alert for alert in result["alerts"]
                      if alert["subtype"] == "encrypted_session_metadata_anomaly"]
    alerted_uids = {uid for alert in anomaly_alerts for uid in alert.get("flow_ids", [])}
    baseline_uids = {uid for uid, label in uid_labels.items() if label == "benign"}
    changed_uids = {uid for uid, label in uid_labels.items() if label == "anomalous-lab"}
    quality = result["quality"]
    capture = result["input_schema"]["packet_capture"]
    coverage = result["feature_coverage"]
    return {
        "schema_version": "drastha-sih-gate2-tls-audit-v1",
        "capture_id": freeze["capture_id"],
        "labels_sha256": next(item["sha256"] for item in freeze["artifacts"]
                              if item["path"].endswith("tls-uid-labels-v1.json")),
        "quality": quality,
        "capture": capture,
        "feature_coverage": coverage,
        "measured_scores_by_label": measured_scores,
        "alerts": [{"subtype": alert["subtype"], "confidence": alert["confidence"],
                    "flow_ids": alert.get("flow_ids", []),
                    "evidence": {item["name"]: item["observed"] for item in alert["evidence"]}}
                   for alert in result["alerts"]],
        "sessions": {"baseline": len(baseline_uids), "changed": len(changed_uids)},
        "tp_sessions": len(alerted_uids & changed_uids),
        "fp_sessions": len(alerted_uids & baseline_uids),
        "fn_sessions": len(changed_uids - alerted_uids),
        "tn_sessions": len(baseline_uids - alerted_uids),
        "anomaly_alerts": len(anomaly_alerts),
        "quality_healthy": quality["status"] == "healthy" and quality["records_accepted"] == 232
                           and quality["records_rejected"] == 0,
        "measured_only": capture["payload_decrypted"] is False
                         and capture["application_payload_retained"] is False
                         and coverage["counts"].get("supplied_compatibility", 0) == 0,
        "limitations": [
            "TLS 1.3 changed sessions are a lab anomaly control, not identified malware.",
            "JA3 extraction is limited to complete cleartext ClientHello in one TCP segment.",
            "The analysis path read only PCAP packet headers/timing and Zeek metadata; it did not decrypt payloads.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-output", type=Path,
                        default=ROOT / "output/sih_gate2_tls_audit.json")
    args = parser.parse_args()
    report = audit()
    path = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"quality_healthy": report["quality_healthy"],
                      "measured_only": report["measured_only"],
                      "coverage": report["feature_coverage"]["counts"],
                      "tp": report["tp_sessions"], "fp": report["fp_sessions"],
                      "fn": report["fn_sessions"], "tn": report["tn_sessions"],
                      "alerts": report["anomaly_alerts"]}, sort_keys=True))
    return 0 if report["quality_healthy"] and report["measured_only"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
