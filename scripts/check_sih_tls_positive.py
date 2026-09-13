"""Score frozen new TLS lab PCAP via deployed passive replay, no supplied scores."""
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
from freeze_sih_tls_positive import FIXTURE, RAW, UID_LABELS, verify


def audit() -> dict:
    frozen = verify()
    uid_labels = json.loads(UID_LABELS.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="drastha-tls-positive-") as directory:
        result = analyse_replay_file(FIXTURE, IncidentRepository(Path(directory) / "audit.db"),
                                     root=ROOT, profile=DEPLOYMENT_BASELINE,
                                     packet_capture=RAW / "traffic.pcap")
    alerts = [alert for alert in result["alerts"]
              if alert["subtype"] == "encrypted_session_metadata_anomaly"]
    unexpected = sorted({alert["subtype"] for alert in result["alerts"]
                         if alert["subtype"] != "encrypted_session_metadata_anomaly"})
    uids = {uid for alert in alerts for uid in alert["flow_ids"]}
    positives = {uid for uid, label in uid_labels.items() if label == "paced-size-anomaly"}
    negatives = set(uid_labels) - positives
    quality = result["quality"]
    capture = result["input_schema"]["packet_capture"]
    coverage = result["feature_coverage"]["counts"]
    measured = (capture["payload_decrypted"] is False and
                capture["application_payload_retained"] is False and
                coverage.get("supplied_compatibility", 0) == 0)
    healthy = (quality["status"] == "healthy" and quality["records_accepted"] == 244
               and quality["records_rejected"] == quality["out_of_order_records"] == 0)
    return {
        "schema_version": "drastha-sih-tls-positive-audit-v1",
        "capture_id": frozen["capture_id"], "quality": quality,
        "capture": capture, "feature_coverage": result["feature_coverage"],
        "tp": len(uids & positives), "fp": len(uids & negatives),
        "fn": len(positives - uids), "tn": len(negatives - uids),
        "alerts": [{"subtype": alert["subtype"], "flow_ids": alert["flow_ids"],
                    "confidence": alert["confidence"],
                    "evidence": {item["name"]: item["observed"] for item in alert["evidence"]}}
                   for alert in alerts],
        "unexpected_alert_subtypes": unexpected,
        "quality_healthy": healthy, "measured_only": measured,
        "passed": healthy and measured and len(alerts) >= 1 and len(uids & positives) >= 1
                  and not (uids & negatives) and not unexpected,
        "limitations": [
            "The paced and larger encrypted records are an anomaly control, not identified malware.",
            "A rare benign TLS fingerprint alone must not trigger an anomaly alert.",
            "These are completed short lab flows; the analyser itself made no connection or decryption attempt.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-output", type=Path,
                        default=ROOT / "output/sih_tls_positive_audit.json")
    args = parser.parse_args()
    report = audit()
    path = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")
    print(json.dumps({"passed": report["passed"], "tp": report["tp"],
                      "fp": report["fp"], "fn": report["fn"], "tn": report["tn"],
                      "derived": report["feature_coverage"]["counts"].get("derived", 0)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
