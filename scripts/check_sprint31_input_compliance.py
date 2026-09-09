from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.upload_analysis import analyse_uploaded_replay


class _Repository:
    def import_records(self, incidents, alerts, feedback=None):
        return {"incidents": len(incidents), "alerts": len(alerts), "feedback": 0}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyse(path: Path) -> dict:
    report = analyse_uploaded_replay(path.name, path.read_text(encoding="utf-8"), _Repository())
    return {
        "records": report["quality"]["records_accepted"],
        "rejected": report["quality"]["records_rejected"],
        "quality": report["quality"]["status"],
        "schema": report["input_schema"]["schema"],
        "record_types": report["input_schema"]["record_types"],
        "findings": len(report["alerts"]),
        "incidents": len(report["incidents"]),
        "evaluation": report["evaluation"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Sprint 31 SIH input compliance")
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    manifest_path = ROOT / "data/manifests/sih26145-input-compliance-v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifacts = {}
    for entry in manifest["artifacts"]:
        path = ROOT / entry["path"]
        actual = digest(path)
        if actual != entry["sha256"]:
            raise SystemExit(f"Checksum mismatch: {entry['path']}")
        result = analyse(path)
        if result["records"] != entry["records"] or result["rejected"] or result["quality"] != "healthy":
            raise SystemExit(f"Input compliance failed: {entry['path']}: {result}")
        if entry["format"] in {"netflow", "ipfix", "sflow"} and result["schema"] != entry["format"]:
            raise SystemExit(f"Wrong detected format: {entry['path']}: {result['schema']}")
        artifacts[entry["path"]] = {"sha256": actual, **result}

    mixed = analyse(ROOT / "examples/drastha_mixed_evaluation_v3.jsonl")
    metrics = mixed["evaluation"]
    expected = {"true_positive": 8, "false_positive": 0, "false_negative": 0, "true_negative": 86}
    if mixed["records"] != 452 or mixed["quality"] != "healthy" or any(metrics[key] != value for key, value in expected.items()):
        raise SystemExit(f"Mixed evaluation regression: {mixed}")

    report = {
        "schema_version": "drastha-sprint31-input-compliance-audit-v1",
        "passed": True,
        "manifest": str(manifest_path.relative_to(ROOT)).replace("\\", "/"),
        "manifest_sha256": digest(manifest_path),
        "artifacts": artifacts,
        "mixed_evaluation_regression": mixed,
        "claims": {
            "collector_decoded_netflow_ipfix_sflow": True,
            "actual_local_iperf3_hping3_pcap_to_zeek": True,
            "raw_binary_flow_wire_decoding": False,
            "external_exporter_interoperability": False,
            "production_accuracy": False,
        },
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report_output:
        output = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
        output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
