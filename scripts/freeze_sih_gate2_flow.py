"""Freeze raw/derived hashes and labels before running Gate 2 inference."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data/raw/sih26145-gate2-flow-v3"
LABELS = ROOT / "data/manifests/sih26145-gate2-flow-labels-v2.json"
FIXTURES = ROOT / "examples/sih26145_gate2_flow_v3"
MANIFEST = ROOT / "data/manifests/sih26145-gate2-flow-freeze-v1.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def selected(name: str) -> list[dict]:
    source = RAW / name / "zeek/conn.log"
    rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line]
    rows = [row for row in rows if row.get("proto") in {"tcp", "udp"}
            and row.get("id.orig_h") == "10.36.0.2"
            and row.get("id.resp_h") == "10.36.0.1"]
    rows.sort(key=lambda row: (float(row["ts"]), str(row["uid"])))
    if not rows or len({row["uid"] for row in rows}) != len(rows):
        raise ValueError(f"Missing records or duplicate UIDs in {name}")
    return rows


def freeze() -> dict:
    if MANIFEST.exists() or FIXTURES.exists():
        raise ValueError("Refusing to overwrite frozen Gate 2 evidence")
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    if not labels.get("frozen_before_inference") or labels["capture_id"] != RAW.name:
        raise ValueError("Gate 2 labels/capture identity mismatch")
    FIXTURES.mkdir(parents=True)
    artifacts = []
    for scenario in labels["scenarios"]:
        name = scenario["name"]
        rows = selected(name)
        path = FIXTURES / f"{name}.jsonl"
        path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                                for row in rows), encoding="utf-8", newline="\n")
        raw_pcap = RAW / name / "traffic.pcap"
        raw_conn = RAW / name / "zeek/conn.log"
        artifacts.append({
            "scenario": name,
            "records": len(rows),
            "fixture": str(path.relative_to(ROOT)).replace("\\", "/"),
            "fixture_sha256": digest(path),
            "raw_pcap": str(raw_pcap.relative_to(ROOT)).replace("\\", "/"),
            "raw_pcap_sha256": digest(raw_pcap),
            "raw_conn_sha256": digest(raw_conn),
        })
    manifest = {
        "schema_version": "drastha-sih-gate2-freeze-v1",
        "labels": str(LABELS.relative_to(ROOT)).replace("\\", "/"),
        "labels_sha256": digest(LABELS),
        "generator": "scripts/generate_sih_gate2_flow_capture.sh",
        "capture_id": RAW.name,
        "artifacts": artifacts,
        "inference_run_at_freeze": False,
        "raw_captures_committed": False,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
    return manifest


def verify() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if digest(ROOT / manifest["labels"]) != manifest["labels_sha256"]:
        raise ValueError("Gate 2 labels changed after freeze")
    for item in manifest["artifacts"]:
        if digest(ROOT / item["fixture"]) != item["fixture_sha256"]:
            raise ValueError(f"Derived fixture changed: {item['scenario']}")
        if digest(ROOT / item["raw_pcap"]) != item["raw_pcap_sha256"]:
            raise ValueError(f"Raw capture changed: {item['scenario']}")
        raw_conn = RAW / item["scenario"] / "zeek/conn.log"
        if digest(raw_conn) != item["raw_conn_sha256"]:
            raise ValueError(f"Raw Zeek log changed: {item['scenario']}")
        if selected(item["scenario"]) != [json.loads(line) for line in
                (ROOT / item["fixture"]).read_text(encoding="utf-8").splitlines()]:
            raise ValueError(f"Derived records changed: {item['scenario']}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("freeze", "verify"))
    args = parser.parse_args()
    result = freeze() if args.action == "freeze" else verify()
    print(json.dumps({"capture_id": result["capture_id"], "scenarios": len(result["artifacts"]),
                      "records": sum(item["records"] for item in result["artifacts"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
