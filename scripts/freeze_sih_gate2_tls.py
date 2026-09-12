"""Freeze captured TLS logs, PCAP and generator labels before inference."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data/raw/sih26145-gate2-tls-v1"
LABELS = ROOT / "data/manifests/sih26145-gate2-tls-labels-v1.json"
UID_LABELS = ROOT / "data/manifests/sih26145-gate2-tls-uid-labels-v1.json"
MANIFEST = ROOT / "data/manifests/sih26145-gate2-tls-freeze-v1.json"
FIXTURE = ROOT / "examples/sih26145_gate2_tls_v1.jsonl"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def selected() -> tuple[list[dict], dict[str, str]]:
    client_lines = [line.split(",") for line in (RAW / "client.csv").read_text(encoding="utf-8").splitlines()]
    ports: dict[int, list[str]] = {}
    for _index, label, port in client_lines:
        ports.setdefault(int(port), []).append(label)
    if len(client_lines) != 116 or [int(item[0]) for item in client_lines] != list(range(116)) \
            or [item[1] for item in client_lines].count("benign") != 110:
        raise ValueError("TLS client labels/ports do not match frozen generator contract")
    records = []
    uid_labels: dict[str, str] = {}
    for log_name in ("conn.log", "ssl.log"):
        path = RAW / "zeek" / log_name
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        if len(rows) != 116:
            raise ValueError(f"Expected 116 native Zeek {log_name} records")
        rows.sort(key=lambda row: (float(row["ts"]), row["uid"]))
        port_occurrence: dict[int, int] = {}
        for row in rows:
            if row.get("id.orig_h") != "10.37.0.2" or row.get("id.resp_h") != "10.37.0.1" \
                    or row.get("id.resp_p") != 443 or row.get("id.orig_p") not in ports:
                raise ValueError(f"Unexpected TLS endpoint/port in {log_name}")
            uid = row["uid"]
            port = row["id.orig_p"]
            if log_name == "conn.log":
                occurrence = port_occurrence.get(port, 0)
                if occurrence >= len(ports[port]):
                    raise ValueError("More TLS sessions than generator port records")
                label = ports[port][occurrence]
                port_occurrence[port] = occurrence + 1
            else:
                if uid not in uid_labels:
                    raise ValueError("TLS SSL row has no matching connection UID")
                label = uid_labels[uid]
            if uid in uid_labels and uid_labels[uid] != label:
                raise ValueError("TLS UID label collision")
            uid_labels[uid] = label
            records.append(row)
    if len(uid_labels) != 116:
        raise ValueError("TLS connection/SSL logs did not join to 116 UIDs")
    records.sort(key=lambda row: (float(row["ts"]), 0 if "version" in row else 1, row["uid"]))
    return records, uid_labels


def freeze() -> dict:
    if MANIFEST.exists() or FIXTURE.exists() or UID_LABELS.exists():
        raise ValueError("Refusing to overwrite frozen TLS evidence")
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    if not labels.get("frozen_before_inference") or labels["capture_id"] != RAW.name:
        raise ValueError("TLS source-label contract not frozen")
    records, uid_labels = selected()
    FIXTURE.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                               for row in records), encoding="utf-8", newline="\n")
    UID_LABELS.write_text(json.dumps(uid_labels, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8", newline="\n")
    artifacts = [LABELS, UID_LABELS, FIXTURE, RAW / "traffic.pcap", RAW / "client.csv",
                 RAW / "zeek/conn.log", RAW / "zeek/ssl.log"]
    manifest = {"schema_version": "drastha-sih-gate2-tls-freeze-v1",
                "capture_id": RAW.name, "records": len(records), "sessions": len(uid_labels),
                "artifacts": [{"path": str(path.relative_to(ROOT)).replace("\\", "/"),
                               "sha256": digest(path), "committed": not path.is_relative_to(RAW)}
                              for path in artifacts],
                "inference_run_at_freeze": False,
                "payload_decrypted_by_analyser": False}
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
    return manifest


def verify() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for item in manifest["artifacts"]:
        if digest(ROOT / item["path"]) != item["sha256"]:
            raise ValueError(f"Frozen TLS evidence changed: {item['path']}")
    records, uid_labels = selected()
    fixture_rows = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]
    if records != fixture_rows or uid_labels != json.loads(UID_LABELS.read_text(encoding="utf-8")):
        raise ValueError("TLS fixture/UID labels no longer match raw capture")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("freeze", "verify"))
    args = parser.parse_args()
    result = freeze() if args.action == "freeze" else verify()
    print(json.dumps({"records": result["records"], "sessions": result["sessions"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
