"""Freeze fresh TLS positive/benign controls before detector inference."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data/raw/sih26145-tls-positive-v1"
LABELS = ROOT / "data/manifests/sih26145-tls-positive-labels-v1.json"
UID_LABELS = ROOT / "data/manifests/sih26145-tls-positive-uid-labels-v1.json"
FIXTURE = ROOT / "examples/sih26145_tls_positive_v1.jsonl"
MANIFEST = ROOT / "data/manifests/sih26145-tls-positive-freeze-v1.json"


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def selected() -> tuple[list[dict], dict[str, str]]:
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    if not labels["frozen_before_inference"] or labels["capture_id"] != RAW.name:
        raise ValueError("TLS labels were not frozen before inference")
    entries = [line.split(",") for line in (RAW / "client.csv").read_text(encoding="utf-8").splitlines()]
    expected = labels["expected_sessions"]
    if len(entries) != sum(expected.values()) or Counter(label for _, label, _ in entries) != expected \
            or [int(index) for index, _, _ in entries] != list(range(len(entries))):
        raise ValueError("TLS source identities differ from predeclared labels")
    port_labels: dict[int, list[str]] = {}
    for _, label, port in entries:
        port_labels.setdefault(int(port), []).append(label)
    records: list[dict] = []
    uid_labels: dict[str, str] = {}
    for name in ("conn.log", "ssl.log"):
        rows = [json.loads(line) for line in (RAW / "zeek" / name).read_text(encoding="utf-8").splitlines() if line]
        if len(rows) != len(entries):
            raise ValueError(f"Expected {len(entries)} Zeek {name} records")
        rows.sort(key=lambda row: (float(row["ts"]), row["uid"]))
        occurrence: dict[int, int] = {}
        for row in rows:
            port = row.get("id.orig_p")
            if (row.get("id.orig_h"), row.get("id.resp_h"), row.get("id.resp_p")) != \
                    ("10.39.0.2", "10.39.0.1", 443) or port not in port_labels:
                raise ValueError("Unexpected TLS endpoint/source port")
            uid = row["uid"]
            if name == "conn.log":
                position = occurrence.get(port, 0)
                if position >= len(port_labels[port]):
                    raise ValueError("Reused TLS source port has no matching source label")
                label = port_labels[port][position]
                occurrence[port] = position + 1
            else:
                if uid not in uid_labels:
                    raise ValueError("TLS SSL UID has no connection record")
                label = uid_labels[uid]
                row = {**row, "transport": "tls"}  # native mixed-log adapter only
            if uid in uid_labels and uid_labels[uid] != label:
                raise ValueError("TLS UID/label collision")
            uid_labels[uid] = label
            records.append(row)
    if len(uid_labels) != len(entries):
        raise ValueError("TLS session UID count mismatch")
    records.sort(key=lambda row: (float(row["ts"]), 0 if "version" in row else 1, row["uid"]))
    return records, uid_labels


def freeze() -> dict:
    if any(path.exists() for path in (UID_LABELS, FIXTURE, MANIFEST)):
        raise ValueError("Refusing to overwrite frozen TLS evidence")
    rows, uid_labels = selected()
    FIXTURE.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                               for row in rows), encoding="utf-8", newline="\n")
    UID_LABELS.write_text(json.dumps(uid_labels, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8", newline="\n")
    paths = [LABELS, UID_LABELS, FIXTURE, RAW / "traffic.pcap", RAW / "client.csv",
             RAW / "zeek/conn.log", RAW / "zeek/ssl.log"]
    manifest = {
        "schema_version": "drastha-sih-tls-positive-freeze-v1",
        "capture_id": RAW.name, "records": len(rows), "sessions": len(uid_labels),
        "artifacts": [{"path": str(path.relative_to(ROOT)).replace("\\", "/"),
                       "sha256": digest(path), "committed": not path.is_relative_to(RAW)}
                      for path in paths],
        "inference_run_at_freeze": False, "payload_decrypted_by_analyser": False,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
    return manifest


def verify() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for item in manifest["artifacts"]:
        if digest(ROOT / item["path"]) != item["sha256"]:
            raise ValueError(f"Frozen TLS artifact changed: {item['path']}")
    rows, uid_labels = selected()
    if rows != [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()] \
            or uid_labels != json.loads(UID_LABELS.read_text(encoding="utf-8")):
        raise ValueError("Frozen TLS fixture/labels no longer derive from raw capture")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("freeze", "verify"))
    args = parser.parse_args()
    result = freeze() if args.action == "freeze" else verify()
    print(json.dumps({"records": result["records"], "sessions": result["sessions"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
