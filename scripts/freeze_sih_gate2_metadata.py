"""Freeze fresh real-tool Zeek metadata independently of inference output."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data/raw/sih26145-gate2-metadata-v1"
LABELS = ROOT / "data/manifests/sih26145-gate2-metadata-labels-v1.json"
FIXTURES = ROOT / "examples/sih26145_gate2_metadata_v1"
MANIFEST = ROOT / "data/manifests/sih26145-gate2-metadata-freeze-v1.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(name: str) -> list[dict]:
    if name in {"slow-http", "c2-timing"}:
        source = RAW / "zeek/conn.log"
        port = {"slow-http": 18081, "c2-timing": 18443}[name]
        rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line]
        rows = [row for row in rows if row.get("id.orig_h") == "10.34.0.2"
                and row.get("id.resp_h") == "10.34.0.1"
                and row.get("id.resp_p") == port]
    elif name == "dns-tunnel":
        source = RAW / "zeek/dns.log"
        rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line]
        rows = [row for row in rows if row.get("id.orig_h") == "10.34.0.2"
                and row.get("id.resp_h") == "10.34.0.1"
                and str(row.get("query", "")).rstrip(".").endswith("g2.test")]
    else:
        raise ValueError(f"Unknown frozen scenario: {name}")
    rows.sort(key=lambda row: (float(row["ts"]), str(row.get("uid", "")),
                               int(row.get("trans_id", 0))))
    if not rows:
        raise ValueError(f"No measured Zeek rows for {name}")
    return rows


def freeze() -> dict:
    if MANIFEST.exists() or FIXTURES.exists():
        raise ValueError("Refusing to overwrite frozen metadata evidence")
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    if not labels.get("frozen_before_inference") or labels["capture_id"] != RAW.name:
        raise ValueError("Metadata label/capture identity mismatch")
    FIXTURES.mkdir(parents=True)
    artifacts = []
    for scenario in labels["scenarios"]:
        name = scenario["name"]
        path = FIXTURES / f"{name}.jsonl"
        rows = records(name)
        path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                                for row in rows), encoding="utf-8", newline="\n")
        artifacts.append({"scenario": name, "records": len(rows),
                          "fixture": str(path.relative_to(ROOT)).replace("\\", "/"),
                          "fixture_sha256": digest(path)})
    manifest = {
        "schema_version": "drastha-sih-gate2-metadata-freeze-v1",
        "capture_id": RAW.name,
        "labels": str(LABELS.relative_to(ROOT)).replace("\\", "/"),
        "labels_sha256": digest(LABELS),
        "raw_pcap": str((RAW / "traffic.pcap").relative_to(ROOT)).replace("\\", "/"),
        "raw_pcap_sha256": digest(RAW / "traffic.pcap"),
        "raw_conn_sha256": digest(RAW / "zeek/conn.log"),
        "raw_dns_sha256": digest(RAW / "zeek/dns.log"),
        "artifacts": artifacts,
        "inference_run_at_freeze": False,
        "raw_captures_committed": False,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
    return manifest


def verify() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    checks = [(ROOT / manifest["labels"], manifest["labels_sha256"]),
              (ROOT / manifest["raw_pcap"], manifest["raw_pcap_sha256"]),
              (RAW / "zeek/conn.log", manifest["raw_conn_sha256"]),
              (RAW / "zeek/dns.log", manifest["raw_dns_sha256"])]
    checks += [(ROOT / item["fixture"], item["fixture_sha256"])
               for item in manifest["artifacts"]]
    for path, expected in checks:
        if digest(path) != expected:
            raise ValueError(f"Frozen metadata evidence changed: {path}")
    for item in manifest["artifacts"]:
        fixture_rows = [json.loads(line) for line in
                        (ROOT / item["fixture"]).read_text(encoding="utf-8").splitlines()]
        if fixture_rows != records(item["scenario"]):
            raise ValueError(f"Derived metadata changed: {item['scenario']}")
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
