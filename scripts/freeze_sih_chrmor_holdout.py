"""Create-only first-use cross-publisher DNS campaign holdout, no domain IO."""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
LABELS = ROOT / "data/manifests/sih26145-chrmor-holdout-labels-v1.json"
DIRECTORY = ROOT / "examples/sih26145_chrmor_holdout_v1"
MANIFEST = ROOT / "data/manifests/sih26145-chrmor-holdout-freeze-v1.json"
VALID = re.compile(r"(?=^.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def selected() -> dict[str, list[dict]]:
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    source = ROOT / labels["source_path"]
    if not labels["frozen_before_inference"] or digest(source) != labels["source_sha256"]:
        raise ValueError("Pinned external publisher source changed")
    pools: dict[tuple[str, str], set[str]] = {}
    with source.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.reader(stream):
            if len(row) != 3:
                raise ValueError("Unexpected publisher CSV format")
            label, family, domain = (item.strip().lower() for item in row)
            if VALID.fullmatch(domain):
                pools.setdefault((label, family), set()).add(domain)
    output = {}
    used: set[str] = set()
    for scenario in labels["scenarios"]:
        candidates = pools.get((scenario["label"], scenario["family"]), set()) - used
        ordered = sorted(candidates, key=lambda item: sha256(
            f"{labels['seed']}|{scenario['name']}|{item}".encode()).digest())
        domains = ordered[:scenario["count"]]
        if len(domains) != scenario["count"]:
            raise ValueError(f"Not enough distinct publisher names for {scenario['name']}")
        used.update(domains)
        output[scenario["name"]] = [{
            "ts": 1790100000 + index * scenario["interval_seconds"],
            "uid": f"CH-{scenario['name']}-{index:03d}",
            "id.orig_h": "10.41.0.2" if scenario["label"] == "dga" else "10.41.0.3",
            "id.orig_p": 40000 + index, "id.resp_h": "10.41.0.1", "id.resp_p": 53,
            "proto": "udp", "query": domain, "qtype_name": "A",
            "rcode_name": scenario["rcode_name"], "trans_id": index + 1,
        } for index, domain in enumerate(domains)]
    return output


def freeze() -> dict:
    if DIRECTORY.exists() or MANIFEST.exists():
        raise ValueError("Refusing to overwrite first-use publisher holdout")
    expected = selected()
    DIRECTORY.mkdir(parents=True)
    artifacts = []
    for name, rows in expected.items():
        path = DIRECTORY / f"{name}.jsonl"
        path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                                for row in rows), encoding="utf-8", newline="\n")
        artifacts.append({"scenario": name, "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                          "sha256": digest(path), "records": len(rows)})
    label_doc = json.loads(LABELS.read_text(encoding="utf-8"))
    report = {"schema_version": "drastha-sih-chrmor-holdout-freeze-v1",
              "source_commit": label_doc["source_commit"],
              "source_path": label_doc["source_path"], "source_sha256": label_doc["source_sha256"],
              "labels": str(LABELS.relative_to(ROOT)).replace("\\", "/"),
              "labels_sha256": digest(LABELS), "artifacts": artifacts,
              "inference_run_at_freeze": False, "actual_dns_responses_captured": False}
    MANIFEST.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
    return report


def verify() -> dict:
    report = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if digest(LABELS) != report["labels_sha256"]:
        raise ValueError("Publisher holdout labels changed")
    expected = selected()
    for item in report["artifacts"]:
        path = ROOT / item["path"]
        actual = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        if digest(path) != item["sha256"] or actual != expected[item["scenario"]]:
            raise ValueError(f"Publisher holdout fixture changed: {item['scenario']}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("freeze", "verify"))
    args = parser.parse_args()
    result = freeze() if args.action == "freeze" else verify()
    print(json.dumps({"scenarios": len(result["artifacts"]),
                      "records": sum(item["records"] for item in result["artifacts"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
