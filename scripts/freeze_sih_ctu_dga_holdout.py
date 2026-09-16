"""Create or verify the prediction-blind CTU DNS Threats DGA holdout."""
from __future__ import annotations

import argparse
import csv
import gzip
from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LABELS = ROOT / "data/manifests/sih26145-ctu-dga-holdout-labels-v1.json"
FIXTURE = ROOT / "examples/sih26145_ctu_dga_holdout_v1.jsonl"
MANIFEST = ROOT / "data/manifests/sih26145-ctu-dga-holdout-freeze-v1.json"


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def normalized(value: str) -> str:
    return value.strip().lower().rstrip(".")


def selected(labels: dict) -> tuple[list[dict], dict[str, int]]:
    source = ROOT / labels["source_path"]
    if digest(source) != labels["source_sha256"] or source.stat().st_size != labels["source_size"]:
        raise ValueError("Pinned CTU DNS Threats source changed")
    pools: dict[int, set[str]] = {0: set(), 1: set()}
    source_counts = {"benign": 0, "dga": 0, "dns_tunnelling_excluded": 0}
    with gzip.open(source, "rt", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ["domain", "class"]:
            raise ValueError("Unexpected CTU DNS Threats CSV schema")
        for row in reader:
            label = int(row["class"])
            if label not in (0, 1, 2):
                raise ValueError("Unexpected CTU DNS Threats class")
            source_counts[labels["class_mapping"][str(label)]] += 1
            domain = normalized(row["domain"])
            if label in pools and domain:
                pools[label].add(domain)
    count = int(labels["sample_records_per_evaluated_class"])
    rows = []
    for label in (0, 1):
        ordered = sorted(pools[label], key=lambda domain: sha256(
            f"{labels['seed']}|{label}|{domain}".encode()).digest())
        if len(ordered) < count:
            raise ValueError(f"Insufficient distinct source records for class {label}")
        rows.extend({"domain": domain, "label": label,
                     "source_class": labels["class_mapping"][str(label)]}
                    for domain in ordered[:count])
    rows.sort(key=lambda row: sha256(
        f"{labels['seed']}|fixture|{row['label']}|{row['domain']}".encode()).digest())
    return rows, source_counts


def freeze() -> dict:
    if FIXTURE.exists() or MANIFEST.exists():
        raise ValueError("Refusing to overwrite frozen CTU holdout")
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    if not labels.get("frozen_before_inference"):
        raise ValueError("Holdout contract was not frozen before inference")
    rows, source_counts = selected(labels)
    FIXTURE.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                               for row in rows), encoding="utf-8", newline="\n")
    manifest = {
        "schema_version": "drastha-sih-ctu-dga-holdout-freeze-v1",
        "labels": str(LABELS.relative_to(ROOT)).replace("\\", "/"),
        "labels_sha256": digest(LABELS),
        "source_sha256": labels["source_sha256"],
        "fixture": str(FIXTURE.relative_to(ROOT)).replace("\\", "/"),
        "fixture_sha256": digest(FIXTURE),
        "records": len(rows),
        "class_counts": {"benign": sum(row["label"] == 0 for row in rows),
                         "dga": sum(row["label"] == 1 for row in rows)},
        "source_class_counts": source_counts,
        "inference_run_at_freeze": False,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
    return manifest


def verify() -> dict:
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if digest(LABELS) != manifest["labels_sha256"]:
        raise ValueError("CTU holdout contract changed")
    rows, source_counts = selected(labels)
    actual = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]
    if actual != rows or digest(FIXTURE) != manifest["fixture_sha256"]:
        raise ValueError("Frozen CTU holdout changed")
    if source_counts != manifest["source_class_counts"]:
        raise ValueError("CTU source class counts changed")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("freeze", "verify"))
    args = parser.parse_args()
    report = freeze() if args.action == "freeze" else verify()
    print(json.dumps({key: report[key] for key in
                      ("records", "class_counts", "inference_run_at_freeze")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
