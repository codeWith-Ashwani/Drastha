"""Create-only passive DNS campaign controls from frozen publisher strings."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LABELS = ROOT / "data/manifests/sih26145-dga-campaign-labels-v1.json"
SOURCE_FREEZE = ROOT / "data/manifests/sih26145-gate2-dga-freeze-v1.json"
DIRECTORY = ROOT / "examples/sih26145_dga_campaign_v1"
MANIFEST = ROOT / "data/manifests/sih26145-dga-campaign-freeze-v1.json"


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def expected_rows() -> dict[str, list[dict]]:
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    old = json.loads(SOURCE_FREEZE.read_text(encoding="utf-8"))
    if not labels["frozen_before_inference"] or old["inference_run_at_freeze"]:
        raise ValueError("DGA source or new scenario labels are not frozen")
    sources = {}
    for item in old["artifacts"]:
        path = ROOT / item["fixture"]
        if digest(path) != item["fixture_sha256"]:
            raise ValueError("Publisher-derived DGA source fixture changed")
        sources[item["label"]] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    output = {}
    for scenario in labels["scenarios"]:
        name = scenario["name"]
        rows = []
        for index, source in enumerate(sources[scenario["source"]]):
            # Existing publisher string remains unchanged; the resolver outcome
            # and timing are explicitly simulated scenario controls.
            rows.append({**source, "ts": 1790000000 + index * scenario["interval_seconds"],
                         "uid": f"{name}-{index:03d}",
                         "id.orig_h": "10.40.0.2" if scenario["expected"] != "benign" else "10.40.0.3",
                         "rcode_name": scenario["response_code"]})
        output[name] = rows
    return output


def freeze() -> dict:
    if DIRECTORY.exists() or MANIFEST.exists():
        raise ValueError("Refusing to overwrite frozen DGA campaign controls")
    rows = expected_rows()
    DIRECTORY.mkdir(parents=True)
    artifacts = []
    for name, records in rows.items():
        path = DIRECTORY / f"{name}.jsonl"
        path.write_text("".join(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                                for record in records), encoding="utf-8", newline="\n")
        artifacts.append({"scenario": name, "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                          "sha256": digest(path), "records": len(records)})
    manifest = {"schema_version": "drastha-sih-dga-campaign-freeze-v1",
                "source_freeze": str(SOURCE_FREEZE.relative_to(ROOT)).replace("\\", "/"),
                "source_freeze_sha256": digest(SOURCE_FREEZE),
                "labels": str(LABELS.relative_to(ROOT)).replace("\\", "/"),
                "labels_sha256": digest(LABELS), "artifacts": artifacts,
                "inference_run_at_freeze": False, "actual_dns_responses_captured": False}
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
    return manifest


def verify() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if digest(SOURCE_FREEZE) != manifest["source_freeze_sha256"] or \
            digest(LABELS) != manifest["labels_sha256"]:
        raise ValueError("DGA source or scenario labels changed")
    expected = expected_rows()
    for item in manifest["artifacts"]:
        path = ROOT / item["path"]
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        if digest(path) != item["sha256"] or rows != expected[item["scenario"]]:
            raise ValueError(f"DGA campaign fixture changed: {item['scenario']}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("freeze", "verify"))
    args = parser.parse_args()
    report = freeze() if args.action == "freeze" else verify()
    print(json.dumps({"scenarios": len(report["artifacts"]),
                      "records": sum(item["records"] for item in report["artifacts"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
