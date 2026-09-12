"""Create a fresh checksum-pinned DNS fixture from published UMUDGA domains."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LABELS = ROOT / "data/manifests/sih26145-gate2-dga-labels-v1.json"
MANIFEST = ROOT / "data/manifests/sih26145-gate2-dga-freeze-v1.json"
FIXTURES = ROOT / "examples/sih26145_gate2_dga_v1"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sample(path: Path, seed: str) -> list[str]:
    domains = {line.strip().lower().rstrip(".") for line in path.read_text(encoding="utf-8").splitlines()
               if line.strip() and "." in line}
    ranked = sorted(domains, key=lambda name: (hashlib.sha256(f"{seed}|{name}".encode()).digest(), name))
    if len(ranked) < 40:
        raise ValueError("Published source has fewer than 40 unique domains")
    return ranked[:40]


def rows(domains: list[str], label: str) -> list[dict]:
    return [{"ts": 1789400000.0 + index * .1, "uid": f"G2-{label}-{index:03d}",
             "id.orig_h": "10.38.0.2" if label == "dga" else "10.38.0.3",
             "id.resp_h": "10.38.0.1", "id.orig_p": 40000 + index,
             "id.resp_p": 53, "proto": "udp", "query": domain,
             "qtype_name": "A", "trans_id": index + 1}
            for index, domain in enumerate(domains)]


def freeze() -> dict:
    if MANIFEST.exists() or FIXTURES.exists():
        raise ValueError("Refusing to overwrite frozen public DGA fixture")
    labels = json.loads(LABELS.read_text(encoding="utf-8"))
    if not labels.get("frozen_before_inference"):
        raise ValueError("Public DGA labels were not frozen")
    FIXTURES.mkdir(parents=True)
    artifacts = []
    for label, key in (("dga", "source_malicious"), ("benign", "source_benign")):
        source = ROOT / labels[key]
        domains = sample(source, labels["seed"])
        path = FIXTURES / f"{label}.jsonl"
        path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                                for row in rows(domains, label)), encoding="utf-8", newline="\n")
        artifacts.append({"label": label, "source": labels[key], "source_sha256": digest(source),
                          "fixture": str(path.relative_to(ROOT)).replace("\\", "/"),
                          "fixture_sha256": digest(path), "records": len(domains)})
    manifest = {"schema_version": "drastha-sih-gate2-dga-freeze-v1",
                "labels": str(LABELS.relative_to(ROOT)).replace("\\", "/"),
                "labels_sha256": digest(LABELS), "artifacts": artifacts,
                "inference_run_at_freeze": False, "publisher_raw_committed": False}
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
    return manifest


def verify() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if digest(ROOT / manifest["labels"]) != manifest["labels_sha256"]:
        raise ValueError("Public DGA labels changed after freeze")
    labels = json.loads((ROOT / manifest["labels"]).read_text(encoding="utf-8"))
    for item in manifest["artifacts"]:
        source = ROOT / item["source"]
        fixture = ROOT / item["fixture"]
        if digest(source) != item["source_sha256"] or digest(fixture) != item["fixture_sha256"]:
            raise ValueError(f"Public DGA evidence changed: {item['label']}")
        expected = rows(sample(source, labels["seed"]), item["label"])
        actual = [json.loads(line) for line in fixture.read_text(encoding="utf-8").splitlines()]
        if actual != expected or len(actual) != item["records"]:
            raise ValueError(f"Public DGA selection changed: {item['label']}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("freeze", "verify"))
    args = parser.parse_args()
    result = freeze() if args.action == "freeze" else verify()
    print(json.dumps({"records": sum(item["records"] for item in result["artifacts"]),
                      "labels_sha256": result["labels_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
