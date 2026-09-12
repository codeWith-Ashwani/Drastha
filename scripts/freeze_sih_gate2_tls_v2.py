"""Adapt frozen native Zeek SSL rows to mixed JSONL without invented features."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from freeze_sih_gate2_tls import ROOT, MANIFEST as V1_MANIFEST, selected, verify as verify_v1, digest


FIXTURE = ROOT / "examples/sih26145_gate2_tls_v2.jsonl"
MANIFEST = ROOT / "data/manifests/sih26145-gate2-tls-freeze-v2.json"


def adapted() -> list[dict]:
    rows, _labels = selected()
    return [{**row, "transport": "tls"} if "version" in row else row for row in rows]


def freeze() -> dict:
    verify_v1()
    if FIXTURE.exists() or MANIFEST.exists():
        raise ValueError("Refusing to overwrite adapted TLS fixture")
    rows = adapted()
    FIXTURE.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                               for row in rows), encoding="utf-8", newline="\n")
    manifest = {"schema_version": "drastha-sih-gate2-tls-adapter-v2",
                "source_freeze": str(V1_MANIFEST.relative_to(ROOT)).replace("\\", "/"),
                "source_freeze_sha256": digest(V1_MANIFEST),
                "fixture": str(FIXTURE.relative_to(ROOT)).replace("\\", "/"),
                "fixture_sha256": digest(FIXTURE),
                "records": len(rows),
                "adapter_change": "transport=tls on native Zeek ssl.log rows only",
                "labels_or_anomaly_scores_added": False}
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
    return manifest


def verify() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    verify_v1()
    if digest(V1_MANIFEST) != manifest["source_freeze_sha256"] or \
            digest(FIXTURE) != manifest["fixture_sha256"]:
        raise ValueError("Adapted TLS evidence changed")
    actual = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]
    if actual != adapted() or len(actual) != manifest["records"]:
        raise ValueError("Adapted TLS rows changed")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("freeze", "verify"))
    args = parser.parse_args()
    result = freeze() if args.action == "freeze" else verify()
    print(json.dumps({"records": result["records"], "adapter_change": result["adapter_change"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
