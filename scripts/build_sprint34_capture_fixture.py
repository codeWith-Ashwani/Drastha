from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data/raw/sih26145-real-tools-v1/zeek"
BENIGN = ROOT / "data/raw/sih26145-real-tools-v1/benign-health/zeek/conn.log"
OUTPUT = ROOT / "examples/sih26145_real_tools_v1.jsonl"


def records() -> list[dict]:
    selected: list[dict] = []
    for name in ("conn.log", "dns.log"):
        path = RAW / name
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{name}:{line_number}: expected an object")
            if name == "conn.log" and int(value.get("id.resp_p", 0)) not in {18081, 18443}:
                continue
            value["_drastha_source"] = f"zeek:sprint34:{name[:-4]}"
            selected.append(value)
    for line_number, line in enumerate(BENIGN.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"benign conn.log:{line_number}: expected an object")
        if int(value.get("id.resp_p", 0)) != 18444:
            continue
        value["_drastha_source"] = "zeek:sprint34:benign-health"
        selected.append(value)
    selected.sort(
        key=lambda item: (
            float(item["ts"]),
            0 if "query" in item else 1,
            str(item.get("uid", "")),
            int(item.get("trans_id", 0)),
        )
    )
    return selected


def rendered() -> str:
    return "".join(
        json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
        for item in records()
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the derived Sprint 34 Zeek fixture")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            raise SystemExit("Sprint 34 fixture does not match the local captured Zeek evidence")
        print(f"Verified {OUTPUT.relative_to(ROOT)}")
        return 0
    if OUTPUT.exists() and not args.refresh:
        raise SystemExit(f"Refusing to overwrite existing fixture: {OUTPUT}")
    OUTPUT.write_text(expected, encoding="utf-8", newline="\n")
    print(f"Created {OUTPUT.relative_to(ROOT)} with {len(expected.splitlines())} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
