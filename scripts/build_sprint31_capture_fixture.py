from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data/raw/sih26145-tools-v1/zeek/conn.log"
OUTPUT = ROOT / "examples/sih26145_tool_capture_zeek_v1.jsonl"


def rendered(source: Path = SOURCE) -> str:
    rows = []
    for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError(f"line {line_number}: expected Zeek JSON object")
        rows.append(record)
    rows.sort(key=lambda item: (float(item["ts"]), str(item.get("uid", ""))))
    return "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the chronological Sprint 31 Zeek fixture")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            raise SystemExit("Sprint 31 Zeek fixture does not match the captured source")
        print(f"Verified {OUTPUT.relative_to(ROOT)}")
        return 0
    if OUTPUT.exists():
        raise SystemExit(f"Refusing to overwrite existing fixture: {OUTPUT}")
    OUTPUT.write_text(expected, encoding="utf-8", newline="\n")
    print(f"Created {OUTPUT.relative_to(ROOT)} with {len(expected.splitlines())} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
