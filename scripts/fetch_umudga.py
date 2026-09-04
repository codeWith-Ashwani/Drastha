"""Explicit offline-research setup. Downloads ONLY pinned plain-text domain lists.

Never resolve/query the names in these lists. This is not an ingest-side client.
Run from repository root: .venv/Scripts/python.exe scripts/fetch_umudga.py
"""
from hashlib import sha256
import json
from pathlib import Path
import re
from urllib.request import Request, urlopen


def main():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "data/manifests/umudga_dns_v1.json").read_text(encoding="utf-8"))
    raw_root = (root / "data/raw/UMUDGA").resolve()
    for source in [*manifest["sources"], {**manifest["public_suffix_list"], "family": "public-suffix-list"}]:
        path = (root / source["path"]).resolve()
        if not path.is_relative_to(raw_root) or path.suffix != ".txt":
            raise ValueError("Download destination must be a .txt file within data/raw/UMUDGA")
        is_psl = source["family"] == "public-suffix-list"
        if (not is_psl and not re.fullmatch(r"[a-f0-9-]{36}", source["file_id"])) or not 0 < source["size"] < 2_000_000:
            raise ValueError("Invalid pinned domain-list ID or size")
        if path.exists():
            data = path.read_bytes()
        else:
            url = ("https://publicsuffix.org/list/public_suffix_list.dat" if is_psl else
                   f"https://data.mendeley.com/public-files/datasets/y8ph45msv8/files/{source['file_id']}/file_downloaded")
            # Public endpoint rejects urllib's default client identifier.
            request = Request(url, headers={"User-Agent": "Mozilla/5.0 DrasthaResearch/1.0"})
            with urlopen(request, timeout=30) as response:
                data = response.read(source["size"] + 1)
        if len(data) != source["size"] or sha256(data).hexdigest() != source["sha256"]:
            raise ValueError(f"Pinned content mismatch: {source['family']}")
        data.decode("utf-8")  # No archives or executable content are processed.
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(data)
        print(f"verified {source['family']}: {len(data)} bytes", flush=True)


if __name__ == "__main__":
    main()
