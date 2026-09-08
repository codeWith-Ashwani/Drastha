"""Prepare/verify Sprint 21's pinned, previously unused UMUDGA slice.

This explicit research command downloads plain-text domain lists only. It never
resolves a domain, opens it, executes publisher code, or runs in ingestion.
The first invocation creates a manifest from the publisher's public metadata;
later invocations trust only that checked-in manifest and verify every byte.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
from urllib.request import Request, urlopen


DATASET = "y8ph45msv8"
VERSION = 1
API = f"https://data.mendeley.com/public-api/datasets/{DATASET}"
DOWNLOAD = f"https://data.mendeley.com/public-files/datasets/{DATASET}/files"
FAMILIES = {
    "train": ("bedep", "ccleaner", "chinad", "dyre", "fobber_v1", "fobber_v2",
              "kraken_v1", "kraken_v2", "murofet_v1", "murofet_v2", "murofet_v3",
              "nymaim", "pizd", "pushdo", "pykspa", "qakbot"),
    "validation": ("proslikefan", "qadars", "ramdo", "ranbyus_v1"),
    "test": ("rovnix", "shiotob", "simda", "tinba"),
}
OLD_FAMILIES = {"alureon", "banjori", "corebot", "dircrypt", "matsnu", "necurs",
                "padcrypt", "ramnit", "cryptolocker", "suppobox", "gozi", "locky"}
HEADERS = {"User-Agent": "Mozilla/5.0 DrasthaResearch/2.0",
           "Accept": "application/vnd.mendeley-public-dataset.1+json"}


def _get_json(url: str):
    with urlopen(Request(url, headers=HEADERS), timeout=60) as response:
        return json.load(response)


def _get_bytes(url: str, limit: int) -> bytes:
    with urlopen(Request(url, headers=HEADERS), timeout=60) as response:
        payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("Publisher artifact exceeds declared size")
    return payload


def _file_for(folder_id: str, filename: str) -> dict:
    files = _get_json(f"{API}/files?folder_id={folder_id}&version={VERSION}")
    matches = [item for item in files if item.get("filename") == filename]
    if len(matches) != 1:
        raise ValueError(f"Expected one {filename} in publisher folder {folder_id}")
    item = matches[0]
    details = item["content_details"]
    return {"file_id": item["id"], "sha256": details["sha256_hash"],
            "size": details["size"], "download_url": details["download_url"]}


def discover_manifest(repo_root: Path) -> dict:
    requested = {family for values in FAMILIES.values() for family in values}
    if requested & OLD_FAMILIES or len(requested) != sum(map(len, FAMILIES.values())):
        raise ValueError("Sprint 21 families must be unique and unused by Sprint 11")
    folders = _get_json(f"{API}/folders/{VERSION}")
    fqdn_roots = [item for item in folders if item.get("name") == "Fully Qualified Domain Names"
                  and not item.get("parent_id")]
    if len(fqdn_roots) != 1:
        raise ValueError("Publisher FQDN root not found")
    root_id = fqdn_roots[0]["id"]
    family_folders = {item["name"]: item["id"] for item in folders if item.get("parent_id") == root_id}
    sources = []
    for split, families in FAMILIES.items():
        for family in families:
            parent = family_folders.get(family)
            list_folders = [item for item in folders if item.get("parent_id") == parent and item.get("name") == "list"]
            if len(list_folders) != 1:
                raise ValueError(f"Publisher list folder not found: {family}")
            pinned = _file_for(list_folders[0]["id"], "1000.txt")
            sources.append({"family": family, "label": 1, "split": split,
                            "path": f"data/raw/UMUDGA-v2/{family}.txt",
                            **{key: pinned[key] for key in ("file_id", "sha256", "size")}})
    prior_manifest = json.loads((repo_root / "data" / "manifests" / "umudga_dns_v1.json").read_text(encoding="utf-8"))
    reused_train = []
    for source in prior_manifest["sources"]:
        if source["label"] == 1 and source["split"] == "train":
            reused_train.append(source["family"])
            sources.append({**{key: source[key] for key in
                                ("family", "file_id", "label", "records", "sha256", "size", "split")},
                            "path": f"data/raw/UMUDGA-v2/legacy-{source['family']}.txt",
                            "reused_from_sprint11": "train"})
    legit_parent = family_folders["legit"]
    legit_lists = [item for item in folders if item.get("parent_id") == legit_parent and item.get("name") == "list"]
    legit_parent_file = _file_for(legit_lists[0]["id"], "50000.txt")
    manifest = {
        "schema_version": "drastha-dns-corpus-v1",
        "corpus_id": "umudga-v2-new-family-holdout-20260909",
        "source_url": "https://data.mendeley.com/datasets/y8ph45msv8/1",
        "license": "MIT", "license_url": "https://data.mendeley.com/datasets/y8ph45msv8/1",
        "citation": "Zago, Gil Perez and Martinez Perez (2020), UMUDGA, DOI 10.17632/y8ph45msv8.1",
        "label_caveat": "Publisher-generated DGA names and publisher legit list; not verified current operational traffic or infection labels.",
        "split_seed": "drastha-sprint21-v2",
        "prior_experiment_boundaries": {"manifest": "data/manifests/umudga_dns_v1.json",
            "reused_training_only_families": sorted(reused_train),
            "excluded_from_validation_and_test": sorted(OLD_FAMILIES),
            "legitimate_prefix_lines_excluded": 10000},
        "selection_contract": {"train_families": list(FAMILIES["train"]),
                               "reused_sprint11_train_families": sorted(reused_train),
                               "validation_families": list(FAMILIES["validation"]),
                               "final_test_families": list(FAMILIES["test"]),
                               "selected_before_model_fit": True,
                               "test_labels_not_used_for_threshold_selection": True},
        "public_suffix_list": {"path": "data/raw/UMUDGA/public_suffix_list.txt",
            "sha256": "0e07be8daca66c85f12cf84827c6a9d09efd5950a89385621cf9df5c1c52e001",
            "size": 333246, "source_url": "https://publicsuffix.org/list/public_suffix_list.dat",
            "version": "2026-09-02_06-03-53_UTC", "commit": "0f1fa47ec45056a19c2fdcd32a08442de9715d12",
            "license": "MPL-2.0", "license_url": "https://mozilla.org/MPL/2.0/"},
        "threshold_grid": [0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.7, 0.8, 0.9, 0.95,
                           0.99, 0.995, 0.999, 0.9995, 0.9999, 0.99999],
        "gates": {"maximum_fpr": 0.01, "minimum_recall": 0.70,
                  "minimum_family_recall": 0.50, "minimum_positives": 1000,
                  "minimum_negatives": 1000},
        "derived_legitimate_source": {"file_id": legit_parent_file["file_id"],
            "sha256": legit_parent_file["sha256"], "size": legit_parent_file["size"],
            "filename": "50000.txt", "excluded_line_range": [1, 10000],
            "selected_line_range": [10001, 40000],
            "reason": "exclude every legitimate name present in the inspected Sprint 11 10000-name source"},
        "sources": sources,
    }
    return manifest


def _verify(payload: bytes, entry: dict, name: str) -> None:
    if len(payload) != entry["size"] or sha256(payload).hexdigest() != entry["sha256"]:
        raise ValueError(f"Pinned publisher content mismatch: {name}")


def materialize(repo_root: Path, manifest: dict) -> None:
    raw_root = (repo_root / "data" / "raw" / "UMUDGA-v2").resolve()
    raw_root.mkdir(parents=True, exist_ok=True)
    for source in manifest["sources"]:
        path = (repo_root / source["path"]).resolve()
        if not path.is_relative_to(raw_root) or path.suffix != ".txt":
            raise ValueError("Raw destination escaped UMUDGA-v2")
        reused = source.get("reused_from_sprint11")
        if path.exists():
            payload = path.read_bytes()
        elif reused:
            payload = (repo_root / "data" / "raw" / "UMUDGA" / f"{source['family']}.txt").read_bytes()
        else:
            payload = _get_bytes(f"{DOWNLOAD}/{source['file_id']}/file_downloaded", source["size"])
        _verify(payload, source, source["family"])
        actual_records = len(payload.decode("utf-8").splitlines())
        if "records" not in source:
            source["records"] = actual_records
        elif actual_records != source["records"]:
            raise ValueError(f"Publisher record count mismatch: {source['family']}")
        if not path.exists():
            path.write_bytes(payload)
    parent = manifest["derived_legitimate_source"]
    parent_path = raw_root / "legit-50000.txt"
    parent_payload = parent_path.read_bytes() if parent_path.exists() else _get_bytes(
        f"{DOWNLOAD}/{parent['file_id']}/file_downloaded", parent["size"])
    _verify(parent_payload, parent, "legit-50000")
    if not parent_path.exists():
        parent_path.write_bytes(parent_payload)
    lines = parent_payload.decode("utf-8").splitlines()
    selected = ("\n".join(lines[10000:40000]) + "\n").encode()
    derived_path = raw_root / "legit-fresh-tail.txt"
    derived = next((item for item in manifest["sources"] if item["family"] == "publisher-legit-fresh-tail"), None)
    if derived is None:
        derived = {"family": "publisher-legit-fresh-tail", "label": 0,
                   "split": "group-hash-60-20-20", "path": "data/raw/UMUDGA-v2/legit-fresh-tail.txt",
                   "file_id": "derived-from-pinned-legit-50000-lines-10001-40000",
                   "sha256": sha256(selected).hexdigest(), "size": len(selected), "records": len(lines[10000:40000])}
        manifest["sources"].append(derived)
    _verify(selected, derived, derived["family"])
    if derived_path.exists() and derived_path.read_bytes() != selected:
        raise ValueError("Derived legitimate tail differs from pinned result")
    if not derived_path.exists():
        derived_path.write_bytes(selected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--prepare-manifest", action="store_true")
    args = parser.parse_args()
    root = args.repo_root.resolve()
    path = root / "data" / "manifests" / "umudga_dns_v2.json"
    if args.prepare_manifest:
        if path.exists():
            raise SystemExit("Refusing to overwrite existing Sprint 21 manifest")
        manifest = discover_manifest(root)
        materialize(root, manifest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    else:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        materialize(root, manifest)
    print(f"verified {len(manifest['sources'])} pinned sources for {manifest['corpus_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
