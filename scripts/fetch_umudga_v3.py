"""Create/verify Sprint 28's fresh-family UMUDGA calibration corpus.

Only publisher text lists are downloaded. Domains are never resolved or visited.
The manifest is create-only; subsequent runs verify its pinned bytes.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.dns_features import normalized_domain  # noqa: E402
from aegisflow.public_suffix import PublicSuffixList  # noqa: E402


DATASET = "y8ph45msv8"
VERSION = 1
API = f"https://data.mendeley.com/public-api/datasets/{DATASET}"
DOWNLOAD = f"https://data.mendeley.com/public-files/datasets/{DATASET}/files"
HEADERS = {"User-Agent": "Mozilla/5.0 DrasthaResearch/3.0",
           "Accept": "application/vnd.mendeley-public-dataset.1+json"}
NEW_SOURCES = {
    "train": {
        "gozi_gpl": "gozi", "gozi_luther": "gozi", "gozi_nasa": "gozi",
        "gozi_rfc4343": "gozi", "pykspa_noise": "pykspa",
        "ranbyus_v2": "ranbyus", "suppobox_1": "suppobox",
        "suppobox_2": "suppobox", "suppobox_3": "suppobox",
        "zeus-newgoz": "zeus-newgoz",
    },
    "validation": {"sisron": "sisron", "symmi": "symmi"},
    "test": {
        "tempedreve": "tempedreve", "vawtrak_v1": "vawtrak",
        "vawtrak_v2": "vawtrak", "vawtrak_v3": "vawtrak",
    },
}


def _get_json(url: str):
    with urlopen(Request(url, headers=HEADERS), timeout=60) as response:
        return json.load(response)


def _get_bytes(url: str, limit: int) -> bytes:
    with urlopen(Request(url, headers=HEADERS), timeout=60) as response:
        payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("Publisher artifact exceeds declared size")
    return payload


def _file_for(folders: list[dict], family_folders: dict[str, str], folder: str) -> dict:
    parent = family_folders.get(folder)
    lists = [item for item in folders if item.get("parent_id") == parent and item.get("name") == "list"]
    if len(lists) != 1:
        raise ValueError(f"Publisher list folder not found: {folder}")
    files = _get_json(f"{API}/files?folder_id={lists[0]['id']}&version={VERSION}")
    matches = [item for item in files if item.get("filename") == "1000.txt"]
    if len(matches) != 1:
        raise ValueError(f"Expected one 1000.txt for {folder}")
    item, details = matches[0], matches[0]["content_details"]
    return {"file_id": item["id"], "sha256": details["sha256_hash"],
            "size": details["size"], "download_url": details["download_url"]}


def _verify(payload: bytes, descriptor: dict, name: str) -> None:
    if len(payload) != descriptor["size"] or sha256(payload).hexdigest() != descriptor["sha256"]:
        raise ValueError(f"Pinned publisher content mismatch: {name}")


def _derived_benign_sources(root: Path, split_seed: str, malicious_sources: list[dict]) -> list[dict]:
    parent = root / "data" / "raw" / "UMUDGA-v2" / "legit-50000.txt"
    raw = parent.read_bytes()
    expected = {"size": 681472,
                "sha256": "db278f3023b6ced9c9afb84fe3c1885bad7a23c7d297834eaeae75e0e31530c0"}
    _verify(raw, expected, "legit-50000")
    lines = raw.decode("utf-8").splitlines()
    suffixes = PublicSuffixList(
        (root / "data" / "raw" / "UMUDGA" / "public_suffix_list.txt").read_text(encoding="utf-8")
    )
    history = [normalized_domain(value) for value in lines[10000:40000]]
    history_groups = {suffixes.registrable_domain(value) for value in history}
    malicious_groups = set()
    for source in malicious_sources:
        source_path = root / source["path"]
        malicious_groups.update(
            suffixes.registrable_domain(normalized_domain(value))
            for value in source_path.read_text(encoding="utf-8").splitlines()
        )
    partitions = {"validation": [], "test": []}
    seen_domains: set[str] = set()
    group_split: dict[str, str] = {}
    for value in lines[40000:50000]:
        domain = normalized_domain(value)
        group = suffixes.registrable_domain(domain)
        if domain in seen_domains or group in history_groups or group in malicious_groups:
            continue
        seen_domains.add(domain)
        assigned = group_split.get(group)
        if assigned is None:
            bucket = int(sha256(f"{split_seed}|{group}".encode()).hexdigest(), 16) % 2
            assigned = "validation" if bucket == 0 else "test"
            group_split[group] = assigned
        partitions[assigned].append(domain)
    values = {"train": history, **partitions}
    output = root / "data" / "raw" / "UMUDGA-v3"
    output.mkdir(parents=True, exist_ok=True)
    sources = []
    for split, domains in values.items():
        if len(domains) < 1000:
            raise ValueError(f"Fresh benign {split} partition is too small: {len(domains)}")
        payload = ("\n".join(domains) + "\n").encode()
        path = output / f"legit-{split}.txt"
        if path.exists() and path.read_bytes() != payload:
            raise ValueError(f"Derived benign partition changed: {split}")
        if not path.exists():
            path.write_bytes(payload)
        sources.append({
            "family": f"publisher-legit-{split}", "label": 0, "split": split,
            "path": path.relative_to(root).as_posix(), "records": len(domains),
            "sha256": sha256(payload).hexdigest(), "size": len(payload),
            "file_id": f"derived-legit-50000-{split}",
        })
    return sources


def ensure_prerequisites(root: Path, previous: dict) -> None:
    """Materialize the two pinned parent files needed to derive fresh negatives."""
    psl = previous["public_suffix_list"]
    psl_path = (root / psl["path"]).resolve()
    if not psl_path.is_relative_to((root / "data" / "raw").resolve()):
        raise ValueError("Public suffix destination escaped data/raw")
    psl_url = ("https://raw.githubusercontent.com/publicsuffix/list/"
               f"{psl['commit']}/public_suffix_list.dat")
    psl_payload = psl_path.read_bytes() if psl_path.exists() else _get_bytes(psl_url, psl["size"])
    _verify(psl_payload, psl, "public-suffix-list")
    if not psl_path.exists():
        psl_path.parent.mkdir(parents=True, exist_ok=True)
        psl_path.write_bytes(psl_payload)

    parent = previous["derived_legitimate_source"]
    parent_path = (root / "data" / "raw" / "UMUDGA-v2" / "legit-50000.txt").resolve()
    parent_payload = parent_path.read_bytes() if parent_path.exists() else _get_bytes(
        f"{DOWNLOAD}/{parent['file_id']}/file_downloaded", parent["size"])
    _verify(parent_payload, parent, "legit-50000")
    if not parent_path.exists():
        parent_path.parent.mkdir(parents=True, exist_ok=True)
        parent_path.write_bytes(parent_payload)


def discover_manifest(root: Path) -> dict:
    previous = json.loads((root / "data" / "manifests" / "umudga_dns_v2.json").read_text(encoding="utf-8"))
    ensure_prerequisites(root, previous)
    folders = _get_json(f"{API}/folders/{VERSION}")
    fqdn = [item for item in folders if item.get("name") == "Fully Qualified Domain Names"
            and not item.get("parent_id")]
    if len(fqdn) != 1:
        raise ValueError("Publisher FQDN root not found")
    family_folders = {item["name"]: item["id"] for item in folders if item.get("parent_id") == fqdn[0]["id"]}
    previous_malicious = []
    for source in previous["sources"]:
        if source["label"] != 1:
            continue
        previous_malicious.append({**source, "split": "train",
                                   "reused_after_prior_inspection": True})
    new_sources = []
    for split, families in NEW_SOURCES.items():
        for publisher_family, grouped_family in families.items():
            descriptor = _file_for(folders, family_folders, publisher_family)
            new_sources.append({
                "publisher_family": publisher_family, "family": grouped_family,
                "label": 1, "split": split,
                "path": f"data/raw/UMUDGA-v3/{publisher_family}.txt",
                **{key: descriptor[key] for key in ("file_id", "sha256", "size")},
            })
    # Materialize the newly declared publisher sources before deriving negatives,
    # so no malicious registrable-domain group can enter a benign holdout.
    materialize(root, {"sources": previous_malicious})
    materialize(root, {"sources": new_sources})
    split_seed = "drastha-sprint28-v3-frozen-before-fit"
    benign = _derived_benign_sources(root, split_seed, [*previous_malicious, *new_sources])
    return {
        "schema_version": "drastha-dns-corpus-v1",
        "corpus_id": "umudga-v3-fresh-family-holdout-20260909",
        "source_url": "https://data.mendeley.com/datasets/y8ph45msv8/1",
        "license": "MIT", "license_url": "https://data.mendeley.com/datasets/y8ph45msv8/1",
        "citation": "Zago, Gil Perez and Martinez Perez (2020), UMUDGA, DOI 10.17632/y8ph45msv8.1",
        "label_caveat": "Publisher-generated DGA names and publisher legit list; not verified current operational traffic or infection labels.",
        "split_seed": split_seed,
        "prior_experiment_boundaries": {
            "manifest": "data/manifests/umudga_dns_v2.json",
            "all_previously_inspected_malicious_sources_reused_in_train_only": True,
            "previous_legitimate_lines_reused_in_train": [10001, 40000],
            "fresh_legitimate_lines_reserved": [40001, 50000],
        },
        "selection_contract": {
            "validation_families": ["sisron", "symmi"],
            "final_test_families": ["tempedreve", "vawtrak"],
            "selected_before_model_fit": True,
            "test_labels_not_used_for_threshold_or_feature_selection": True,
            "final_test_is_single_use": True,
        },
        "public_suffix_list": previous["public_suffix_list"],
        "threshold_grid": [0.5, 0.7, 0.8, 0.9, 0.95, 0.975, 0.99, 0.995, 0.999, 0.9995, 0.9999],
        "ngram_sizes": [2, 3, 4],
        "count_modes": ["frequency", "binary_presence"],
        "score_modes": ["multinomial"],
        "feature_variants": [
            {"ngram_weight": 1.0, "lexical_weight": 0.0},
            {"ngram_weight": 1.0, "lexical_weight": 0.1},
            {"ngram_weight": 1.0, "lexical_weight": 0.25},
            {"ngram_weight": 0.75, "lexical_weight": 0.25},
            {"ngram_weight": 0.5, "lexical_weight": 0.5},
            {"ngram_weight": 0.0, "lexical_weight": 1.0}
        ],
        "gates": {"maximum_fpr": 0.01, "minimum_recall": 0.70,
                  "minimum_family_recall": 0.50, "minimum_positives": 1000,
                  "minimum_negatives": 1000},
        "sources": [*previous_malicious, *new_sources, *benign],
    }


def materialize(root: Path, manifest: dict) -> None:
    output = (root / "data" / "raw").resolve()
    output.mkdir(parents=True, exist_ok=True)
    for source in manifest["sources"]:
        path = (root / source["path"]).resolve()
        if not path.is_relative_to(output) or path.suffix != ".txt":
            raise ValueError("Raw destination escaped data/raw")
        downloadable = source.get("label") == 1 and not str(source.get("file_id", "")).startswith("derived-")
        if downloadable:
            payload = path.read_bytes() if path.exists() else _get_bytes(
                f"{DOWNLOAD}/{source['file_id']}/file_downloaded", source["size"])
            _verify(payload, source, source.get("publisher_family", source["family"]))
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
        else:
            payload = path.read_bytes()
            _verify(payload, source, source["family"])
        records = len(payload.decode("utf-8").splitlines())
        if source.get("records") is None:
            source["records"] = records
        elif source["records"] != records:
            raise ValueError(f"Record count mismatch: {source['family']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--prepare-manifest", action="store_true")
    args = parser.parse_args()
    root = args.repo_root.resolve()
    path = root / "data" / "manifests" / "umudga_dns_v3.json"
    if args.prepare_manifest:
        if path.exists():
            raise SystemExit("Refusing to overwrite existing Sprint 28 manifest")
        manifest = discover_manifest(root)
        materialize(root, manifest)
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
    else:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        previous = json.loads((root / "data" / "manifests" / "umudga_dns_v2.json").read_text(encoding="utf-8"))
        ensure_prerequisites(root, previous)
        malicious = [source for source in manifest["sources"] if source["label"] == 1]
        materialize(root, {"sources": malicious})
        derived = _derived_benign_sources(root, manifest["split_seed"], malicious)
        expected = sorted((source for source in manifest["sources"] if source["label"] == 0),
                          key=lambda source: source["split"])
        if sorted(derived, key=lambda source: source["split"]) != expected:
            raise ValueError("Derived benign partitions differ from the frozen manifest")
        materialize(root, manifest)
    print(f"verified {len(manifest['sources'])} pinned sources for {manifest['corpus_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
