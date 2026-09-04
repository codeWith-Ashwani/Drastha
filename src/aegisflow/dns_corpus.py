"""Offline, hash-pinned domain corpus. Labels never enter inference events."""
from collections import Counter
from hashlib import sha256
import json
import math
from pathlib import Path
import re

from aegisflow.benchmark import pinned_file
from aegisflow.dns_features import normalized_domain
from aegisflow.dns_model import DNSLabelledDomain, validate_leakage_safe_split
from aegisflow.public_suffix import PublicSuffixList


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def read_manifest(path):
    raw = Path(path).read_bytes()
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "drastha-dns-corpus-v1":
        raise ValueError("Unsupported DNS corpus manifest")
    for key in ("corpus_id", "source_url", "license", "license_url", "citation", "label_caveat", "split_seed"):
        if not isinstance(manifest.get(key), str) or not manifest[key].strip():
            raise ValueError(f"DNS corpus requires {key}")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 100:
        raise ValueError("DNS corpus requires 1..100 pinned sources")
    grid = manifest.get("threshold_grid")
    if not isinstance(grid, list) or not 1 <= len(grid) <= 100 or any(
        type(x) not in (int, float) or not math.isfinite(x) or not 0 < x < 1 for x in grid
    ) or sorted(set(grid)) != grid:
        raise ValueError("Threshold grid must contain unique ascending finite values between 0 and 1")
    gates = manifest.get("gates", {})
    for key in ("maximum_fpr", "minimum_recall", "minimum_family_recall"):
        value = gates.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"Invalid calibration gate {key}")
    for key in ("minimum_positives", "minimum_negatives"):
        if type(gates.get(key)) is not int or gates[key] < 1:
            raise ValueError(f"Invalid calibration gate {key}")
    return manifest, sha256(raw).hexdigest()


def load_dns_corpus(path, data_root):
    manifest, manifest_hash = read_manifest(path)
    root = Path(data_root).resolve()
    suffix_entry = manifest.get("public_suffix_list")
    suffixes = PublicSuffixList(pinned_file(root, suffix_entry))
    rows, audits = [], []
    groups, seen, source_hashes = {}, {}, set()
    raw_records = 0
    for source in manifest["sources"]:
        if not isinstance(source, dict) or source.get("label") not in (0, 1) or type(source.get("label")) is not int:
            raise ValueError("Invalid DNS source label")
        family = source.get("family", "").strip().lower()
        split = source.get("split")
        if not family or split not in {"train", "validation", "test", "group-hash-60-20-20"}:
            raise ValueError("Invalid DNS family or split")
        if split == "group-hash-60-20-20" and source["label"] != 0:
            raise ValueError("Malicious families must be assigned whole to one split")
        text = pinned_file(root, source)
        if source["sha256"] in source_hashes:
            raise ValueError("Duplicate source content in DNS corpus")
        source_hashes.add(source["sha256"])
        lines = text.splitlines()
        if type(source.get("records")) is not int or source["records"] < 1 or len(lines) != source["records"]:
            raise ValueError(f"Source record count mismatch: {family}")
        raw_records += len(lines)
        if raw_records > 200_000:
            raise ValueError("DNS corpus exceeds 200000 domain limit")
        counts = Counter()
        for line, value in enumerate(lines, 1):
            domain = normalized_domain(value)
            if not 1 <= len(domain) <= 253 or len(domain.split(".")) < 2 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in domain.split(".")
            ):
                raise ValueError(f"Invalid DNS name in {family} line {line}; do not silently discard it")
            # Registrable domains (including hosted tenants) never cross splits.
            group = suffixes.registrable_domain(domain)
            assigned = split
            if split == "group-hash-60-20-20":
                bucket = int(sha256(f"{manifest['split_seed']}|{group}".encode()).hexdigest(), 16) % 100
                assigned = "train" if bucket < 60 else "validation" if bucket < 80 else "test"
            row = DNSLabelledDomain(domain, source["label"], family, assigned)
            if domain in seen:
                if seen[domain] != row:
                    raise ValueError("Conflicting labels/families or domain leakage in DNS corpus")
                counts["duplicate_same_label_rows"] += 1
                continue
            seen[domain] = row
            if group in groups and groups[group] != assigned:
                raise ValueError(f"Domain-group leakage across splits: {group}")
            groups[group] = assigned
            rows.append(row)
            counts[assigned] += 1
        audits.append({"family": family, "sha256": source["sha256"], "raw_records": len(lines), **counts})
    validate_leakage_safe_split(rows)
    partitions = {split: [row for row in rows if row.split == split] for split in ("train", "validation", "test")}
    for split, part in partitions.items():
        if {row.label for row in part} != {0, 1}:
            raise ValueError(f"{split} must include both labelled classes")
    audit = {
        "manifest_sha256": manifest_hash, "sources": audits,
        "raw_records": sum(s["raw_records"] for s in audits), "unique_records": len(rows),
        "duplicate_same_label_rows": sum(s.get("duplicate_same_label_rows", 0) for s in audits),
        "group_policy": "pinned PSL registrable domain, ICANN and private suffixes",
        "public_suffix_sha256": suffix_entry["sha256"],
        "splits": {split: {"records": len(part), "benign": sum(r.label == 0 for r in part),
                           "malicious": sum(r.label == 1 for r in part),
                           "malicious_families": sorted({r.family for r in part if r.label}),
                           "sha256": digest([(r.domain, r.label, r.family) for r in part])}
                   for split, part in partitions.items()},
    }
    return manifest, partitions, audit
