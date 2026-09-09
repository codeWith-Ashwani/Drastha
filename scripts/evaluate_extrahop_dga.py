"""Evaluate a frozen Drastha DGA candidate on the independent ExtraHop corpus."""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
from hashlib import sha256
import json
import math
from pathlib import Path
import sys
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.dns_calibration import load_candidate, pipeline_evaluation, scored_metrics, write_new_json  # noqa: E402
from aegisflow.dns_corpus import digest, load_dns_corpus  # noqa: E402
from aegisflow.dns_model import DNSLabelledDomain, DNSNgramModel  # noqa: E402
from aegisflow.dns_features import normalized_domain  # noqa: E402


def _verify_file(path: Path, descriptor: dict) -> str:
    size = path.stat().st_size
    checksum = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    actual = checksum.hexdigest()
    if size != descriptor["size"] or actual != descriptor["sha256"]:
        raise ValueError("ExtraHop source size or checksum mismatch")
    return actual


def fetch_source(path: Path, descriptor: dict) -> None:
    if path.exists():
        _verify_file(path, descriptor)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".part")
    if temporary.exists():
        raise ValueError("Incomplete ExtraHop download exists; inspect and remove it before retrying")
    checksum, size = sha256(), 0
    try:
        with urlopen(Request(descriptor["download_url"], headers={
            "User-Agent": "DrasthaResearch/30.0"
        }), timeout=120) as response, temporary.open("xb") as output:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > descriptor["size"]:
                    raise ValueError("ExtraHop download exceeds pinned size")
                checksum.update(block)
                output.write(block)
        if size != descriptor["size"] or checksum.hexdigest() != descriptor["sha256"]:
            raise ValueError("Downloaded ExtraHop source failed checksum verification")
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _umudga_cores(manifest_path: Path, data_root: Path) -> tuple[set[str], str]:
    _, parts, audit = load_dns_corpus(manifest_path, data_root)
    cores = set()
    for rows in parts.values():
        for row in rows:
            value = normalized_domain(row.domain)
            cores.add(value.rsplit(".", 1)[0] if "." in value else value)
    return cores, audit["manifest_sha256"]


def sample_source(path: Path, contract: dict, excluded: set[str]) -> tuple[list[DNSLabelledDomain], dict]:
    limit = int(contract["records_per_label"])
    fraction = float(contract["oversample_hash_fraction"])
    if not 1000 <= limit <= 100000 or not 0 < fraction <= 0.1:
        raise ValueError("Invalid external sample contract")
    cutoff = math.floor((2 ** 256) * fraction)
    selected = {0: {}, 1: {}}
    counts = {0: 0, 1: 0}
    labelled_counts = {0: 0, 1: 0}
    invalid = unsupported_domains = comments = overlaps = 0
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        for line_number, line in enumerate(stream, start=1):
            value = line.strip()
            if not value or value.startswith("#"):
                comments += 1
                continue
            try:
                record = json.loads(value)
                if not isinstance(record, dict) or set(record) != {"domain", "threat"}:
                    raise ValueError("record shape")
                domain = normalized_domain(record["domain"])
                label = {"benign": 0, "dga": 1}[record["threat"]]
                labelled_counts[label] += 1
                if (not domain or "." in domain or len(domain) > 63
                        or domain.startswith("-") or domain.endswith("-")
                        or any(not ("a" <= character <= "z" or "0" <= character <= "9" or character == "-")
                               for character in domain)):
                    unsupported_domains += 1
                    continue
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                invalid += 1
                raise ValueError(f"ExtraHop line {line_number} is invalid: {exc}") from exc
            counts[label] += 1
            if domain in excluded:
                overlaps += 1
                continue
            value_hash = sha256(f"{contract['seed']}|{label}|{domain}".encode()).digest()
            if int.from_bytes(value_hash, "big") < cutoff:
                selected[label].setdefault(domain, value_hash.hex())
    if invalid:
        raise ValueError(f"ExtraHop source contains {invalid} invalid records")
    conflict = set(selected[0]) & set(selected[1])
    if conflict:
        raise ValueError("ExtraHop deterministic sample contains conflicting labels")
    rows = []
    sample_records = []
    for label in (0, 1):
        ranked = sorted(selected[label].items(), key=lambda item: (item[1], item[0]))
        if len(ranked) < limit:
            raise ValueError(f"ExtraHop oversample is too small for label {label}: {len(ranked)}")
        for domain, value_hash in ranked[:limit]:
            family = "extrahop-dga-unlabelled-family" if label else "extrahop-benign"
            rows.append(DNSLabelledDomain(domain, label, family, "test"))
            sample_records.append({"domain": domain, "label": label, "selection_hash": value_hash})
    return rows, {
        "source_records": labelled_counts[0] + labelled_counts[1],
        "source_by_label": labelled_counts, "eligible_dns_by_label": counts,
        "comment_or_blank_lines": comments, "invalid_records": invalid,
        "unsupported_dns_host_labels_excluded": unsupported_domains,
        "umudga_core_overlaps_excluded": overlaps,
        "oversample_unique_by_label": {str(label): len(selected[label]) for label in (0, 1)},
        "selected_by_label": {"0": limit, "1": limit},
        "selected_unique_domains": len({row.domain for row in rows}),
        "sample_sha256": digest(sample_records),
    }


def pipeline_evaluation_chunked(rows: list[DNSLabelledDomain], model,
                                chunk_size: int = 8000) -> dict:
    totals = Counter()
    unexpected = Counter()
    chunks = []
    for index in range(0, len(rows), chunk_size):
        result = pipeline_evaluation(rows[index:index + chunk_size], model)
        for key in ("tp", "fp", "fn", "tn"):
            totals[key] += result["metrics"][key]
        unexpected.update(result["unexpected_subtypes"])
        chunks.append({
            "index": len(chunks), "records": result["metrics"]["records"],
            "findings": result["findings"], "incidents": result["incidents"],
            "quality_status": result["quality"]["status"],
            "records_accepted": result["quality"]["records_accepted"],
            "records_rejected": result["quality"]["records_rejected"],
        })
    return {
        "scope": "bounded chunks through actual upload-analysis demo path",
        "chunk_size": chunk_size, "chunks": chunks,
        "metrics": dict(totals), "unexpected_subtypes": dict(unexpected),
        "quality": {
            "status": "healthy" if all(chunk["quality_status"] == "healthy" for chunk in chunks) else "degraded",
            "records_accepted": sum(chunk["records_accepted"] for chunk in chunks),
            "records_rejected": sum(chunk["records_rejected"] for chunk in chunks),
        },
    }


def evaluate(source: Path, external_manifest_path: Path, candidate_path: Path,
             umudga_manifest_path: Path, data_root: Path) -> dict:
    manifest_bytes = external_manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema_version") != "drastha-external-dga-v1":
        raise ValueError("Unsupported external DGA manifest")
    source_hash = _verify_file(source, manifest["source"])
    candidate = load_candidate(candidate_path)
    excluded, umudga_hash = _umudga_cores(umudga_manifest_path, data_root)
    rows, sample_audit = sample_source(source, manifest["sample_contract"], excluded)
    model = DNSNgramModel(candidate["model"])
    threshold = candidate["model"]["operating_threshold"]
    probabilities = [model.predict_probability(row.domain) for row in rows]
    direct = scored_metrics(rows, probabilities, threshold)
    pipeline = pipeline_evaluation_chunked(rows, model)
    parity = all(direct[key] == pipeline["metrics"][key] for key in ("tp", "fp", "fn", "tn"))
    gate_failures = []
    gates = manifest["gates"]
    if direct["tp"] + direct["fn"] < gates["minimum_positives"]:
        gate_failures.append("insufficient_positive_examples")
    if direct["fp"] + direct["tn"] < gates["minimum_negatives"]:
        gate_failures.append("insufficient_negative_examples")
    if direct["fpr_interval_95"][1] > gates["maximum_fpr"]:
        gate_failures.append("fpr_wilson_upper_bound_exceeds_budget")
    if direct["recall"] < gates["minimum_recall"]:
        gate_failures.append("recall_below_minimum")
    if not parity:
        gate_failures.append("upload_prediction_parity_failed")
    if pipeline["quality"]["status"] != "healthy" or pipeline["unexpected_subtypes"]:
        gate_failures.append("upload_quality_or_isolation_failed")
    report = {
        "schema_version": "drastha-external-dga-evaluation-v1",
        "corpus_id": manifest["corpus_id"],
        "external_manifest_sha256": sha256(manifest_bytes).hexdigest(),
        "source_sha256": source_hash, "source_commit": manifest["source"]["commit"],
        "candidate_sha256": candidate["candidate_sha256"],
        "umudga_manifest_sha256": umudga_hash,
        "sample_contract": manifest["sample_contract"], "sample_audit": sample_audit,
        "metrics": direct, "gate_failures": gate_failures,
        "upload_prediction_parity": parity, "upload_analysis": pipeline,
        "dataset_numeric_gates_passed": not gate_failures,
        "promotion_blockers": manifest["promotion_blockers"],
        "promotion_eligible": False, "production_approved": False,
        "limitations": [manifest["publisher_description"],
                        "The source has no malware-family labels, so per-family recall cannot be measured.",
                        "The source omits TLDs; core strings are evaluated unchanged and full-query compatibility is not proven.",
                        "Publisher benign/DGA labels are not deployment traffic, infection labels or prevalence.",
                        "No model feature, weight or threshold was selected using this external sample."],
    }
    report["report_sha256"] = digest(report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path,
                        default=ROOT / "data/raw/ExtraHop/dga-training-data-encoded.json.gz")
    parser.add_argument("--external-manifest", type=Path,
                        default=ROOT / "data/manifests/extrahop_dga_v1.json")
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--umudga-manifest", type=Path,
                        default=ROOT / "data/manifests/umudga_dns_v3.json")
    parser.add_argument("--data-root", type=Path, default=ROOT)
    parser.add_argument("--report-output", required=True, type=Path)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    if args.report_output.exists():
        raise SystemExit("External evaluation report is create-only")
    manifest = json.loads(args.external_manifest.read_text(encoding="utf-8"))
    if args.fetch:
        fetch_source(args.source, manifest["source"])
    report = evaluate(args.source, args.external_manifest, args.candidate,
                      args.umudga_manifest, args.data_root)
    write_new_json(args.report_output, report)
    print(json.dumps({"records": report["sample_audit"]["selected_unique_domains"],
                      "metrics": {key: report["metrics"][key] for key in
                                  ("tp", "fp", "fn", "tn", "recall", "fpr")},
                      "gate_failures": report["gate_failures"],
                      "promotion_eligible": False, "output": str(args.report_output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
