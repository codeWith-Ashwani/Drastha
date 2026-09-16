"""Fit a create-only DGA candidate from the official CTU training split."""
from __future__ import annotations

import argparse
import copy
import csv
import gzip
from hashlib import sha256
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.dns_calibration import gate_failures, scored_metrics
from aegisflow.dns_features import normalized_domain
from aegisflow.dns_model import DNSLabelledDomain, DNSNgramModel


MANIFEST = ROOT / "data/manifests/sih26145-ctu-dga-training-v1.json"


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def load_rows(manifest: dict) -> tuple[list[DNSLabelledDomain], dict]:
    source = ROOT / manifest["source_path"]
    if digest(source) != manifest["source_sha256"] or source.stat().st_size != manifest["source_size"]:
        raise ValueError("Pinned CTU training source changed")
    pools: dict[int, set[str]] = {0: set(), 1: set()}
    source_counts = {"benign": 0, "dga": 0, "dns_tunnelling_excluded": 0}
    with gzip.open(source, "rt", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ["domain", "class"]:
            raise ValueError("Unexpected CTU training CSV schema")
        for item in reader:
            label = int(item["class"])
            if label not in (0, 1, 2):
                raise ValueError("Unexpected CTU training class")
            source_counts[manifest["class_mapping"][str(label)]] += 1
            domain = normalized_domain(item["domain"])
            if label in pools and domain:
                pools[label].add(domain)
    counts = manifest["records_per_class"]
    required = int(counts["train"]) + int(counts["validation"])
    rows = []
    selection_hashes = {}
    for label in (0, 1):
        ordered = sorted(pools[label], key=lambda domain: sha256(
            f"{manifest['seed']}|{label}|{domain}".encode()).digest())
        if len(ordered) < required:
            raise ValueError(f"Insufficient distinct CTU training rows for class {label}")
        chosen = ordered[:required]
        selection_hashes[str(label)] = sha256("\n".join(chosen).encode()).hexdigest()
        for index, domain in enumerate(chosen):
            split = "train" if index < int(counts["train"]) else "validation"
            rows.append(DNSLabelledDomain(domain, label,
                                          "ctu-dga" if label else "ctu-benign", split))
    return rows, {"source_class_counts": source_counts,
                  "selection_sha256_by_label": selection_hashes}


def fit() -> tuple[dict, DNSNgramModel]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows, source_audit = load_rows(manifest)
    training = [row for row in rows if row.split == "train"]
    validation = [row for row in rows if row.split == "validation"]
    candidates = []
    payloads = []
    for ngram_size in manifest["ngram_sizes"]:
        for count_mode in manifest["count_modes"]:
            base = DNSNgramModel.train(training, ngram_size=ngram_size,
                                       count_mode=count_mode)
            for weights in manifest["feature_variants"]:
                model = DNSNgramModel(copy.deepcopy(base.payload))
                model.payload.update(weights)
                probabilities = [model.predict_probability(row.domain) for row in validation]
                for threshold in manifest["threshold_grid"]:
                    metrics = scored_metrics(validation, probabilities, threshold)
                    failures = gate_failures(metrics, manifest["gates"])
                    summary = {"ngram_size": ngram_size, "count_mode": count_mode,
                               **weights, "threshold": threshold, "metrics": metrics,
                               "gate_failures": failures}
                    candidates.append(summary)
                    payloads.append((summary, copy.deepcopy(model.payload)))
    eligible = [(summary, payload) for summary, payload in payloads
                if not summary["gate_failures"]]
    if not eligible:
        chosen_summary, chosen_payload = min(payloads, key=lambda item: (
            len(item[0]["gate_failures"]), item[0]["metrics"]["fpr"],
            -item[0]["metrics"]["recall"]))
    else:
        chosen_summary, chosen_payload = min(eligible, key=lambda item: (
            -item[0]["metrics"]["recall"], item[0]["metrics"]["fpr"],
            item[0]["ngram_size"], item[0]["threshold"]))
    chosen_payload.update(
        operating_threshold=chosen_summary["threshold"],
        input_mode="full-query-v1", research_status="not_approved",
        training_scope="CTU DNS Threats official train split only",
        training_source_sha256=manifest["source_sha256"],
        training_manifest_sha256=digest(MANIFEST),
    )
    report = {
        "schema_version": "drastha-sih-ctu-dga-candidate-v1",
        "research_status": "not_approved", "deployment_model_changed": False,
        "training_records": len(training), "validation_records": len(validation),
        "source_audit": source_audit,
        "training_manifest_sha256": digest(MANIFEST),
        "search_candidates": len(candidates), "selected": chosen_summary,
        "validation_passed": not chosen_summary["gate_failures"],
        "test_fixture_read_during_fit": False,
        "limitations": [
            "The CTU source supplies domain and class only, not resolver, client or infection telemetry.",
            "The official test split was already used to evaluate older models, but is not read or used to select this candidate.",
            "The candidate remains blocked from normal runtime loading until an external evaluation and explicit promotion step pass."
        ],
    }
    return report, DNSNgramModel(chosen_payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-output", type=Path,
                        default=ROOT / "output/sih_ctu_dga_candidate_research.json")
    parser.add_argument("--report-output", type=Path,
                        default=ROOT / "output/sih_ctu_dga_candidate_fit_audit.json")
    args = parser.parse_args()
    candidate = args.candidate_output if args.candidate_output.is_absolute() else ROOT / args.candidate_output
    report_path = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
    if candidate.exists() or report_path.exists():
        raise SystemExit("Candidate and fit report are create-only")
    report, model = fit()
    model.save(candidate)
    report["candidate_sha256"] = digest(candidate)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8", newline="\n")
    metrics = report["selected"]["metrics"]
    print(json.dumps({"validation_passed": report["validation_passed"],
                      "tp": metrics["tp"], "fp": metrics["fp"],
                      "fn": metrics["fn"], "tn": metrics["tn"],
                      "recall": metrics["recall"], "fpr": metrics["fpr"]}))
    return 0 if report["validation_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
