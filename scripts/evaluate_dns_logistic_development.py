"""Family-blocked development evaluation for the Sprint 29 DGA classifier.

All UMUDGA families have already been inspected. This command therefore performs
cross-validation for model development only and can never emit an approved model.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegisflow.dns_calibration import gate_failures, scored_metrics, write_new_json  # noqa: E402
from aegisflow.dns_corpus import digest, load_dns_corpus  # noqa: E402
from aegisflow.dns_model import DNSHashedLogisticModel, DNSLabelledDomain  # noqa: E402
from aegisflow.public_suffix import PublicSuffixList  # noqa: E402


FOLDS = 3
SEED = "drastha-sprint29-family-blocked-development-v1"
THRESHOLDS = [0.5, 0.7, 0.8, 0.9, 0.95, 0.975, 0.99]
MODEL_CONFIG = {"hash_dimensions": 4096, "ngram_sizes": (2, 3, 4),
                "epochs": 4, "learning_rate": 0.08, "l2": 0.0001}


def _ordered_fold(values: set[str]) -> dict[str, int]:
    ordered = sorted(values, key=lambda value: sha256(f"{SEED}|{value}".encode()).digest())
    return {value: index % FOLDS for index, value in enumerate(ordered)}


def evaluate(manifest_path: Path, data_root: Path) -> dict:
    manifest, parts, audit = load_dns_corpus(manifest_path, data_root)
    rows = [row for split in ("train", "validation", "test") for row in parts[split]]
    psl_path = (data_root.resolve() / manifest["public_suffix_list"]["path"]).resolve()
    suffixes = PublicSuffixList(psl_path.read_text(encoding="utf-8"))
    malware_folds = _ordered_fold({row.family for row in rows if row.label == 1})
    benign_groups = {suffixes.registrable_domain(row.domain) for row in rows if row.label == 0}
    benign_folds = {group: int(sha256(f"{SEED}|benign|{group}".encode()).hexdigest(), 16) % FOLDS
                    for group in benign_groups}
    assignments = []
    for row in rows:
        group = row.family if row.label else suffixes.registrable_domain(row.domain)
        fold = malware_folds[group] if row.label else benign_folds[group]
        assignments.append((row, fold))
    if len({row.domain for row, _ in assignments}) != len(assignments):
        raise ValueError("Development corpus contains duplicate domains")

    scored_rows, probabilities, folds = [], [], []
    for fold in range(FOLDS):
        training = [DNSLabelledDomain(row.domain, row.label, row.family, "train")
                    for row, assigned in assignments if assigned != fold]
        validation = [row for row, assigned in assignments if assigned == fold]
        train_malware = {row.family for row in training if row.label == 1}
        validation_malware = {row.family for row in validation if row.label == 1}
        if train_malware & validation_malware:
            raise ValueError("Malware family crossed a development fold")
        model = DNSHashedLogisticModel.train(training, **MODEL_CONFIG)
        fold_scores = [model.predict_probability(row.domain) for row in validation]
        scored_rows.extend(validation)
        probabilities.extend(fold_scores)
        folds.append({
            "fold": fold,
            "training_records": len(training), "validation_records": len(validation),
            "training_malware_families": sorted(train_malware),
            "validation_malware_families": sorted(validation_malware),
            "validation_positive_records": sum(row.label for row in validation),
            "validation_negative_records": sum(not row.label for row in validation),
        })
    candidates = [scored_metrics(scored_rows, probabilities, threshold)
                  for threshold in THRESHOLDS]
    eligible = [result for result in candidates if not gate_failures(result, manifest["gates"])]
    selected = min(eligible, key=lambda result: (-result["recall"], result["fpr"], result["threshold"])) \
        if eligible else min(candidates, key=lambda result: (
            len(gate_failures(result, manifest["gates"])), result["fpr"], -result["recall"],
            result["threshold"]))
    offset = 0
    for fold in folds:
        count = fold["validation_records"]
        fold["metrics"] = scored_metrics(scored_rows[offset:offset + count],
                                           probabilities[offset:offset + count],
                                           selected["threshold"])
        offset += count
    report = {
        "schema_version": "drastha-dns-development-v1",
        "corpus_id": manifest["corpus_id"], "source_audit": audit,
        "purpose": "family-blocked model development on already inspected UMUDGA; no untouched final test",
        "seed": SEED, "fold_count": FOLDS, "folds": folds,
        "model_type": "hashed_character_logistic_regression",
        "model_config": {**MODEL_CONFIG, "ngram_sizes": list(MODEL_CONFIG["ngram_sizes"])},
        "threshold_grid": THRESHOLDS, "gates": manifest["gates"],
        "selected_cross_validation_result": selected,
        "selected_gate_failures": gate_failures(selected, manifest["gates"]),
        "candidate_summaries": [{key: result[key] for key in
                                 ("threshold", "tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr")}
                                for result in candidates],
        "assignment_audit": {
            "records": len(assignments), "unique_domains": len({row.domain for row, _ in assignments}),
            "malware_families": len(malware_folds), "benign_registrable_groups": len(benign_folds),
            "records_by_fold": dict(sorted(Counter(fold for _, fold in assignments).items())),
        },
        "promotion_eligible": False, "production_approved": False,
        "limitations": [
            "Every available UMUDGA malware family has been inspected in an earlier or current development experiment.",
            "Cross-validation is model-selection evidence, not an untouched independent final holdout.",
            "Publisher domain labels are not deployment traffic, host infection labels or campaign prevalence.",
            "Scores are not calibrated probabilities; deployment context and campaign evidence remain required.",
            "A different external corpus or future time/environment holdout is mandatory before promotion.",
        ],
    }
    report["report_sha256"] = digest(report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path,
                        default=ROOT / "data" / "manifests" / "umudga_dns_v3.json")
    parser.add_argument("--data-root", type=Path, default=ROOT)
    parser.add_argument("--report-output", required=True, type=Path)
    args = parser.parse_args()
    if args.report_output.exists():
        raise SystemExit("Development report is create-only; choose a new output path")
    report = evaluate(args.manifest, args.data_root)
    write_new_json(args.report_output, report)
    selected = report["selected_cross_validation_result"]
    print(json.dumps({"records": report["assignment_audit"]["records"],
                      "threshold": selected["threshold"], "recall": selected["recall"],
                      "fpr": selected["fpr"], "gate_failures": report["selected_gate_failures"],
                      "promotion_eligible": False, "output": str(args.report_output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
