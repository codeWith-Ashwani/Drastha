"""Train a guarded domain-only candidate; never auto-deploy it.

The old Vawtrak test has been inspected, so it can become training data only.
Validation still uses separated UMUDGA families. The external publisher sample
is scored once after validation threshold selection, without using DNS outcomes.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import replace
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from aegisflow.dns_calibration import gate_failures, scored_metrics
from aegisflow.dns_corpus import load_dns_corpus
from aegisflow.dns_model import DNSNgramModel, DNSLabelledDomain
from freeze_sih_chrmor_holdout import verify as verify_external


def evaluate() -> tuple[dict, DNSNgramModel]:
    manifest, parts, source_audit = load_dns_corpus(ROOT / "data/manifests/umudga_dns_v3.json", ROOT)
    train = [replace(row, split="train") for row in (*parts["train"], *parts["test"])]
    validation = parts["validation"]
    if {row.family for row in train if row.label} & {row.family for row in validation if row.label}:
        raise ValueError("Training/validation DGA families overlap")
    model = DNSNgramModel.train(train, ngram_size=3, count_mode="frequency")
    model.payload.update(ngram_weight=0.75, lexical_weight=0.25,
                         input_mode="full-query-v1", research_status="not_approved")
    probabilities = [model.predict_probability(row.domain) for row in validation]
    candidates = [scored_metrics(validation, probabilities, threshold)
                  for threshold in manifest["threshold_grid"]]
    eligible = [item for item in candidates if not gate_failures(item, manifest["gates"])]
    chosen = (min(eligible, key=lambda item: (-item["recall"], item["fpr"], item["threshold"]))
              if eligible else min(candidates, key=lambda item: (
                  len(gate_failures(item, manifest["gates"])), item["fpr"], -item["recall"])))
    model.payload["operating_threshold"] = chosen["threshold"]
    model.payload["training_scope"] = "UMUDGA-v3 train plus previously inspected old test; excluded validation families"
    external = verify_external()
    rows = []
    for item in external["artifacts"]:
        if item["scenario"] not in {"kraken-failed-burst", "alexa-resolved-burst"}:
            continue
        label = int(item["scenario"] == "kraken-failed-burst")
        for line in (ROOT / item["path"]).read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            rows.append(DNSLabelledDomain(record["query"], label,
                                          "kraken" if label else "alexa", "external"))
    external_scores = [model.predict_probability(row.domain) for row in rows]
    external_metrics = scored_metrics(rows, external_scores, chosen["threshold"])
    report = {
        "schema_version": "drastha-sih-dga-domain-candidate-v1",
        "model_type": model.payload["model_type"], "research_status": "not_approved",
        "training_records": len(train), "validation_records": len(validation),
        "training_families": sorted({row.family for row in train if row.label}),
        "validation_families": sorted({row.family for row in validation if row.label}),
        "source_audit_sha256": source_audit["manifest_sha256"],
        "selection": {"threshold_grid": manifest["threshold_grid"],
                      "selected_threshold": chosen["threshold"],
                      "selected_validation": chosen,
                      "validation_gate_failures": gate_failures(chosen, manifest["gates"])},
        "external_publisher": {"source_commit": external["source_commit"],
                               "sample_records": len(rows), "metrics": external_metrics,
                               "family_counts": dict(Counter(row.family for row in rows))},
        "deployment_model_changed": False,
        "promotion_eligible": False,
        "limitations": [
            "Old UMUDGA test families, including Vawtrak, were already inspected and are now training-only.",
            "The external 100+100 domain sample is too small for the frozen 1,000-positive/negative promotion gates.",
            "The external publisher has already been used for campaign-context validation, though not for this model's fitting or threshold selection.",
            "Domain-only scores omit resolver response and client campaign context; no production generalization claim is made.",
        ],
    }
    return report, model


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-output", type=Path,
                        default=ROOT / "output/sih_dga_candidate_audit.json")
    parser.add_argument("--candidate-output", type=Path,
                        default=ROOT / "output/sih_dga_candidate_research.json")
    args = parser.parse_args()
    report_path = args.report_output if args.report_output.is_absolute() else ROOT / args.report_output
    candidate_path = args.candidate_output if args.candidate_output.is_absolute() else ROOT / args.candidate_output
    if report_path.exists() or candidate_path.exists():
        raise SystemExit("Research candidate/report are create-only")
    report, model = evaluate()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    candidate_path.parent.mkdir(parents=True, exist_ok=True)
    model.save(candidate_path)
    report["candidate_sha256"] = __import__("hashlib").sha256(candidate_path.read_bytes()).hexdigest()
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8", newline="\n")
    print(json.dumps({"validation": {key: report["selection"]["selected_validation"][key]
                                     for key in ("tp", "fp", "fn", "tn", "recall", "fpr")},
                      "external": {key: report["external_publisher"]["metrics"][key]
                                   for key in ("tp", "fp", "fn", "tn", "recall", "fpr")},
                      "promotion_eligible": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
