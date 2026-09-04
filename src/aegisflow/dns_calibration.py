"""Validation-only operating-point selection, separate frozen holdout evaluation.

This calibrates a DECISION THRESHOLD, not a probability or an infection verdict.
No network operations, production policy changes, or automatic model promotion.
"""
from collections import Counter
from dataclasses import replace
import json
import math
from pathlib import Path

from aegisflow.analysis_session import AnalysisSession, DEPLOYMENT_BASELINE
from aegisflow.benchmark import ReportRepository
from aegisflow.benchmark_metrics import metrics
from aegisflow.dns_corpus import digest, load_dns_corpus
from aegisflow.dns_model import DNSNgramModel
from aegisflow.upload_analysis import analyse_uploaded_replay


def scored_metrics(rows, probabilities, threshold):
    if len(rows) != len(probabilities) or not rows:
        raise ValueError("Scores require a nonempty matched labelled population")
    confusion, families = Counter(), {}
    bins = [{"count": 0, "score_sum": 0.0, "positives": 0} for _ in range(10)]
    brier = log_loss = 0.0
    for row, probability in zip(rows, probabilities):
        if not math.isfinite(probability) or not 0 <= probability <= 1:
            raise ValueError("Invalid model score")
        predicted = probability >= threshold
        outcome = "tp" if row.label and predicted else "fn" if row.label else "fp" if predicted else "tn"
        confusion[outcome] += 1
        families.setdefault(row.family, Counter())[outcome] += 1
        item = bins[min(9, int(probability * 10))]
        item["count"] += 1
        item["score_sum"] += probability
        item["positives"] += row.label
        brier += (probability - row.label) ** 2
        safe = max(1e-15, min(1 - 1e-15, probability))
        log_loss -= row.label * math.log(safe) + (1 - row.label) * math.log1p(-safe)
    reliability = [{"bin": i, "count": item["count"],
                    "mean_score": item["score_sum"] / item["count"],
                    "positive_fraction": item["positives"] / item["count"]}
                   for i, item in enumerate(bins) if item["count"]]
    return {**metrics(confusion), "threshold": threshold, "records": len(rows),
            "per_family": {key: metrics(value) for key, value in sorted(families.items())},
            "score_diagnostics": {"brier": brier / len(rows), "log_loss": log_loss / len(rows),
                                  "reliability_bins": reliability,
                                  "ece_10_bins": sum(x["count"] * abs(x["mean_score"] - x["positive_fraction"])
                                                     for x in reliability) / len(rows)}}


def gate_failures(result, gates):
    failures = []
    if result["tp"] + result["fn"] < gates["minimum_positives"]:
        failures.append("insufficient_positive_examples")
    if result["fp"] + result["tn"] < gates["minimum_negatives"]:
        failures.append("insufficient_negative_examples")
    if result["fpr_interval_95"] is None or result["fpr_interval_95"][1] > gates["maximum_fpr"]:
        failures.append("fpr_wilson_upper_bound_exceeds_budget")
    if result["recall"] is None or result["recall"] < gates["minimum_recall"]:
        failures.append("recall_below_minimum")
    for name, value in result["per_family"].items():
        if value["tp"] + value["fn"] and value["recall"] < gates["minimum_family_recall"]:
            failures.append(f"family_recall_below_minimum:{name}")
    return failures


def fit_candidate(manifest_path, data_root):
    manifest, parts, audit = load_dns_corpus(manifest_path, data_root)
    # Test is audited for identity/leakage, but never scored or passed to fit.
    model = DNSNgramModel.train(parts["train"])
    scores = [model.predict_probability(row.domain) for row in parts["validation"]]
    candidates = [scored_metrics(parts["validation"], scores, value) for value in manifest["threshold_grid"]]
    eligible = [value for value in candidates if not gate_failures(value, manifest["gates"])]
    if eligible:
        selected = min(eligible, key=lambda value: (-value["recall"], value["fpr"], value["threshold"]))
    else:
        # Retain the unsuccessful experiment, not a manufactured pass or an
        # alert-disabled threshold of 1. No production defaults are changed.
        selected = min(candidates, key=lambda value: (value["fpr"], -value["recall"], value["threshold"]))
    model.payload.update({"input_mode": "full-query-v1", "research_status": "not_approved",
                          "operating_threshold": selected["threshold"]})
    result = {
        "schema_version": "drastha-dns-candidate-v1", "corpus_id": manifest["corpus_id"],
        "model": model.payload, "audit": audit, "gates": manifest["gates"],
        "threshold_grid": manifest["threshold_grid"], "validation": selected,
        "validation_candidates": [{key: value[key] for key in ("threshold", "tp", "fp", "fn", "tn", "recall", "fpr")}
                                  for value in candidates],
        "validation_gate_failures": gate_failures(selected, manifest["gates"]),
        "test_used_for_selection": False, "production_approved": False,
        "score_semantics": "uncalibrated n-gram class score; validation-selected operating threshold only",
        "label_caveat": manifest["label_caveat"],
    }
    result["candidate_sha256"] = digest(result)
    return result


def load_candidate(path):
    if Path(path).stat().st_size > 10_000_000:
        raise ValueError("Candidate artifact exceeds 10 MB")
    candidate = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(candidate, dict) or candidate.get("schema_version") != "drastha-dns-candidate-v1":
        raise ValueError("Unsupported DNS candidate artifact")
    expected = candidate.get("candidate_sha256")
    if digest({key: value for key, value in candidate.items() if key != "candidate_sha256"}) != expected:
        raise ValueError("Candidate checksum mismatch; model/threshold/selection must remain frozen")
    if candidate.get("production_approved") is not False or candidate.get("test_used_for_selection") is not False:
        raise ValueError("Invalid research candidate status")
    return candidate


def pipeline_evaluation(rows, model, repository=None):
    # One isolated query per domain. Times are synthetic transport scaffolding,
    # not captured DNS timing; cannot validate tunnelling or campaigns.
    profile = replace(DEPLOYMENT_BASELINE, name="dns-domain-isolation-research-v1", enabled=("dns",))
    records = [{"ts": 1_800_000_000 + index * 121, "uid": f"DNS-HOLDOUT-{index}",
                "id.orig_h": "192.0.2.10", "id.resp_h": "192.0.2.53", "proto": "udp",
                "id.resp_p": 53, "query": row.domain, "qtype_name": "A"}
               for index, row in enumerate(rows)]
    content = "\n".join(json.dumps(record) for record in records)
    report = analyse_uploaded_replay("dns-domain-holdout.jsonl", content, repository or ReportRepository(),
                                     session=AnalysisSession(profile, dns_model=model))
    detected = {uid for alert in report["alerts"] if alert["subtype"] == "dga_like_domain" for uid in alert["flow_ids"]}
    observed = [1.0 if record["uid"] in detected else 0.0 for record in records]
    confusion = scored_metrics(rows, observed, 0.5)
    # Binary alert coverage has no probability-calibration interpretation.
    confusion.pop("score_diagnostics")
    confusion.pop("threshold")
    return {"scope": "isolated domain queries via actual upload-analysis; not captured flow/campaign accuracy",
            "run_id": report["run_id"],
            "metrics": confusion, "quality": report["quality"], "telemetry": report["telemetry"],
            "findings": len(report["alerts"]), "incidents": len(report["incidents"]),
            "unexpected_subtypes": dict(Counter(a["subtype"] for a in report["alerts"] if a["subtype"] != "dga_like_domain")),
            "analysis_provenance": report["analysis_provenance"]}


def evaluate_candidate(candidate_path, manifest_path, data_root, repository=None):
    candidate = load_candidate(candidate_path)
    manifest, parts, audit = load_dns_corpus(manifest_path, data_root)
    if audit != candidate["audit"] or manifest["gates"] != candidate["gates"]:
        raise ValueError("Corpus/splits/gates differ from the frozen candidate")
    model = DNSNgramModel(candidate["model"])
    threshold = model.payload["operating_threshold"]
    if threshold != candidate["validation"]["threshold"] or threshold not in manifest["threshold_grid"]:
        raise ValueError("Frozen operating threshold mismatch")
    rows = parts["test"]
    scores = [model.predict_probability(row.domain) for row in rows]
    result = scored_metrics(rows, scores, threshold)
    pipeline = pipeline_evaluation(rows, model, repository)
    parity = all(result[key] == pipeline["metrics"][key] for key in ("tp", "fp", "fn", "tn"))
    failures = gate_failures(result, manifest["gates"])
    if not parity:
        failures.append("upload_prediction_parity_failed")
    if pipeline["quality"]["status"] != "healthy" or pipeline["unexpected_subtypes"]:
        failures.append("upload_quality_or_isolation_failed")
    return {
        "schema_version": "drastha-dns-holdout-v1", "candidate_sha256": candidate["candidate_sha256"],
        "corpus_id": candidate["corpus_id"], "audit": audit,
        "validation": candidate["validation"], "validation_gate_failures": candidate["validation_gate_failures"],
        "validation_candidates": candidate["validation_candidates"], "gates": candidate["gates"],
        "test": result, "test_gate_failures": failures, "upload_analysis": pipeline,
        "upload_prediction_parity": parity,
        "dataset_gates_passed": not candidate["validation_gate_failures"] and not failures,
        "production_approved": False,
        "limitations": [manifest["label_caveat"], candidate["score_semantics"],
                        "Same-publisher family holdout, not an independent deployment/time/environment holdout.",
                        "Related domains violate IID assumptions; Wilson bounds are descriptive only.",
                        "Subdomains/operational services and other attack families require separate labelled captures.",
                        "Final holdout is now inspected: further tuning needs a newly reserved final holdout.",
                        "No automatic deployment or promotion, even if these research dataset gates pass."],
    }


def write_new_json(path, payload):
    """Never overwrite an input, previous experiment, demo model or report."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n")
