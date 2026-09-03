"""Post-inference benchmark scoring; unknown truth is never counted as benign."""
from collections import Counter, defaultdict
from math import sqrt

from aegisflow.evaluation_scoring import EXPECTED_SUBTYPES


CLASSES = {**EXPECTED_SUBTYPES, "volumetric_ddos_udp_flood": {"udp_flood"}, "any_attack": set()}


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def wilson(successes, total):
    if not total:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z*z / total
    center = (p + z*z/(2*total)) / denominator
    half = z * sqrt(p*(1-p)/total + z*z/(4*total*total)) / denominator
    return [max(0, center-half), min(1, center+half)]


def metrics(counts):
    tp, fp, fn, tn = (counts.get(key, 0) for key in ("tp", "fp", "fn", "tn"))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": ratio(tp, tp+fp), "recall": ratio(tp, tp+fn),
            "f1": ratio(2*tp, 2*tp+fp+fn), "fpr": ratio(fp, fp+tn),
            "recall_interval_95": wilson(tp, tp+fn), "fpr_interval_95": wilson(fp, fp+tn)}


def score_units(units, alerts, accepted_uids):
    """Explicit, disjoint units; subtype mistakes incur both FN and FP.

    Flow membership means alert coverage, not a prediction on every packet.
    Unknown/background units participate in inference but not confusion matrices.
    Rejected labelled attack units remain in the denominator (FN if not covered).
    """
    predictions = defaultdict(set)
    unknown_subtypes = Counter()
    orphan_alerts = []
    for alert in alerts:
        subtype = alert["subtype"]
        classes = {name for name, subtypes in CLASSES.items() if subtype in subtypes}
        if not classes:
            unknown_subtypes[subtype] += 1
        for uid in alert["flow_ids"]:
            predictions[uid].update(classes | {"any_attack"})
    all_uids = {uid for unit in units for uid in unit["flow_ids"]}
    orphan_alerts = [a["alert_id"] for a in alerts if not set(a["flow_ids"]) & all_uids]
    confusion = {name: Counter() for name in CLASSES}
    binary = Counter()
    coverage = Counter()
    examples = defaultdict(list)
    for unit in units:
        expected = set(unit["expected_classes"])
        observed = set().union(*(predictions[uid] for uid in unit["flow_ids"]))
        label = unit["label"]
        coverage[label + "_units"] += 1
        if not set(unit["flow_ids"]) <= accepted_uids:
            coverage["units_with_rejected_or_unavailable_records"] += 1
        if label == "unknown":
            coverage["unknown_units_with_alerts"] += bool(observed)
            continue
        truth = label == "attack"
        predicted = bool(observed)
        outcome = "tp" if truth and predicted else "fn" if truth else "fp" if predicted else "tn"
        binary[outcome] += 1
        for name in CLASSES:
            # Generic malware labels cannot establish any specific subtype's TN.
            if name != "any_attack" and "any_attack" in expected:
                continue
            actual = truth if name == "any_attack" else name in expected
            detected = name in observed
            key = "tp" if actual and detected else "fn" if actual else "fp" if detected else "tn"
            confusion[name][key] += 1
            if key in {"fp", "fn"} and len(examples[name]) < 20:
                examples[name].append({"unit_id": unit["unit_id"], "error": key,
                                      "expected_classes": sorted(expected), "observed_classes": sorted(observed - {"any_attack"})})
    return {"scope": "explicit-unit alert coverage; not per-packet accuracy",
            "binary_alert_coverage": metrics(binary),
            "per_class": {name: metrics(counts) for name, counts in confusion.items()},
            "coverage": dict(coverage), "error_examples": dict(examples),
            "unknown_alert_subtypes": dict(unknown_subtypes), "orphan_alert_ids": orphan_alerts,
            "interval_note": "Wilson 95% intervals assume independent units; related flows violate that assumption. Report by capture; these are descriptive only."}
