from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from aegisflow.models import Alert


EXPECTED_SUBTYPES = {
    "volumetric_ddos_syn_flood": {"syn_flood", "distributed_source_syn_flood"},
    "udp_reflection_amplification": {"udp_reflection_amplification"},
    "reconnaissance_port_scan": {
        "vertical_port_scan", "horizontal_host_scan", "multi_host_port_scan"
    },
    "botnet_c2_beaconing": {"periodic_beacon"},
    "dga_domain": {"dga_like_domain"},
    "dns_tunnelling": {"dns_tunnelling"},
    "encrypted_session_malware": {"encrypted_session_metadata_anomaly"},
    "data_exfiltration": {"outbound_volume_anomaly"},
}


@dataclass(slots=True)
class _Unit:
    label: str
    expected_class: str
    flow_ids: set[str]


def _unit_key(record: dict[str, Any]) -> tuple[str, ...]:
    label = str(record.get("evaluation_label", "")).lower()
    expected = str(record.get("evaluation_threat_class", "")).lower()
    source = str(record.get("id.orig_h", ""))
    destination = str(record.get("id.resp_h", ""))
    port = str(record.get("id.resp_p", ""))
    service = str(record.get("service", ""))
    # Distributed floods are one target-centric scenario. Other attacks remain
    # source/destination-centric. Benign units retain endpoint/service context.
    if label == "attack" and expected in {
        "volumetric_ddos_syn_flood", "udp_reflection_amplification"
    }:
        return label, expected, destination, port
    if label == "attack" and expected == "reconnaissance_port_scan":
        return label, expected, source
    if label == "attack":
        return label, expected, source, destination
    return label, expected, source, destination, port, service


def score_ground_truth(
    records: list[dict[str, Any]], alerts: list[Alert]
) -> dict[str, Any] | None:
    """Score detections after inference using optional evaluation-only fields.

    Ground truth never enters detector feature extraction. Metrics are computed
    over endpoint/scenario units because stateful alerts represent windows, not
    independent per-flow classifications.
    """
    labelled = [
        record for record in records
        if str(record.get("evaluation_label", "")).lower() in {"attack", "benign"}
        and record.get("evaluation_threat_class")
        and record.get("uid")
    ]
    if not labelled:
        return None

    grouped: dict[tuple[str, ...], _Unit] = {}
    for record in labelled:
        key = _unit_key(record)
        grouped.setdefault(key, _Unit(
            label=str(record["evaluation_label"]).lower(),
            expected_class=str(record["evaluation_threat_class"]).lower(),
            flow_ids=set(),
        )).flow_ids.add(str(record["uid"]))

    alert_flows = [(alert, set(alert.flow_ids)) for alert in alerts]
    tp = fp = fn = tn = 0
    class_results: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"expected_units": 0, "detected_units": 0, "missed_units": 0}
    )
    mismatches: list[dict[str, Any]] = []
    covered_alert_ids: set[str] = set()

    for unit in grouped.values():
        overlapping = [
            alert for alert, flows in alert_flows if flows.intersection(unit.flow_ids)
        ]
        covered_alert_ids.update(alert.alert_id for alert in overlapping)
        if unit.label == "benign":
            if overlapping:
                fp += 1
            else:
                tn += 1
            continue

        result = class_results[unit.expected_class]
        result["expected_units"] += 1
        acceptable = EXPECTED_SUBTYPES.get(unit.expected_class, set())
        matching = [alert for alert in overlapping if alert.subtype in acceptable]
        if matching:
            tp += 1
            result["detected_units"] += 1
        else:
            fn += 1
            result["missed_units"] += 1
            if overlapping:
                mismatches.append({
                    "expected_class": unit.expected_class,
                    "observed_subtypes": sorted({alert.subtype for alert in overlapping}),
                })

    unmatched_alerts = [
        alert for alert in alerts if alert.alert_id not in covered_alert_ids
    ]
    fp += len(unmatched_alerts)
    attack_sources = {
        str(record.get("id.orig_h", "")) for record in labelled
        if str(record.get("evaluation_label", "")).lower() == "attack"
    }
    benign_sources = {
        str(record.get("id.orig_h", "")) for record in labelled
        if str(record.get("evaluation_label", "")).lower() == "benign"
    }
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "scope": "scenario_endpoint_units",
        "ground_truth_isolation": "evaluation fields used only after detector inference",
        "units": len(grouped),
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "per_class": dict(sorted(class_results.items())),
        "classification_mismatches": mismatches,
        "unmatched_alerts": [alert.alert_id for alert in unmatched_alerts],
        "identity_overlap": {
            "sources_present_in_attack_and_benign_units": sorted(
                (attack_sources & benign_sources) - {""}
            ),
            "detector_state_reset_from_ground_truth": False,
            "note": (
                "Ground-truth fields never control detector state. Use distinct identities "
                "or explicit externally defined scenario boundaries for isolated evaluation."
            ),
        },
    }
