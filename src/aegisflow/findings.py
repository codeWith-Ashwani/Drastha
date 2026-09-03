from dataclasses import replace
from aegisflow.models import Alert, Evidence

def resolve_findings(alerts: list[Alert]) -> list[Alert]:
    """Suppress cross-detector contradictions and merge repeated findings."""
    recon_alerts = [item for item in alerts if item.threat_type == "reconnaissance"]
    resolved: list[Alert] = []
    for alert in alerts:
        if alert.subtype in {"syn_flood", "distributed_source_syn_flood"}:
            flows = set(alert.flow_ids)
            if any(
                recon.src_ip == alert.src_ip and flows.intersection(recon.flow_ids)
                for recon in recon_alerts
            ):
                continue
        resolved.append(alert)

    grouped: dict[tuple[str, str, str, str | None], Alert] = {}
    counts: dict[tuple[str, str, str, str | None], int] = {}
    for alert in resolved:
        key = (alert.threat_type, alert.subtype, alert.src_ip, alert.dst_ip)
        counts[key] = counts.get(key, 0) + 1
        previous = grouped.get(key)
        if previous is None:
            grouped[key] = alert
            continue
        strongest = alert if alert.confidence > previous.confidence else previous
        grouped[key] = replace(
            strongest,
            confidence=max(previous.confidence, alert.confidence),
            window_start=min(previous.window_start, alert.window_start),
            window_end=max(previous.window_end, alert.window_end),
            flow_ids=tuple(dict.fromkeys((*previous.flow_ids, *alert.flow_ids))),
        )

    output: list[Alert] = []
    for key, alert in grouped.items():
        duplicate_count = counts[key] - 1
        if duplicate_count:
            alert = replace(
                alert,
                evidence=(*alert.evidence, Evidence(
                    "related_findings_merged",
                    duplicate_count,
                    "deduplicated",
                    "Repeated findings from the same source and threat family were merged into one analyst alert.",
                )),
            )
        output.append(alert)
    return sorted(output, key=lambda item: (item.window_start, item.threat_type, item.subtype))



