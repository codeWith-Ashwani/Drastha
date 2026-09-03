"""Shared replay validation. Quality observes original order, before event sorting."""
from __future__ import annotations
import json
from collections import Counter
from dataclasses import dataclass
from typing import Any
from aegisflow.ingestion.replay_input import parse_replay_content, record_schema, schema_summary
from aegisflow.ingestion.zeek_jsonl import ZeekRecordError, normalize_conn_record, normalize_field_aliases
from aegisflow.ingestion.zeek_dns import normalize_dns_record
from aegisflow.ingestion.zeek_encrypted import normalize_encrypted_record
from aegisflow.models import DNSEvent, EncryptedSessionMetadata
from aegisflow.telemetry_quality import TelemetryQuality

PARSER_VERSION = "passive-replay-v2"

class ReplayQualityError(ValueError):
    def __init__(self, message, quality):
        super().__init__(message)
        self.quality = quality

def event_order(event):
    # Metadata at the same observation time is available before its connection.
    priority = 0 if isinstance(event, EncryptedSessionMetadata) else 1 if isinstance(event, DNSEvent) else 2
    return event.timestamp, priority, event.flow_id, event.src_ip, event.dst_ip

@dataclass
class PreparedReplay:
    events: list
    dns_events: list
    encrypted_events: list
    accepted_records: list[dict[str, Any]]
    quality: TelemetryQuality
    input_schema: dict

    def ordered_events(self):
        return sorted([*self.events, *self.dns_events, *self.encrypted_events], key=event_order)

    def telemetry(self):
        return {"connection_records": len(self.events), "dns_records": len(self.dns_events),
                "encrypted_session_records": len(self.encrypted_events), "supplied_labels_ignored": True}

def prepare_replay(content: str, source_name: str = "replay", *, maximum_records: int | None = 20_000,
                   source_kind: str | None = None) -> PreparedReplay:
    if source_kind not in {None, "connection", "dns", "tls", "quic"}:
        raise ValueError("Unknown passive source kind")
    parsed_replay = parse_replay_content(content, source_name)
    raw_records = list(parsed_replay.records)
    if maximum_records is not None and len(raw_records) > maximum_records:
        raise ValueError(f"Replay contains more than {maximum_records:,} records.")

    quality = TelemetryQuality(stream="passive:replay", source=source_name)
    events = []
    dns_events = []
    encrypted_events = []
    accepted_records: list[dict[str, Any]] = []
    alias_usage: Counter[tuple[str, str]] = Counter()
    schema_counts: Counter[str] = Counter()
    seen_uids: dict[str, str] = {}
    latest_timestamp: float | None = None
    for line_number, raw in raw_records:
        quality.records_seen += 1
        if isinstance(raw, ZeekRecordError):
            error = raw
            quality.records_rejected += 1
            quality.records_quarantined += 1
            if len(quality.errors) < 5:
                quality.errors.append(str(error))
            quality.quarantined_records.append(error.to_dict())
            continue
        if not isinstance(raw, dict):
            error = ZeekRecordError(
                f"Line {line_number}: unsupported record; expected a JSON object.",
                line_number=line_number,
                category="unsupported_record",
            )
            quality.records_rejected += 1
            quality.records_quarantined += 1
            quality.unsupported_record_count += 1
            if len(quality.errors) < 5:
                quality.errors.append(str(error))
            quality.quarantined_records.append(error.to_dict())
            continue

        try:
            canonical, aliases = normalize_field_aliases(raw, line_number)
        except ZeekRecordError as exc:
            quality.records_rejected += 1
            quality.records_quarantined += 1
            if len(quality.errors) < 5:
                quality.errors.append(str(exc))
            quality.quarantined_records.append(exc.to_dict())
            continue
        for target, source in aliases.items():
            alias_usage[(target, source)] += 1
        kind = source_kind or record_schema(canonical)
        schema_counts[kind] += 1

        record_timestamps: list[float] = []
        record_events = []
        record_dns_events = []
        record_encrypted_events = []
        record_error: ZeekRecordError | None = None
        try:
            if kind == "connection" or (source_kind is None and kind in {"tls", "quic"} and canonical.get("proto")):
                event = normalize_conn_record(canonical, line_number)
                record_events.append(event)
                record_timestamps.append(event.timestamp)

            if kind == "dns":
                dns_event = normalize_dns_record(canonical, line_number)
                record_dns_events.append(dns_event)
                record_timestamps.append(dns_event.timestamp)

            if kind in {"tls", "quic"}:
                encrypted_event = normalize_encrypted_record(canonical, line_number, kind)
                record_encrypted_events.append(encrypted_event)
                record_timestamps.append(encrypted_event.timestamp)
        except ZeekRecordError as exc:
            record_error = exc

        if record_error is not None or not record_timestamps:
            error = record_error or ZeekRecordError(
                f"Line {line_number}: unsupported passive telemetry record. Expected connection, DNS, or TLS/QUIC metadata.",
                line_number=line_number,
                category="unsupported_record",
            )
            quality.records_rejected += 1
            quality.records_quarantined += 1
            if error.category == "invalid_timestamp":
                quality.invalid_timestamp_count += 1
            if error.category == "unsupported_record":
                quality.unsupported_record_count += 1
            if len(quality.errors) < 5:
                quality.errors.append(str(error))
            quality.quarantined_records.append(error.to_dict())
            continue

        events.extend(record_events)
        dns_events.extend(record_dns_events)
        encrypted_events.extend(record_encrypted_events)
        accepted_records.append(canonical)

        uid = str(canonical.get("uid", ""))
        signature = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
        if uid in seen_uids:
            quality.duplicate_uid_count += 1
            if seen_uids[uid] == signature:
                quality.exact_duplicate_count += 1
            else:
                quality.conflicting_duplicate_uid_count += 1
        else:
            seen_uids[uid] = signature

        record_timestamp = min(record_timestamps)
        if latest_timestamp is not None and record_timestamp < latest_timestamp:
            quality.out_of_order_records += 1
            quality.maximum_backward_skew_seconds = max(
                quality.maximum_backward_skew_seconds, latest_timestamp - record_timestamp
            )
        latest_timestamp = max(record_timestamp, latest_timestamp or record_timestamp)
        quality.records_accepted += 1

    rejection_ratio = quality.records_rejected / max(quality.records_seen, 1)
    if not (events or dns_events or encrypted_events) or rejection_ratio > 0.10:
        quality.status = "unusable"
    elif quality.records_rejected or quality.out_of_order_records or quality.duplicate_uid_count:
        quality.status = "degraded"
    if quality.records_rejected:
        quality.degraded_reasons.append(f"{quality.records_rejected} rejected record(s)")
    if quality.out_of_order_records:
        quality.degraded_reasons.append(
            f"{quality.out_of_order_records} out-of-order timestamp record(s)"
        )
    if quality.duplicate_uid_count:
        quality.degraded_reasons.append(
            f"{quality.duplicate_uid_count} duplicate flow ID occurrence(s)"
        )
    quality.maximum_backward_skew_seconds = round(quality.maximum_backward_skew_seconds, 6)
    if quality.status == "unusable":
        reason = quality.errors[0] if quality.errors else "No supported passive telemetry records were found."
        raise ReplayQualityError(f"Replay could not be analysed (data quality: unusable): {reason}", quality)

    return PreparedReplay(events, dns_events, encrypted_events, accepted_records, quality,
                          schema_summary(parsed_replay.input_format, raw_records, alias_usage, schema_counts))
