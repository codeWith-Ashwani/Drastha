from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Generic, TypeVar

from aegisflow.ingestion.zeek_jsonl import ZeekRecordError


EventT = TypeVar("EventT")
Normalizer = Callable[[dict[str, Any], int], EventT]


@dataclass(slots=True)
class TelemetryQuality:
    stream: str
    source: str
    status: str = "healthy"
    records_seen: int = 0
    records_accepted: int = 0
    records_rejected: int = 0
    records_quarantined: int = 0
    out_of_order_records: int = 0
    duplicate_uid_count: int = 0
    exact_duplicate_count: int = 0
    conflicting_duplicate_uid_count: int = 0
    invalid_timestamp_count: int = 0
    unsupported_record_count: int = 0
    maximum_backward_skew_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    quarantined_records: list[dict[str, Any]] = field(default_factory=list)
    degraded_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["records_received"] = self.records_seen
        result["rejection_ratio"] = round(
            self.records_rejected / max(self.records_seen, 1), 4
        )
        return result


def load_jsonl_resilient(
    path: str | Path,
    normalizer: Normalizer[EventT],
    *,
    stream: str,
    maximum_error_ratio: float = 0.10,
    maximum_recorded_errors: int = 5,
) -> tuple[list[EventT], TelemetryQuality]:
    source = Path(path)
    source_display = (
        "/".join(source.parts[-2:]) if source.is_absolute() and len(source.parts) >= 2
        else source.as_posix()
    )
    quality = TelemetryQuality(stream=stream, source=source_display)
    if not source.is_file():
        quality.status = "unavailable"
        quality.errors.append(f"telemetry file unavailable: {source.as_posix()}")
        return [], quality

    events: list[EventT] = []
    seen_flow_ids: dict[str, str] = {}
    latest_timestamp: float | None = None
    with source.open("r", encoding="utf-8") as input_stream:
        for line_number, line in enumerate(input_stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            quality.records_seen += 1
            try:
                record = json.loads(stripped)
                if not isinstance(record, dict):
                    raise ZeekRecordError(f"line {line_number}: expected a JSON object")
                event = normalizer(record, line_number)
            except (json.JSONDecodeError, ZeekRecordError) as exc:
                quality.records_rejected += 1
                quality.records_quarantined += 1
                if isinstance(exc, ZeekRecordError):
                    if exc.category == "invalid_timestamp":
                        quality.invalid_timestamp_count += 1
                    if exc.category == "unsupported_record":
                        quality.unsupported_record_count += 1
                    quality.quarantined_records.append(exc.to_dict())
                else:
                    quality.quarantined_records.append({
                        "line_number": line_number,
                        "reason": f"line {line_number}: invalid JSON at column {exc.colno}: {exc.msg}",
                        "field": None,
                        "value": None,
                        "error_category": "invalid_json",
                    })
                if len(quality.errors) < maximum_recorded_errors:
                    detail = (
                        f"line {line_number}: invalid JSON at column {exc.colno}: {exc.msg}"
                        if isinstance(exc, json.JSONDecodeError)
                        else str(exc)
                    )
                    quality.errors.append(detail)
                continue

            timestamp = float(getattr(event, "timestamp"))
            if latest_timestamp is not None and timestamp < latest_timestamp:
                quality.out_of_order_records += 1
                quality.maximum_backward_skew_seconds = max(
                    quality.maximum_backward_skew_seconds, latest_timestamp - timestamp
                )
            latest_timestamp = max(timestamp, latest_timestamp or timestamp)
            quality.records_accepted += 1
            events.append(event)
            flow_id = str(getattr(event, "flow_id", ""))
            signature = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
            if flow_id in seen_flow_ids:
                quality.duplicate_uid_count += 1
                if seen_flow_ids[flow_id] == signature:
                    quality.exact_duplicate_count += 1
                else:
                    quality.conflicting_duplicate_uid_count += 1
            else:
                seen_flow_ids[flow_id] = signature

    rejection_ratio = quality.records_rejected / max(quality.records_seen, 1)
    if quality.records_accepted == 0 or rejection_ratio > maximum_error_ratio:
        quality.status = "unusable"
    elif quality.records_rejected or quality.out_of_order_records or quality.duplicate_uid_count:
        quality.status = "degraded"
    if quality.records_rejected:
        quality.records_quarantined = quality.records_rejected
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
    return events, quality
