from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisflow.models import NetworkEvent


class ZeekRecordError(ValueError):
    """Raised when a Zeek JSONL record cannot be normalized."""


def _required(record: dict[str, Any], key: str, line_number: int) -> Any:
    if key not in record or record[key] in (None, ""):
        raise ZeekRecordError(f"line {line_number}: missing required Zeek field {key!r}")
    return record[key]


def _integer(record: dict[str, Any], key: str, default: int = 0) -> int:
    value = record.get(key, default)
    return default if value in (None, "-") else int(value)


def _number(record: dict[str, Any], key: str, default: float = 0.0) -> float:
    value = record.get(key, default)
    return default if value in (None, "-") else float(value)


def _timestamp(record: dict[str, Any], key: str = "ts", line_number: int = 1) -> float:
    """Accept native Zeek epoch timestamps and ISO-8601 replay timestamps."""
    value = _required(record, key, line_number)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{key} must be a Unix timestamp or ISO-8601 datetime") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _connection_state(record: dict[str, Any]) -> str:
    explicit = str(record.get("conn_state", "") or "").upper()
    if explicit:
        return explicit
    history = str(record.get("history", "") or "").upper()
    response_bytes = _integer(record, "resp_bytes")
    # Zeek history "S" means an originator SYN with no observed response when
    # the flow also has no responder bytes. Do not treat generic history values
    # such as "D" as incomplete connections; doing so confuses scans with floods.
    if history == "S" and response_bytes == 0:
        return "S0"
    if history.startswith("R") and response_bytes == 0:
        return "REJ"
    if response_bytes > 0:
        return "SF"
    return ""


def normalize_conn_record(record: dict[str, Any], line_number: int = 1) -> NetworkEvent:
    try:
        return NetworkEvent(
            timestamp=_timestamp(record, "ts", line_number),
            flow_id=str(_required(record, "uid", line_number)),
            src_ip=str(_required(record, "id.orig_h", line_number)),
            dst_ip=str(_required(record, "id.resp_h", line_number)),
            src_port=_integer(record, "id.orig_p"),
            dst_port=_integer(record, "id.resp_p"),
            protocol=str(_required(record, "proto", line_number)).lower(),
            duration_seconds=_number(record, "duration"),
            outbound_bytes=_integer(record, "orig_bytes"),
            inbound_bytes=_integer(record, "resp_bytes"),
            outbound_packets=_integer(record, "orig_pkts"),
            inbound_packets=_integer(record, "resp_pkts"),
            connection_state=_connection_state(record),
            source="zeek:conn",
            raw=record,
        )
    except ZeekRecordError:
        raise
    except (TypeError, ValueError) as exc:
        raise ZeekRecordError(f"line {line_number}: invalid Zeek field value: {exc}") from exc


def read_conn_jsonl(path: str | Path) -> Iterator[NetworkEvent]:
    with Path(path).open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ZeekRecordError(
                    f"line {line_number}: invalid JSON at column {exc.colno}: {exc.msg}"
                ) from exc
            if not isinstance(record, dict):
                raise ZeekRecordError(f"line {line_number}: expected a JSON object")
            yield normalize_conn_record(record, line_number)
