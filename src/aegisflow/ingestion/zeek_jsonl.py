from __future__ import annotations

import json
from collections.abc import Iterator
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


def normalize_conn_record(record: dict[str, Any], line_number: int = 1) -> NetworkEvent:
    try:
        return NetworkEvent(
            timestamp=float(_required(record, "ts", line_number)),
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
            connection_state=str(record.get("conn_state", "")),
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

