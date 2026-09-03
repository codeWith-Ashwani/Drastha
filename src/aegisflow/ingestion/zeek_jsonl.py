from __future__ import annotations

import json
import math
import ipaddress
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisflow.models import NetworkEvent


FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "ts": ("ts", "timestamp", "time", "@timestamp"),
    "uid": ("uid", "flow_id", "flowid"),
    "id.orig_h": ("id.orig_h", "src_ip", "src", "source_ip", "source.address"),
    "id.orig_p": ("id.orig_p", "src_port", "source_port", "source.port"),
    "id.resp_h": ("id.resp_h", "dst_ip", "dst", "destination_ip", "destination.address"),
    "id.resp_p": ("id.resp_p", "dst_port", "destination_port", "destination.port"),
    "proto": ("proto", "protocol", "network.transport"),
}

FIELD_LABELS = {
    "ts": "timestamp field",
    "uid": "flow ID",
    "id.orig_h": "source IP",
    "id.resp_h": "destination IP",
    "proto": "protocol",
}

SUPPORTED_PROTOCOLS = {
    "tcp", "udp", "icmp", "icmp6", "ipv6-icmp", "sctp", "gre", "esp", "ah", "quic"
}


class ZeekRecordError(ValueError):
    """Structured, safe validation failure for one passive telemetry record."""

    def __init__(
        self,
        message: str,
        *,
        line_number: int | None = None,
        category: str = "invalid_record",
        field: str | None = None,
        value: Any = None,
    ) -> None:
        super().__init__(message)
        self.line_number = line_number
        self.category = category
        self.field = field
        self.value = value

    def to_dict(self) -> dict[str, Any]:
        return {
            "line_number": self.line_number,
            "reason": str(self),
            "field": self.field,
            "value": self.value,
            "error_category": self.category,
        }


def _lookup(record: dict[str, Any], path: str) -> tuple[bool, Any]:
    if path in record:
        return True, record[path]
    if "." not in path:
        return False, None
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def normalize_field_aliases(
    record: dict[str, Any], line_number: int = 1
) -> tuple[dict[str, Any], dict[str, str]]:
    """Return a canonical Zeek-shaped copy and the aliases that were used."""
    canonical = dict(record)
    aliases_used: dict[str, str] = {}
    for target, aliases in FIELD_ALIASES.items():
        present = [(name, value) for name in aliases if (found := _lookup(record, name))[0]
                   for value in (found[1],)]
        meaningful = [(name, value) for name, value in present if value not in (None, "")]
        if not meaningful:
            continue
        normalized_values = {str(value).strip().lower() for _, value in meaningful}
        if len(normalized_values) > 1:
            names = ", ".join(name for name, _ in meaningful)
            raise ZeekRecordError(
                f"line {line_number}: conflicting aliases for {FIELD_LABELS.get(target, target)}: {names}.",
                line_number=line_number,
                category="ambiguous_alias",
                field=target,
            )
        selected_name, selected_value = meaningful[0]
        canonical[target] = selected_value
        if selected_name != target:
            aliases_used[target] = selected_name
    return canonical, aliases_used


def _required(record: dict[str, Any], key: str, line_number: int) -> Any:
    if key not in record or record[key] in (None, ""):
        aliases = ", ".join(FIELD_ALIASES.get(key, (key,)))
        detected = ", ".join(sorted(record)) or "none"
        label = FIELD_LABELS.get(key, f"required field {key!r}")
        raise ZeekRecordError(
            f"line {line_number}: missing required {label}. Accepted one of: {aliases}. "
            f"Detected fields: {detected}.",
            line_number=line_number,
            category="missing_required_field",
            field=key,
        )
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
    text = str(value).strip()
    try:
        numeric = float(text)
    except (ValueError, OverflowError):
        numeric = None
    if numeric is not None:
        if math.isfinite(numeric):
            return numeric
        raise ZeekRecordError(f"line {line_number}: timestamp must be finite",
                              line_number=line_number, category="invalid_timestamp", field=key, value=text)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ZeekRecordError(
            f"line {line_number}: invalid timestamp in field {key!r}: {text!r}. "
            "Expected Unix timestamp or ISO-8601 datetime.",
            line_number=line_number,
            category="invalid_timestamp",
            field=key,
            value=text,
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _ip(record: dict[str, Any], key: str, line_number: int) -> str:
    value = str(_required(record, key, line_number)).strip()
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        label = "source IP" if key == "id.orig_h" else "destination IP"
        raise ZeekRecordError(
            f"line {line_number}: invalid {label} {value!r}. Expected a valid IPv4 or IPv6 address.",
            line_number=line_number,
            category="invalid_ip",
            field=key,
            value=value,
        ) from exc
    return value


def _port(record: dict[str, Any], key: str, line_number: int) -> int:
    value = record.get(key, 0)
    try:
        port = 0 if value in (None, "-") else int(value)
    except (TypeError, ValueError) as exc:
        raise ZeekRecordError(
            f"line {line_number}: invalid port in field {key!r}: {value!r}. Expected an integer from 0 to 65535.",
            line_number=line_number, category="invalid_port", field=key, value=value,
        ) from exc
    if isinstance(value, bool) or not 0 <= port <= 65535:
        raise ZeekRecordError(
            f"line {line_number}: invalid port in field {key!r}: {value!r}. Expected an integer from 0 to 65535.",
            line_number=line_number, category="invalid_port", field=key, value=value,
        )
    return port


def _protocol(record: dict[str, Any], line_number: int) -> str:
    value = str(_required(record, "proto", line_number)).strip().lower()
    if value not in SUPPORTED_PROTOCOLS:
        raise ZeekRecordError(
            f"line {line_number}: unsupported protocol {value!r}. Expected one of: {', '.join(sorted(SUPPORTED_PROTOCOLS))}.",
            line_number=line_number, category="invalid_protocol", field="proto", value=value,
        )
    return value


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
        record, _ = normalize_field_aliases(record, line_number)
        return NetworkEvent(
            timestamp=_timestamp(record, "ts", line_number),
            flow_id=str(_required(record, "uid", line_number)),
            src_ip=_ip(record, "id.orig_h", line_number),
            dst_ip=_ip(record, "id.resp_h", line_number),
            src_port=_port(record, "id.orig_p", line_number),
            dst_port=_port(record, "id.resp_p", line_number),
            protocol=_protocol(record, line_number),
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
