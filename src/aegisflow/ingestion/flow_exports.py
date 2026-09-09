"""Normalize collector-decoded NetFlow, IPFIX and sFlow records.

The adapters intentionally accept JSON/NDJSON exported by a passive collector;
they are not binary wire-protocol decoders.  Every record is copied, retains its
original fields, and receives explicit provenance before entering the shared
Zeek-shaped connection normalizer.
"""
from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any

from aegisflow.ingestion.zeek_jsonl import ZeekRecordError


FLOW_FORMATS = {"netflow", "ipfix", "sflow"}
PROTOCOL_NUMBERS = {
    1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ah",
    58: "icmp6", 132: "sctp",
}


def _lookup(record: dict[str, Any], *names: str) -> tuple[str | None, Any]:
    for name in names:
        if name in record and record[name] not in (None, ""):
            return name, record[name]
        current: Any = record
        found = True
        for part in name.split("."):
            if not isinstance(current, dict) or part not in current:
                found = False
                break
            current = current[part]
        if found and current not in (None, ""):
            return name, current
    return None, None


def _present(record: dict[str, Any], names: tuple[str, ...]) -> list[tuple[str, Any]]:
    values: list[tuple[str, Any]] = []
    for name in names:
        field, value = _lookup(record, name)
        if field is not None:
            values.append((field, value))
    return values


def detect_flow_format(record: dict[str, Any]) -> str | None:
    """Return a supported collector format only when its signature is explicit."""
    _, explicit = _lookup(record, "flow_format", "export_format", "collector.format")
    if explicit:
        value = str(explicit).strip().lower().replace("-v5", "").replace("-v9", "")
        if value in FLOW_FORMATS:
            return value
    keys = set(record)
    if keys & {"sourceIPv4Address", "sourceIPv6Address", "octetDeltaCount",
               "packetDeltaCount", "flowStartMilliseconds"}:
        return "ipfix"
    if keys & {"srcaddr", "dstaddr", "dOctets", "dPkts", "tcp_flags", "unix_secs"}:
        return "netflow"
    if keys & {"srcIP", "dstIP", "ipProtocol", "samplingRate", "sampledPacketSize"}:
        return "sflow"
    return None


def _timestamp(value: Any, unit: str, line_number: int, field: str) -> float:
    text = str(value).strip()
    try:
        numeric = float(text)
    except (TypeError, ValueError, OverflowError):
        numeric = None
    if numeric is not None:
        if not math.isfinite(numeric):
            raise ZeekRecordError(
                f"line {line_number}: timestamp must be finite",
                line_number=line_number, category="invalid_timestamp", field=field, value=text,
            )
        return numeric / 1000.0 if unit == "milliseconds" else numeric
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ZeekRecordError(
            f"line {line_number}: invalid timestamp in exporter field {field!r}: {text!r}.",
            line_number=line_number, category="invalid_timestamp", field=field, value=text,
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _protocol(value: Any, line_number: int, field: str) -> str:
    text = str(value).strip().lower()
    try:
        number = int(text)
    except ValueError:
        return text
    if number not in PROTOCOL_NUMBERS:
        raise ZeekRecordError(
            f"line {line_number}: unsupported IP protocol number {number!r} in {field!r}.",
            line_number=line_number, category="invalid_protocol", field=field, value=value,
        )
    return PROTOCOL_NUMBERS[number]


def _integer(value: Any, line_number: int, field: str) -> int:
    try:
        result = int(value or 0)
    except (TypeError, ValueError) as exc:
        raise ZeekRecordError(
            f"line {line_number}: invalid integer in exporter field {field!r}: {value!r}.",
            line_number=line_number, category="invalid_record", field=field, value=value,
        ) from exc
    if result < 0:
        raise ZeekRecordError(
            f"line {line_number}: exporter counter {field!r} cannot be negative.",
            line_number=line_number, category="invalid_record", field=field, value=value,
        )
    return result


def _stable_uid(flow_format: str, raw: dict[str, Any]) -> str:
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False, default=str).encode("utf-8")
    return f"{flow_format}-{hashlib.sha256(encoded).hexdigest()[:20]}"


def _mapping(flow_format: str) -> dict[str, tuple[str, ...]]:
    common = {
        "uid": ("uid", "flow_id", "flowId", "FLOW_ID", "sequence", "flowSample.sequence_number"),
        "id.orig_p": ("srcport", "srcPort", "sourceTransportPort", "source_port"),
        "id.resp_p": ("dstport", "dstPort", "destinationTransportPort", "destination_port"),
        "proto": ("prot", "protocol", "protocolIdentifier", "ipProtocol", "ipprotocol"),
    }
    if flow_format == "netflow":
        return {**common,
            "id.orig_h": ("srcaddr", "srcaddr_v6", "src_ip"),
            "id.resp_h": ("dstaddr", "dstaddr_v6", "dst_ip"),
            "orig_bytes": ("dOctets", "IN_BYTES", "bytes", "octets"),
            "orig_pkts": ("dPkts", "IN_PKTS", "packets"),
            "resp_bytes": ("OUT_BYTES", "reverse_bytes"),
            "resp_pkts": ("OUT_PKTS", "reverse_packets"),
        }
    if flow_format == "ipfix":
        return {**common,
            "id.orig_h": ("sourceIPv4Address", "sourceIPv6Address", "src_ip"),
            "id.resp_h": ("destinationIPv4Address", "destinationIPv6Address", "dst_ip"),
            "orig_bytes": ("octetDeltaCount", "octetTotalCount", "bytes"),
            "orig_pkts": ("packetDeltaCount", "packetTotalCount", "packets"),
            "resp_bytes": ("reverseOctetDeltaCount", "reverseOctetTotalCount"),
            "resp_pkts": ("reversePacketDeltaCount", "reversePacketTotalCount"),
        }
    return {**common,
        "id.orig_h": ("srcIP", "sourceIP", "src_ip"),
        "id.resp_h": ("dstIP", "destinationIP", "dst_ip"),
        "orig_bytes": ("bytes", "sampledPacketSize", "frameLength"),
        "orig_pkts": ("frames", "packets", "sampledPacketCount"),
        "resp_bytes": ("reverseBytes",),
        "resp_pkts": ("reverseFrames", "reversePackets"),
    }


def _flow_timestamp(record: dict[str, Any], flow_format: str, line_number: int) -> tuple[str, float]:
    field, value = _lookup(record, "flowStartMilliseconds", "flow_start_milliseconds")
    if field:
        return field, _timestamp(value, "milliseconds", line_number, field)
    if flow_format == "netflow":
        first_name, first = _lookup(record, "first", "First")
        uptime_name, uptime = _lookup(record, "sys_uptime", "sysUpTime")
        unix_name, unix_seconds = _lookup(record, "unix_secs", "unixSeconds")
        if first_name and uptime_name and unix_name:
            observed = float(unix_seconds) - (float(uptime) - float(first)) / 1000.0
            return unix_name, _timestamp(observed, "seconds", line_number, unix_name)
    field, value = _lookup(
        record, "flowStartSeconds", "unix_secs", "unixSecondsUTC", "timestamp", "ts", "time"
    )
    if field:
        return field, _timestamp(value, "seconds", line_number, field)
    raise ZeekRecordError(
        f"line {line_number}: missing required timestamp for {flow_format} record.",
        line_number=line_number, category="missing_required_field", field="ts",
    )


def normalize_exported_flow_record(
    record: dict[str, Any], line_number: int = 1, flow_format: str | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Return a canonical, provenance-bearing copy of one decoded flow record."""
    selected = flow_format or detect_flow_format(record)
    if selected not in FLOW_FORMATS:
        raise ZeekRecordError(
            f"line {line_number}: unsupported or unrecognized exported flow format.",
            line_number=line_number, category="unsupported_record",
        )
    canonical = dict(record)
    aliases: dict[str, str] = {}
    timestamp_field, timestamp = _flow_timestamp(record, selected, line_number)
    canonical["ts"] = timestamp
    if timestamp_field != "ts":
        aliases["ts"] = timestamp_field

    for target, names in _mapping(selected).items():
        present = _present(record, names)
        comparable = {str(value).strip().lower() for _, value in present}
        if len(comparable) > 1:
            fields = ", ".join(field for field, _ in present)
            raise ZeekRecordError(
                f"line {line_number}: conflicting {selected} aliases for {target!r}: {fields}.",
                line_number=line_number, category="ambiguous_alias", field=target,
            )
        field, value = present[0] if present else (None, None)
        if field is None:
            continue
        if target in {"orig_bytes", "orig_pkts", "resp_bytes", "resp_pkts"}:
            value = _integer(value, line_number, field)
        elif target == "proto":
            value = _protocol(value, line_number, field)
        canonical[target] = value
        if field != target:
            aliases[target] = field

    generated_uid = not canonical.get("uid")
    if generated_uid:
        canonical["uid"] = _stable_uid(selected, record)

    duration_field, duration = _lookup(record, "flowDurationMilliseconds", "durationMilliseconds")
    if duration_field:
        canonical["duration"] = float(duration) / 1000.0
        aliases["duration"] = duration_field
    elif selected == "netflow":
        first_field, first = _lookup(record, "first", "First")
        last_field, last = _lookup(record, "last", "Last")
        if first_field and last_field:
            canonical["duration"] = max(0.0, (float(last) - float(first)) / 1000.0)

    flags_field, flags = _lookup(record, "tcpControlBits", "tcp_flags", "tcpFlags")
    if flags_field:
        try:
            bits = int(str(flags), 0)
        except ValueError:
            bits = 0
        if bits & 0x02 and not bits & 0x10 and canonical.get("resp_bytes", 0) == 0:
            canonical["conn_state"] = "S0"

    canonical["flow_export_format"] = selected
    canonical["_drastha_source"] = f"{selected}:collector"
    canonical["_drastha_ingest"] = {
        "adapter": "collector-flow-json-v1",
        "format": selected,
        "passive": True,
        "generated_flow_id": generated_uid,
        "counter_semantics": "exported_direction_with_optional_reverse_counters",
        "sampling_rate_observed": _lookup(record, "samplingRate", "sampling_rate")[1],
    }
    return canonical, aliases
