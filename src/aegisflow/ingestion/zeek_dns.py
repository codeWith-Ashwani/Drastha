from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from aegisflow.ingestion.zeek_jsonl import (
    ZeekRecordError,
    _ip,
    _required,
    _timestamp,
    normalize_field_aliases,
)
from aegisflow.models import DNSEvent


DNS_NORMALIZER_VERSION = "2.0"
_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
           16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
           4: "NOTIMP", 5: "REFUSED"}


def _dns_code(value: Any, names: dict[int, str]) -> str:
    if value is None or value == "":
        return "UNKNOWN"
    text = str(value).strip().upper()
    # Unknown numeric values remain visible; do not silently invent a type.
    return names.get(int(text), text) if text.isdecimal() else text


def normalize_dns_record(record: dict[str, Any], line_number: int = 1) -> DNSEvent:
    try:
        record, _ = normalize_field_aliases(record, line_number)
        features = record.get("features", record.get("ml_evidence", record.get("evidence", {})))
        features = features if isinstance(features, dict) else {}
        if not record.get("query"):
            query_value = record.get("query_name") or features.get("query_name")
            if query_value:
                record = {**record, "query": query_value}
        query = str(_required(record, "query", line_number)).strip().lower().rstrip(".")
        answers = record.get("answers") or ()
        if isinstance(answers, str):
            answers = (answers,)
        if not isinstance(answers, (list, tuple)):
            raise ValueError("answers must be a list")
        return DNSEvent(
            timestamp=_timestamp(record, "ts", line_number),
            flow_id=str(_required(record, "uid", line_number)),
            src_ip=_ip(record, "id.orig_h", line_number),
            dst_ip=_ip(record, "id.resp_h", line_number),
            query=query,
            query_type=_dns_code(record.get("qtype_name") or record.get("qtype")
                                 or features.get("record_type"), _QTYPES),
            response_code=_dns_code(record.get("rcode_name") or record.get("rcode"), _RCODES),
            answers=tuple(str(answer) for answer in answers),
            rejected=bool(record.get("rejected", False)),
            source="zeek:dns",
            raw=record,
        )
    except ZeekRecordError:
        raise
    except (TypeError, ValueError) as exc:
        raise ZeekRecordError(f"line {line_number}: invalid Zeek DNS field value: {exc}") from exc


def read_dns_jsonl(path: str | Path) -> Iterator[DNSEvent]:
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
            yield normalize_dns_record(record, line_number)
