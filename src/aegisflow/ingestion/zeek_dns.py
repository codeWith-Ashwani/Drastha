from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from aegisflow.ingestion.zeek_jsonl import ZeekRecordError, _required
from aegisflow.models import DNSEvent


def normalize_dns_record(record: dict[str, Any], line_number: int = 1) -> DNSEvent:
    try:
        answers = record.get("answers") or ()
        if isinstance(answers, str):
            answers = (answers,)
        if not isinstance(answers, (list, tuple)):
            raise ValueError("answers must be a list")
        return DNSEvent(
            timestamp=float(_required(record, "ts", line_number)),
            flow_id=str(_required(record, "uid", line_number)),
            src_ip=str(_required(record, "id.orig_h", line_number)),
            dst_ip=str(_required(record, "id.resp_h", line_number)),
            query=str(_required(record, "query", line_number)).strip().lower().rstrip("."),
            query_type=str(record.get("qtype_name", record.get("qtype", "UNKNOWN"))),
            response_code=str(record.get("rcode_name", record.get("rcode", "UNKNOWN"))),
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
