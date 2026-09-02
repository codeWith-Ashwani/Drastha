from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Any

from aegisflow.ingestion.zeek_jsonl import FIELD_ALIASES, ZeekRecordError


@dataclass(frozen=True, slots=True)
class ParsedReplay:
    input_format: str
    records: tuple[tuple[int, Any], ...]


def parse_replay_content(content: str, filename: str = "") -> ParsedReplay:
    """Parse supported JSON containers while retaining record/line locations."""
    stripped = content.strip()
    if not stripped:
        return ParsedReplay("empty", ())

    if stripped.startswith(("[", "{")):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            if exc.msg != "Extra data":
                raise ValueError(
                    f"Line {exc.lineno}: invalid JSON at column {exc.colno}: {exc.msg}."
                ) from exc
        else:
            if isinstance(parsed, list):
                return ParsedReplay(
                    "json_array", tuple(enumerate(parsed, start=1))
                )
            if isinstance(parsed, dict) and "records" in parsed:
                if not isinstance(parsed["records"], list):
                    if "dataset" in parsed and isinstance(parsed["records"], int):
                        dataset = str(parsed.get("dataset") or "the referenced JSONL dataset")[:120]
                        raise ValueError(
                            f"This file is a dataset manifest, not a traffic replay. It describes "
                            f"{parsed['records']} records but does not contain a records array. "
                            f"Upload {dataset!r} itself, or another JSONL/NDJSON traffic file."
                        )
                    raise ValueError(
                        "Unsupported JSON structure: 'records' must be an array of objects. "
                        "Expected JSONL, a JSON array, one record object, or {'records': [...]}."
                    )
                return ParsedReplay(
                    "wrapped_json", tuple(enumerate(parsed["records"], start=1))
                )
            if isinstance(parsed, dict) and filename.lower().endswith((".jsonl", ".ndjson")):
                return ParsedReplay("jsonl", ((1, parsed),))
            if isinstance(parsed, dict):
                return ParsedReplay("single_json_object", ((1, parsed),))
            raise ValueError(
                "Unsupported JSON structure. Expected JSONL, a JSON array, one record "
                "object, or {'records': [...]} ."
            )

    records: list[tuple[int, Any]] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            records.append((line_number, json.loads(value)))
        except json.JSONDecodeError as exc:
            records.append((
                line_number,
                ZeekRecordError(
                    f"Line {line_number}: invalid JSON at column {exc.colno}: {exc.msg}.",
                    line_number=line_number,
                    category="invalid_json",
                ),
            ))
    return ParsedReplay("jsonl", tuple(records))


def record_schema(record: dict[str, Any]) -> str:
    features = record.get(
        "features", record.get("ml_evidence", record.get("evidence", {}))
    )
    features = features if isinstance(features, dict) else {}
    if record.get("query") or record.get("query_name") or features.get("query_name"):
        return "dns"
    if any(
        record.get(name) or features.get(name)
        for name in (
            "ja3", "ja3s", "ja4", "client_fingerprint", "client fingerprint",
            "server_fingerprint", "server fingerprint",
        )
    ):
        transport = str(record.get("transport") or record.get("proto") or "tls").lower()
        return "quic" if transport == "quic" else "tls"
    return "connection"


def schema_summary(
    input_format: str,
    raw_records: list[tuple[int, Any]],
    alias_usage: Counter[tuple[str, str]],
    schema_counts: Counter[str],
) -> dict[str, Any]:
    valid_objects = [item for _, item in raw_records if isinstance(item, dict)]
    fields = sorted({key for item in valid_objects[:25] for key in item})
    aliases = [
        {"source": source, "canonical": target, "records": count}
        for (target, source), count in sorted(alias_usage.items())
    ]
    resolved_fields: dict[str, str | None] = {}
    for target, candidates in FIELD_ALIASES.items():
        resolved_fields[target] = next(
            (candidate for candidate in candidates if any(candidate in item for item in valid_objects[:25])),
            None,
        )
    likely = "mixed" if len(schema_counts) > 1 else next(iter(schema_counts), "unknown")
    if aliases and likely == "connection":
        likely = "flow_style"
    return {
        "format": input_format,
        "schema": likely,
        "records": len(raw_records),
        "record_types": dict(sorted(schema_counts.items())),
        "detected_fields": fields,
        "resolved_fields": resolved_fields,
        "aliases_used": aliases,
    }
