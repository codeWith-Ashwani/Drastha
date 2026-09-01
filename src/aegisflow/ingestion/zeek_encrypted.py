from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from aegisflow.ingestion.zeek_jsonl import ZeekRecordError, _required, _timestamp
from aegisflow.models import EncryptedSessionMetadata


def normalize_encrypted_record(
    record: dict[str, Any], line_number: int = 1, transport: str = "tls"
) -> EncryptedSessionMetadata:
    try:
        features = record.get(
            "features", record.get("ml_evidence", record.get("evidence", {}))
        )
        if not isinstance(features, dict):
            features = {}
        fingerprint = (
            record.get("ja4")
            or record.get("ja3")
            or record.get("client_fingerprint")
            or features.get("ja4")
            or features.get("ja3")
            or ""
        )
        return EncryptedSessionMetadata(
            timestamp=_timestamp(record, "ts", line_number),
            flow_id=str(_required(record, "uid", line_number)),
            src_ip=str(_required(record, "id.orig_h", line_number)),
            dst_ip=str(_required(record, "id.resp_h", line_number)),
            transport=transport.lower(),
            server_name=str(record.get("server_name", features.get("server_name", "")) or "").lower(),
            version=str(record.get("version", features.get("tls_version", "")) or ""),
            cipher=str(record.get("cipher", features.get("cipher", "")) or ""),
            application_protocol=str(
                record.get("next_protocol", record.get("alpn", record.get("service", ""))) or ""
            ),
            client_fingerprint=str(fingerprint),
            server_fingerprint=str(record.get("ja3s", record.get("server_fingerprint", "")) or ""),
            established=bool(record.get("established", False)),
            resumed=bool(record.get("resumed", False)),
            source=f"zeek:{transport.lower()}",
            raw=record,
        )
    except ZeekRecordError:
        raise
    except (TypeError, ValueError) as exc:
        raise ZeekRecordError(
            f"line {line_number}: invalid Zeek encrypted-session field value: {exc}"
        ) from exc


def read_encrypted_jsonl(
    path: str | Path, transport: str = "tls"
) -> Iterator[EncryptedSessionMetadata]:
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
            yield normalize_encrypted_record(record, line_number, transport)


def build_encrypted_metadata_index(
    events: list[EncryptedSessionMetadata],
) -> dict[str, tuple[EncryptedSessionMetadata, float]]:
    """Index metadata by flow and attach a contextual, non-triggering anomaly score."""
    fingerprint_counts = Counter(
        event.client_fingerprint for event in events if event.client_fingerprint
    )
    index: dict[str, tuple[EncryptedSessionMetadata, float]] = {}
    for event in events:
        score = 0.0
        if not event.server_name:
            score += 0.25
        if event.version and event.version not in {"TLSv12", "TLSv13", "TLS 1.2", "TLS 1.3"}:
            score += 0.25
        if not event.established:
            score += 0.20
        if event.client_fingerprint and fingerprint_counts[event.client_fingerprint] == 1:
            score += 0.20
        index[event.flow_id] = (event, round(min(score, 1.0), 3))
    return index
