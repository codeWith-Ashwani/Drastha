from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from aegisflow.analysis_session import AnalysisProfile, UPLOAD_DEMO
from aegisflow.ingestion.passive_replay import prepare_replay
from aegisflow.findings import resolve_findings as _deduplicate_and_resolve_conflicts
from aegisflow.analysis_service import analyse_prepared
from aegisflow.ingestion.replay_input import (
    parse_replay_content,
)


MAX_UPLOAD_BYTES = 5_000_000
MAX_UPLOAD_RECORDS = 20_000
ALLOWED_SUFFIXES = {".jsonl", ".ndjson", ".json"}


def _records_from_content(content: str) -> list[tuple[int, Any]]:
    return list(parse_replay_content(content).records)


def analyse_uploaded_replay(
    filename: str,
    content: str,
    repository: Any,
    *,
    profile: AnalysisProfile = UPLOAD_DEMO,
) -> dict[str, Any]:
    started = time.perf_counter()
    safe_name = Path(filename).name[:120]
    suffix = Path(safe_name).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise ValueError("Upload a Zeek connection replay as .jsonl, .ndjson or .json.")
    upload_bytes = len(content.encode("utf-8"))
    if upload_bytes > MAX_UPLOAD_BYTES:
        raise ValueError("Replay file is larger than the 5 MB demonstration limit.")

    prepared = prepare_replay(content, safe_name, maximum_records=MAX_UPLOAD_RECORDS)
    return analyse_prepared(prepared, repository, filename=safe_name, upload_bytes=upload_bytes,
                            started=started, profile=profile)
