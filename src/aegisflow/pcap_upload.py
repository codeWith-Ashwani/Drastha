"""Browser-upload adapter for passive classic-PCAP analysis.

The uploaded capture is decoded into a short-lived local file, converted to
Zeek JSON logs, attached for measured packet timing/size and JA3 metadata, and
then passed through the same analysis service used by JSON/JSONL replays.
"""
from __future__ import annotations

import base64
import binascii
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from aegisflow.analysis_service import analyse_prepared
from aegisflow.analysis_session import AnalysisProfile, AnalysisSession, UPLOAD_DEMO
from aegisflow.ingestion.capture_join import attach_capture
from aegisflow.ingestion.zeek_runner import (
    WSLZeekRunner,
    ZeekExecutionError,
    ZeekRunner,
    ZeekUnavailableError,
)
from aegisflow.replay_service import prepare_zeek_directory


MAX_PCAP_UPLOAD_BYTES = 5_000_000
MAX_PCAP_BASE64_CHARS = ((MAX_PCAP_UPLOAD_BYTES + 2) // 3) * 4
MAX_PCAP_DERIVED_RECORDS = 20_000
PCAP_PROCESSING_TIMEOUT_SECONDS = 30.0
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}


def _configured_runner() -> ZeekRunner | WSLZeekRunner:
    mode = os.getenv("DRASTHA_ZEEK_MODE", "auto").strip().lower()
    if mode not in {"auto", "native", "wsl"}:
        raise ValueError("DRASTHA_ZEEK_MODE must be auto, native or wsl.")
    if mode == "auto":
        mode = "wsl" if os.name == "nt" else "native"
    executable = os.getenv("DRASTHA_ZEEK_BINARY")
    if mode == "wsl":
        return WSLZeekRunner(
            executable=executable or "/opt/zeek/bin/zeek",
            distribution=os.getenv("DRASTHA_WSL_DISTRO") or None,
        )
    return ZeekRunner(executable or "zeek")


def _decode_capture(content_base64: str) -> bytes:
    if len(content_base64) > MAX_PCAP_BASE64_CHARS:
        raise ValueError("PCAP file is larger than the 5 MB demonstration limit.")
    try:
        capture = base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("PCAP upload is not valid base64 data.") from exc
    if not capture:
        raise ValueError("PCAP upload is empty.")
    if len(capture) > MAX_PCAP_UPLOAD_BYTES:
        raise ValueError("PCAP file is larger than the 5 MB demonstration limit.")
    if capture[:4] not in PCAP_MAGICS:
        raise ValueError("Upload a classic .pcap file. PCAPNG is not supported by this upload path.")
    return capture


def analyse_uploaded_pcap(
    filename: str,
    content_base64: str,
    repository: Any,
    *,
    profile: AnalysisProfile = UPLOAD_DEMO,
    session: AnalysisSession | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    safe_name = Path(filename).name[:120]
    if Path(safe_name).suffix.lower() != ".pcap":
        raise ValueError("Upload a classic packet capture with the .pcap extension.")
    capture = _decode_capture(content_base64)

    try:
        with tempfile.TemporaryDirectory(prefix="drastha-pcap-upload-") as directory:
            workspace = Path(directory)
            capture_path = workspace / "capture.pcap"
            capture_path.write_bytes(capture)
            result = _configured_runner().process_pcap(
                capture_path,
                workspace / "zeek",
                timeout_seconds=PCAP_PROCESSING_TIMEOUT_SECONDS,
            )
            # Zeek writes completed connections in close order, while their `ts`
            # values describe start time. Sorting this derived output avoids
            # mislabelling a chronological capture as bad input. Packet order in
            # the original PCAP is still checked independently by attach_capture.
            prepared = prepare_zeek_directory(
                result.output_directory, chronological_generated_logs=True
            )
            if prepared.quality.records_seen > MAX_PCAP_DERIVED_RECORDS:
                raise ValueError(
                    "PCAP produced more than the 20,000-record demonstration limit."
                )
            prepared.quality.stream = "passive:pcap-upload"
            prepared.quality.source = safe_name
            prepared = attach_capture(prepared, capture_path)
            prepared.input_schema = {
                **prepared.input_schema,
                "source_upload": {
                    "format": "pcap",
                    "filename": safe_name,
                    "zeek_logs": [path.name for path in result.log_files],
                    "temporary_processing": True,
                    "raw_capture_retained": False,
                },
            }
            return analyse_prepared(
                prepared,
                repository,
                filename=safe_name,
                upload_bytes=len(capture),
                started=started,
                profile=profile,
                session=session,
            )
    except (ZeekUnavailableError, ZeekExecutionError) as exc:
        raise ValueError(f"PCAP could not be analysed with Zeek: {exc}") from exc
