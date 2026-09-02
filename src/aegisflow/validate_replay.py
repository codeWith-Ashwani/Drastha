from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from aegisflow.upload_analysis import analyse_uploaded_replay


class _ValidationRepository:
    """No-op sink: validation never mutates the incident repository."""

    def import_records(
        self,
        incidents: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
        feedback: list[dict[str, Any]] | None = None,
    ) -> dict[str, int]:
        return {"incidents": 0, "alerts": 0, "feedback": 0}


def validate_replay_file(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    return analyse_uploaded_replay(
        source.name,
        source.read_text(encoding="utf-8-sig"),
        _ValidationRepository(),
    )


def validation_summary(report: dict[str, Any]) -> dict[str, Any]:
    quality = report["quality"]
    schema = report["input_schema"]
    telemetry = report["telemetry"]
    return {
        "file": report["filename"],
        "format": schema["format"],
        "schema": schema["schema"],
        "records": quality["records_received"],
        "record_types": {
            "connections": telemetry["connection_records"],
            "dns": telemetry["dns_records"],
            "tls_quic": telemetry["encrypted_session_records"],
        },
        "aliases_used": schema["aliases_used"],
        "quality": {
            "status": quality["status"],
            "accepted": quality["records_accepted"],
            "rejected": quality["records_rejected"],
            "quarantined": quality["records_quarantined"],
            "invalid_timestamps": quality["invalid_timestamp_count"],
            "out_of_order": quality["out_of_order_records"],
            "duplicate_uids": quality["duplicate_uid_count"],
            "unsupported_records": quality["unsupported_record_count"],
            "reasons": quality["degraded_reasons"],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a passive Drastha replay")
    parser.add_argument("file", type=Path)
    args = parser.parse_args(argv)
    try:
        summary = validation_summary(validate_replay_file(args.file))
    except (OSError, ValueError) as exc:
        print(f"Replay validation failed: {exc}")
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["quality"]["status"] == "healthy" else 1


if __name__ == "__main__":
    raise SystemExit(main())
