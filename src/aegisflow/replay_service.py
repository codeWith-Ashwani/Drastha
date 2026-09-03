"""File/Zeek-directory adapters for the same analysis used by HTTP uploads."""
from pathlib import Path

from aegisflow.analysis_session import DEPLOYMENT_BASELINE
from aegisflow.ingestion.passive_replay import PreparedReplay, prepare_replay
from aegisflow.telemetry_quality import TelemetryQuality
from aegisflow.analysis_service import analyse_prepared


def prepare_zeek_directory(directory):
    directory = Path(directory)
    parts = []
    for name, kind in (("conn.log", "connection"), ("dns.log", "dns"),
                       ("ssl.log", "tls"), ("quic.log", "quic")):
        path = directory / name
        if path.is_file() and path.stat().st_size:
            parts.append(prepare_replay(path.read_text(encoding="utf-8"), name,
                                       maximum_records=None, source_kind=kind))
    if not parts:
        raise ValueError("No supported Zeek logs found")
    quality = TelemetryQuality(stream="passive:zeek-directory", source=str(directory))
    for part in parts:
        for field in ("records_seen", "records_accepted", "records_rejected", "records_quarantined",
                      "out_of_order_records", "duplicate_uid_count", "exact_duplicate_count",
                      "conflicting_duplicate_uid_count", "invalid_timestamp_count", "unsupported_record_count"):
            setattr(quality, field, getattr(quality, field) + getattr(part.quality, field))
        quality.maximum_backward_skew_seconds = max(quality.maximum_backward_skew_seconds,
                                                    part.quality.maximum_backward_skew_seconds)
        quality.errors.extend(part.quality.errors)
        quality.quarantined_records.extend(part.quality.quarantined_records)
        quality.degraded_reasons.extend(part.quality.degraded_reasons)
        if part.quality.status != "healthy":
            quality.status = "degraded"
    return PreparedReplay(
        [e for p in parts for e in p.events], [e for p in parts for e in p.dns_events],
        [e for p in parts for e in p.encrypted_events],
        [record for p in parts for record in p.accepted_records], quality,
        {"format": "zeek_directory", "schema": "mixed", "sources": [p.input_schema for p in parts]},
    )


def analyse_replay_file(path, repository, *, root=None, profile=DEPLOYMENT_BASELINE, model_path=None):
    path = Path(path)
    prepared = (prepare_zeek_directory(path) if path.is_dir() else
                prepare_replay(path.read_text(encoding="utf-8"), path.name, maximum_records=None))
    return analyse_prepared(prepared, repository, filename=path.name, profile=profile,
                            root=root, model_path=model_path)
