"""Checksum-pinned, split-audited evaluation through the shared analysis path.

No downloader, training or threshold search is invoked by this offline module.
"""
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import time

from aegisflow.analysis_service import analyse_prepared
from aegisflow.analysis_session import AnalysisSession, DEPLOYMENT_BASELINE
from aegisflow.benchmark_data import prepare_dataset
from aegisflow.benchmark_metrics import metrics, score_units
from aegisflow.context_policy import ContextPolicy
from aegisflow.dns_model import DNSNgramModel


VERSION = "drastha-corpus-v1"
SPLITS = {"train", "validation", "test"}
MAX_FILE_BYTES = 64_000_000


class ReportRepository:
    def import_records(self, incidents, alerts, feedback=()):
        return {"incidents": 0, "alerts": 0, "feedback": 0}


def pinned_file(root, entry):
    if not isinstance(entry, dict):
        raise ValueError("Pinned file descriptor must be an object")
    relative = entry.get("path")
    digest = entry.get("sha256")
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise ValueError("Corpus paths must be relative to the explicit data root")
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or path == root:
        raise ValueError("Corpus path escapes data root")
    if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
        raise ValueError("A pinned lowercase SHA-256 is required")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Corpus file exceeds 64 MB adapter limit; use reviewed whole-capture artifacts")
    payload = path.read_bytes()
    if sha256(payload).hexdigest() != digest:
        raise ValueError(f"Checksum mismatch: {relative}")
    return payload.decode("utf-8-sig")


def protect_outputs(manifest_path, data_root, outputs):
    """Prevent CLI reports/databases from overwriting read-only corpus inputs."""
    root = Path(data_root).resolve()
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("artifacts"), list):
        raise ValueError("Invalid corpus manifest")
    inputs = {Path(manifest_path).resolve()}
    entries = list(manifest.get("artifacts", []))
    if manifest.get("dns_model"):
        entries.append(manifest["dns_model"])
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            inputs.add((root / entry["path"]).resolve())
        labels = entry.get("labels", {}) if isinstance(entry, dict) else {}
        if isinstance(labels, dict) and isinstance(labels.get("path"), str):
            inputs.add((root / labels["path"]).resolve())
    destinations = []
    for output in outputs:
        if output is not None:
            value = str(output)
            if value.startswith(("postgresql://", "postgres://")):
                continue
            value = value.removeprefix("sqlite:///")
            resolved = Path(value).resolve()
            if resolved in inputs or resolved in destinations:
                raise ValueError("Benchmark outputs must not overwrite inputs or each other")
            destinations.append(resolved)


def load_corpus(manifest_path, data_root):
    root = Path(data_root).resolve()
    raw = Path(manifest_path).read_bytes()
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != VERSION:
        raise ValueError("Unsupported corpus manifest version")
    if not isinstance(manifest.get("corpus_id"), str) or not manifest["corpus_id"]:
        raise ValueError("corpus_id is required")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 100:
        raise ValueError("Corpus must contain 1..100 artifacts")
    ids, captures, groups, hashes = set(), set(), {}, {}
    loaded = []
    telemetry_splits = {}
    total_records = 0
    for entry in artifacts:
        if not isinstance(entry, dict):
            raise ValueError("Invalid artifact")
        identifier, split = entry.get("id"), entry.get("split")
        if not isinstance(identifier, str) or not identifier or identifier in ids or split not in SPLITS:
            raise ValueError("Invalid/duplicate artifact id or split")
        ids.add(identifier)
        capture = entry.get("capture_id")
        group_ids = entry.get("group_ids")
        if not isinstance(capture, str) or not capture or not isinstance(group_ids, list) or not group_ids:
            raise ValueError("capture_id and nonempty group_ids are required")
        if capture in captures:
            raise ValueError("Duplicate capture_id: capture leakage or fragmentation; one complete capture per artifact is required")
        captures.add(capture)
        for group in ["capture:" + capture, *group_ids]:
            if not isinstance(group, str) or not group:
                raise ValueError("Group IDs must be nonempty strings")
            if group in groups and groups[group] != split:
                raise ValueError(f"Cross-split capture/family/group leakage: {group}")
            groups[group] = split
        origin = entry.get("origin", {})
        if not isinstance(origin, dict) or origin.get("kind") not in {"synthetic", "external"}:
            raise ValueError("Artifact origin must explicitly be synthetic or external")
        if origin["kind"] == "external":
            required = ("source_url", "license", "license_url", "citation", "retrieved_at")
            if any(not isinstance(origin.get(name), str) or not origin[name].strip() for name in required):
                raise ValueError("External data requires source, license, citation and retrieval provenance")
            timestamp = datetime.fromisoformat(origin["retrieved_at"].replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                raise ValueError("Retrieval timestamp requires a timezone")
        text = pinned_file(root, entry)
        digest = entry["sha256"]
        if digest in hashes:
            raise ValueError("Duplicate capture content, including cross-split copies")
        hashes[digest] = split
        labels = None
        if entry.get("format") == "zeek-jsonl":
            label_document = json.loads(pinned_file(root, entry.get("labels", {})))
            if not isinstance(label_document, dict):
                raise ValueError("Label sidecar must be an object containing units")
            labels = label_document.get("units")
        prepared, units, details, fingerprints = prepare_dataset(
            text, entry["id"], format=entry.get("format"), labels=labels,
            offset_minutes=entry.get("timestamp_utc_offset_minutes"))
        total_records += prepared.quality.records_seen
        if "expected_records" in entry and entry["expected_records"] != prepared.quality.records_seen:
            raise ValueError("Artifact record count differs from pinned expected_records")
        if total_records > 500_000:
            raise ValueError("Corpus exceeds the 500,000-record offline evaluation limit")
        for fingerprint in fingerprints:
            previous = telemetry_splits.get(fingerprint)
            if previous is not None and previous != split:
                raise ValueError("Duplicate normalized telemetry across splits (UID/labels do not hide leakage)")
            telemetry_splits[fingerprint] = split
        loaded.append((entry, prepared, units, details))
    return manifest, sha256(raw).hexdigest(), loaded


def run_benchmark(manifest_path, *, data_root, split="test", repository=None):
    if split not in SPLITS:
        raise ValueError("Invalid evaluation split")
    started = time.perf_counter()
    manifest, manifest_digest, loaded = load_corpus(manifest_path, data_root)
    selected = [item for item in loaded if item[0]["split"] == split]
    if not selected:
        raise ValueError(f"No artifacts in selected {split} split")
    # Trusted, frozen benchmark configuration. Never inherit demo policy/model
    # files or operator environment variables implicitly in a reproducibility run.
    cidrs = manifest.get("internal_cidrs", [])
    if not isinstance(cidrs, list) or any(not isinstance(x, str) for x in cidrs):
        raise ValueError("internal_cidrs must be a list")
    profile = replace(DEPLOYMENT_BASELINE, internal_cidrs=tuple(cidrs))
    model = None
    model_entry = manifest.get("dns_model")
    if model_entry is not None:
        if not isinstance(model_entry, dict):
            raise ValueError("dns_model must be a pinned file descriptor")
        groups = model_entry.get("training_group_ids", [])
        if not isinstance(groups, list) or not groups or any(not isinstance(g, str) or not g for g in groups):
            raise ValueError("Pinned model requires training_group_ids lineage")
        train_groups = {g for entry, *_ in loaded if entry["split"] == "train" for g in entry["group_ids"]}
        if not set(groups) <= train_groups:
            raise ValueError("Model training lineage must reference audited training groups")
        model = DNSNgramModel(json.loads(pinned_file(Path(data_root).resolve(), model_entry)))
    runs = []
    repository = repository or ReportRepository()
    aggregate = Counter()
    per_class = defaultdict(Counter)
    for entry, prepared, units, details in selected:
        session = AnalysisSession(profile, context_policy=ContextPolicy(), dns_model=model)
        analysed = analyse_prepared(prepared, repository, filename=entry["id"], session=session)
        scores = score_units(units, analysed["alerts"], {record["uid"] for record in prepared.accepted_records})
        for key in ("tp", "fp", "fn", "tn"):
            aggregate[key] += scores["binary_alert_coverage"][key]
        for name, values in scores["per_class"].items():
            per_class[name].update({key: values[key] for key in ("tp", "fp", "fn", "tn")})
        result = {"artifact_id": entry["id"], "capture_id": entry["capture_id"], "split": split,
                  "origin": entry["origin"], "source_sha256": entry["sha256"],
                  "adapter": details, "quality": analysed["quality"], "feature_coverage": analysed["feature_coverage"],
                  "findings": len(analysed["alerts"]), "incidents": len(analysed["incidents"]),
                  "observed_subtypes": dict(Counter(a["subtype"] for a in analysed["alerts"])),
                  "scores": scores, "analysis_provenance": analysed["analysis_provenance"],
                  "run_id": analysed["run_id"], "analysis_ms": analysed["analysis_ms"]}
        if hasattr(repository, "save_analysis_run"):
            repository.save_analysis_run(analysed["run_id"], {**analysed, "benchmark": {
                "manifest_sha256": manifest_digest, "split": split, "scores": scores, "source_sha256": entry["sha256"]}})
        runs.append(result)
    return {"schema_version": "drastha-benchmark-v1", "corpus_id": manifest["corpus_id"],
            "manifest_sha256": manifest_digest, "split": split, "threshold_selection_performed": False,
            "executed_at": datetime.now(timezone.utc).isoformat(), "elapsed_ms": round((time.perf_counter()-started)*1000, 3),
            "split_audit": {"artifacts": len(loaded), "groups_checked": True,
                "normalized_cross_split_duplicates": 0, "resets": "one session per capture artifact, never from labels",
                "registered_splits": sorted({entry["split"] for entry, *_ in loaded})},
            "runs": runs, "pooled_binary_alert_coverage": metrics(aggregate),
            "per_class": {name: metrics(values) for name, values in per_class.items()},
            "limitations": ["Frozen uncalibrated detector thresholds; not a production-accuracy claim.",
                "Unknown/background labels are excluded from confusion matrices but retained during inference.",
                "No implicit demo model or allowlist; missing features and rejected records are reported.",
                "Registered splits and checksums cannot prove source-label correctness or absence of undeclared prior training.",
                "Flow-based units measure membership in emitted alerts, not full per-flow or packet classification.",
                "Generic malicious labels do not validate attack-specific classification; inspect per-capture denominators."]}
