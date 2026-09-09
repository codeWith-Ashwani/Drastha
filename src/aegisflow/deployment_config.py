"""Fail-closed operator deployment contract for the passive monitoring enclave."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import ip_network
import json
from pathlib import Path
import re

from aegisflow.context_policy import ContextPolicy, load_context_policy_file


VERSION = "drastha-deployment-v1"


@dataclass(frozen=True, slots=True)
class DeploymentSettings:
    deployment_id: str
    internal_cidrs: tuple[str, ...]
    context_policy: ContextPolicy
    context_policy_sha256: str
    confidence_semantics: str
    confidence_calibration_status: str
    dns_model_status: str
    source: str
    sha256: str


def _pinned_relative_file(config_path: Path, descriptor: object) -> tuple[Path, str]:
    if not isinstance(descriptor, dict):
        raise ValueError("deployment context_policy must be a pinned file descriptor")
    relative, expected = descriptor.get("path"), descriptor.get("sha256")
    if not isinstance(relative, str) or Path(relative).is_absolute() or not relative:
        raise ValueError("deployment context policy path must be relative to the deployment file")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("deployment context policy requires lowercase SHA-256")
    root = config_path.parent.resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or path == root:
        raise ValueError("deployment context policy escapes its configuration directory")
    payload = path.read_bytes()
    if sha256(payload).hexdigest() != expected:
        raise ValueError("deployment context policy checksum mismatch")
    return path, expected


def load_deployment_config(path: str | Path) -> DeploymentSettings:
    path = Path(path).resolve(strict=True)
    if path.stat().st_size > 65_536:
        raise ValueError("deployment configuration exceeds 64 KiB")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid deployment configuration: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != VERSION:
        raise ValueError(f"deployment schema_version must be {VERSION}")
    deployment_id = payload.get("deployment_id")
    if not isinstance(deployment_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}", deployment_id):
        raise ValueError("deployment_id must be a stable lowercase identifier")
    cidrs = payload.get("internal_cidrs")
    if not isinstance(cidrs, list) or not cidrs or any(not isinstance(item, str) for item in cidrs):
        raise ValueError("deployment internal_cidrs must be a nonempty string array")
    try:
        networks = tuple(ip_network(item, strict=True) for item in cidrs)
    except ValueError as exc:
        raise ValueError(f"invalid deployment network boundary: {exc}") from exc
    if len(set(networks)) != len(networks):
        raise ValueError("duplicate deployment network boundary")
    if any(left.version == right.version and left.overlaps(right)
           for index, left in enumerate(networks) for right in networks[index + 1:]):
        raise ValueError("overlapping deployment boundaries are ambiguous")
    confidence = payload.get("confidence")
    if not isinstance(confidence, dict):
        raise ValueError("deployment confidence declaration is required")
    if confidence.get("semantics") != "heuristic_evidence_score":
        raise ValueError("confidence semantics must remain heuristic_evidence_score")
    if confidence.get("probability_calibrated") is not False:
        raise ValueError("this release has no approved probability calibrator")
    if confidence.get("calibration_status") != "not_probability_calibrated":
        raise ValueError("confidence calibration status must disclose the current limitation")
    passive = payload.get("passive_constraints")
    required = {"read_only_ingest": True, "no_return_path": True,
                "payload_decryption": False, "active_mitigation": False}
    if passive != required:
        raise ValueError("deployment passive constraints must match the enclave safety contract")
    if payload.get("dns_model", "missing") is not None:
        raise ValueError("this release has no production-approved DNS model; dns_model must be null")
    policy_path, policy_digest = _pinned_relative_file(path, payload.get("context_policy"))
    return DeploymentSettings(
        deployment_id=deployment_id,
        internal_cidrs=tuple(str(item) for item in networks),
        context_policy=load_context_policy_file(policy_path),
        context_policy_sha256=policy_digest,
        confidence_semantics="heuristic_evidence_score",
        confidence_calibration_status="not_probability_calibrated",
        dns_model_status="none_production_approved",
        source=str(path),
        sha256=sha256(raw).hexdigest(),
    )
