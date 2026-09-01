from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegisflow.models import NetworkEvent


@dataclass(frozen=True, slots=True)
class EndpointRule:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str = ""
    service: str = ""
    purpose: str = "approved operational traffic"

    def matches(self, event: NetworkEvent) -> bool:
        service = str(event.raw.get("service", "") or "").lower()
        return (
            event.src_ip == self.src_ip
            and event.dst_ip == self.dst_ip
            and event.dst_port == self.dst_port
            and (not self.protocol or event.protocol == self.protocol)
            and (not self.service or service == self.service)
        )


@dataclass(frozen=True, slots=True)
class ContextPolicy:
    trusted_periodic_endpoints: tuple[EndpointRule, ...] = ()
    approved_bulk_transfer_endpoints: tuple[EndpointRule, ...] = ()
    source: str = "none"


def _rules(value: Any, name: str) -> tuple[EndpointRule, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"context policy {name} must be an array")
    output: list[EndpointRule] = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"context policy {name}[{index}] must be an object")
        try:
            output.append(EndpointRule(
                src_ip=str(item["src_ip"]),
                dst_ip=str(item["dst_ip"]),
                dst_port=int(item["dst_port"]),
                protocol=str(item.get("protocol", "") or "").lower(),
                service=str(item.get("service", "") or "").lower(),
                purpose=str(item.get("purpose", "approved operational traffic")),
            ))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid context policy {name}[{index}]: {exc}") from exc
    return tuple(output)


def load_context_policy(root: str | Path | None = None) -> ContextPolicy:
    project_root = Path(root) if root is not None else Path(__file__).resolve().parents[2]
    configured = os.getenv("DRASTHA_CONTEXT_POLICY")
    path = Path(configured) if configured else project_root / "config" / "context_policy.json"
    if not path.is_file():
        return ContextPolicy(source="none")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not load context policy {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("context policy root must be an object")
    return ContextPolicy(
        trusted_periodic_endpoints=_rules(
            payload.get("trusted_periodic_endpoints"), "trusted_periodic_endpoints"
        ),
        approved_bulk_transfer_endpoints=_rules(
            payload.get("approved_bulk_transfer_endpoints"),
            "approved_bulk_transfer_endpoints",
        ),
        source=str(path),
    )
