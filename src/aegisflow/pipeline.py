from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence

from aegisflow.detectors.base import Detector
from aegisflow.models import Alert, DNSEvent, NetworkEvent


def run_pipeline(events: Iterable[NetworkEvent], detectors: Sequence[Detector]) -> Iterator[Alert]:
    for event in events:
        for detector in detectors:
            yield from detector.process(event)


def run_dns_pipeline(events: Iterable[DNSEvent], detectors: Sequence) -> Iterator[Alert]:
    for event in events:
        for detector in detectors:
            yield from detector.process(event)
