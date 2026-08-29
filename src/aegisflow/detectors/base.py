from __future__ import annotations

from abc import ABC, abstractmethod

from aegisflow.models import Alert, NetworkEvent


class Detector(ABC):
    detector_id: str
    detector_version: str

    @abstractmethod
    def process(self, event: NetworkEvent) -> list[Alert]:
        """Consume one event and return zero or more new alerts."""

