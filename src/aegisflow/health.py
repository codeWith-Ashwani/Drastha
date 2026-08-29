from __future__ import annotations

from dataclasses import asdict, dataclass
from time import perf_counter
from typing import Any

from aegisflow.models import Alert, NetworkEvent


@dataclass(slots=True)
class ReplayHealth:
    events_processed: int = 0
    alerts_emitted: int = 0
    first_event_timestamp: float | None = None
    last_event_timestamp: float | None = None
    out_of_order_events: int = 0
    capture_loss_records: int = 0
    wall_seconds: float = 0.0
    _started_at: float = 0.0

    def start(self) -> None:
        self._started_at = perf_counter()

    def record_event(self, event: NetworkEvent) -> None:
        if self.first_event_timestamp is None:
            self.first_event_timestamp = event.timestamp
        if self.last_event_timestamp is not None and event.timestamp < self.last_event_timestamp:
            self.out_of_order_events += 1
        self.last_event_timestamp = max(event.timestamp, self.last_event_timestamp or event.timestamp)
        self.events_processed += 1

    def record_alert(self, alert: Alert) -> None:
        self.alerts_emitted += 1

    def finish(self) -> None:
        self.wall_seconds = max(perf_counter() - self._started_at, 0.0)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("_started_at", None)
        span = 0.0
        if self.first_event_timestamp is not None and self.last_event_timestamp is not None:
            span = max(self.last_event_timestamp - self.first_event_timestamp, 0.0)
        data["event_time_span_seconds"] = round(span, 6)
        data["processing_events_per_second"] = round(
            self.events_processed / self.wall_seconds, 3
        ) if self.wall_seconds else None
        data["capture_loss_visibility"] = (
            "available" if self.capture_loss_records else "not_provided_by_conn_log"
        )
        return data

