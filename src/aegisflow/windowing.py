from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Hashable
from dataclasses import dataclass
from typing import Generic, TypeVar


T = TypeVar("T")
K = TypeVar("K", bound=Hashable)


@dataclass(frozen=True, slots=True)
class TimedValue(Generic[T]):
    timestamp: float
    value: T


class KeyedSlidingWindow(Generic[K, T]):
    """In-memory event-time windows with bounded out-of-order support."""

    def __init__(self, window_seconds: float) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self._windows: dict[K, deque[TimedValue[T]]] = defaultdict(deque)
        self._latest_timestamp: dict[K, float] = {}

    def add(self, key: K, timestamp: float, value: T) -> tuple[TimedValue[T], ...]:
        latest = self._latest_timestamp.get(key)
        effective_latest = max(timestamp, latest) if latest is not None else timestamp
        self._latest_timestamp[key] = effective_latest
        window = self._windows[key]
        timed_value = TimedValue(timestamp, value)
        if latest is None or timestamp >= latest:
            window.append(timed_value)
        else:
            insert_at = len(window)
            while insert_at > 0 and window[insert_at - 1].timestamp > timestamp:
                insert_at -= 1
            window.insert(insert_at, timed_value)
        cutoff = effective_latest - self.window_seconds
        while window and window[0].timestamp < cutoff:
            window.popleft()
        return tuple(window)

    def values(self, key: K) -> tuple[TimedValue[T], ...]:
        return tuple(self._windows.get(key, ()))

    def items(self) -> tuple[tuple[K, tuple[TimedValue[T], ...]], ...]:
        return tuple((key, tuple(values)) for key, values in self._windows.items())

    def clear(self) -> None:
        self._windows.clear()
        self._latest_timestamp.clear()
