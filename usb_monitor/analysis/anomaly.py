"""In-session sliding windows for reconnect and first-seen bursts.

This is not persistence and not a malware detector. Counts reset when
the process exits. Windows are measured from event timestamps so demos
can replay a timeline without waiting.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from usb_monitor.models.enums import EventType
from usb_monitor.models.event import USBEvent
from usb_monitor.utils.time import ensure_utc

RAPID_RECONNECT_WINDOW_SECONDS = 15
RAPID_RECONNECT_MIN_CONNECTS = 3
REPEATED_EVENTS_WINDOW_SECONDS = 20
REPEATED_EVENTS_MIN_EVENTS = 4
MULTIPLE_NEW_WINDOW_SECONDS = 60
MULTIPLE_NEW_MIN_DEVICES = 3


@dataclass(frozen=True)
class AnomalySnapshot:
    """Window counts after recording one event."""

    connect_count: int
    event_count: int
    new_device_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "connects_in_window": self.connect_count,
            "connect_window_seconds": RAPID_RECONNECT_WINDOW_SECONDS,
            "events_in_window": self.event_count,
            "event_window_seconds": REPEATED_EVENTS_WINDOW_SECONDS,
            "new_devices_in_window": self.new_device_count,
            "new_device_window_seconds": MULTIPLE_NEW_WINDOW_SECONDS,
        }


class AnomalyTracker:
    """Remember recent CONNECT/DISCONNECT timestamps per identity."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._connects: dict[str, deque[datetime]] = defaultdict(deque)
        self._events: dict[str, deque[datetime]] = defaultdict(deque)
        self._first_seen: deque[tuple[datetime, str]] = deque()

    def record(self, event: USBEvent, *, is_first_seen: bool = False) -> AnomalySnapshot:
        """Record a logical USB event and return the updated window snapshot."""
        identity = event.device_id
        timestamp = ensure_utc(event.timestamp)
        with self._lock:
            connect_count = 0
            event_count = 0
            if identity:
                if event.event_type is EventType.CONNECT:
                    self._connects[identity].append(timestamp)
                if event.event_type in (EventType.CONNECT, EventType.DISCONNECT):
                    self._events[identity].append(timestamp)
                _prune_times(
                    self._connects[identity], timestamp, RAPID_RECONNECT_WINDOW_SECONDS
                )
                _prune_times(
                    self._events[identity], timestamp, REPEATED_EVENTS_WINDOW_SECONDS
                )
                connect_count = len(self._connects[identity])
                event_count = len(self._events[identity])
            if is_first_seen and identity and event.event_type is EventType.CONNECT:
                self._first_seen.append((timestamp, identity))
            _prune_first_seen(self._first_seen, timestamp, MULTIPLE_NEW_WINDOW_SECONDS)
            new_device_count = len({device_id for _ts, device_id in self._first_seen})
        return AnomalySnapshot(
            connect_count=connect_count,
            event_count=event_count,
            new_device_count=new_device_count,
        )


def _prune_times(items: deque[datetime], now: datetime, window_seconds: int) -> None:
    cutoff = now - timedelta(seconds=window_seconds)
    while items and items[0] < cutoff:
        items.popleft()


def _prune_first_seen(
    items: deque[tuple[datetime, str]], now: datetime, window_seconds: int
) -> None:
    cutoff = now - timedelta(seconds=window_seconds)
    while items and items[0][0] < cutoff:
        items.popleft()
