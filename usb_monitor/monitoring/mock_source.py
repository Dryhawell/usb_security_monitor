"""In-process EventSource for tests and hardware-free replay.

This is not a Windows watcher. It yields queued RawDeviceEvent records
so the rest of the pipeline can be exercised without USB devices.
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Iterable

from usb_monitor.monitoring.event_source import EventSource, RawDeviceEvent


class MockEventSource(EventSource):
    """Queue of raw device events. ``poll`` never talks to the operating system."""

    def __init__(self, events: Iterable[RawDeviceEvent] | None = None) -> None:
        self._queue: deque[RawDeviceEvent] = deque(events or ())
        self._running = False
        self._lock = threading.Lock()
        self._not_empty = threading.Event()
        if self._queue:
            self._not_empty.set()

    @property
    def mechanism(self) -> str:
        return "mock"

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def queued(self) -> int:
        with self._lock:
            return len(self._queue)

    def push(self, event: RawDeviceEvent) -> None:
        """Append one raw event for a later ``poll`` or ``take_all``."""
        with self._lock:
            self._queue.append(event)
            self._not_empty.set()

    def extend(self, events: Iterable[RawDeviceEvent]) -> None:
        with self._lock:
            self._queue.extend(events)
            if self._queue:
                self._not_empty.set()

    def take_all(self) -> list[RawDeviceEvent]:
        """Remove and return every queued event. Used by replay helpers."""
        with self._lock:
            items = list(self._queue)
            self._queue.clear()
            self._not_empty.clear()
            return items

    def start(self) -> None:
        self._running = True

    def stop(self, timeout: float = 5.0) -> None:
        self._running = False
        self._not_empty.set()

    def poll(self, timeout: float | None = None) -> RawDeviceEvent | None:
        if not self._running:
            return None
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be >= 0")
        if timeout == 0:
            return self._pop()
        if self._wait_for_item(timeout):
            return self._pop()
        return None

    def _pop(self) -> RawDeviceEvent | None:
        with self._lock:
            if not self._queue:
                self._not_empty.clear()
                return None
            event = self._queue.popleft()
            if not self._queue:
                self._not_empty.clear()
            return event

    def _wait_for_item(self, timeout: float | None) -> bool:
        if self._queue:
            return True
        if timeout is None:
            self._not_empty.wait()
            return bool(self._queue) and self._running
        return self._not_empty.wait(timeout)
