"""Append-only local event history (events.json).

Records stay on this machine. Stored documents may include serial
numbers, like inventory; console and logs still mask them.
"""

from __future__ import annotations

import threading
from pathlib import Path

from usb_monitor.models.event import USBEvent
from usb_monitor.storage.atomic import read_json_file, write_json_atomic
from usb_monitor.utils.logger import get_logger
from usb_monitor.utils.permissions import DEFAULT_DATA_DIR

DEFAULT_EVENTS_PATH = DEFAULT_DATA_DIR / "events" / "events.json"
_SCHEMA_VERSION = 1


class EventStore:
    """In-memory event list with optional JSON persistence."""

    def __init__(self, path: Path | None = DEFAULT_EVENTS_PATH) -> None:
        self._path = path
        self._events: list[USBEvent] = []
        self._lock = threading.Lock()
        self._log = get_logger("storage.events")

    @classmethod
    def load(cls, path: Path | None = DEFAULT_EVENTS_PATH) -> EventStore:
        store = cls(path=path)
        store.reload()
        return store

    def reload(self) -> None:
        if self._path is None:
            return
        raw = read_json_file(self._path)
        records = raw.get("events") if isinstance(raw, dict) else None
        if raw is None:
            return
        if not isinstance(records, list):
            self._log.warning("Events file is missing an events list; starting empty")
            return
        loaded: list[USBEvent] = []
        seen: set[str] = set()
        for item in records:
            if not isinstance(item, dict):
                continue
            try:
                event = USBEvent.from_dict(item)
            except (KeyError, TypeError, ValueError):
                self._log.warning("Skipping a malformed event record")
                continue
            if event.event_id in seen:
                continue
            seen.add(event.event_id)
            loaded.append(event)
        with self._lock:
            self._events = loaded
        self._log.info("Loaded %s event(s) from local store", len(loaded))

    def append(self, event: USBEvent) -> None:
        """Record one event and persist when a path is configured."""
        with self._lock:
            if any(item.event_id == event.event_id for item in self._events):
                return
            self._events.append(event)
        self.save()

    def list_events(self) -> list[USBEvent]:
        with self._lock:
            return list(self._events)

    def stats(self) -> dict[str, int]:
        events = self.list_events()
        return {"total": len(events)}

    def save(self) -> None:
        if self._path is None:
            return
        payload = {
            "version": _SCHEMA_VERSION,
            "events": [event.to_dict() for event in self.list_events()],
        }
        try:
            write_json_atomic(self._path, payload, prefix="events.")
        except OSError as exc:
            self._log.error("Could not save events: %s", exc)
