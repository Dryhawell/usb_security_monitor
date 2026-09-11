"""Local JSON persistence for events, alerts, and shared atomic writes."""

from usb_monitor.storage.alert_store import DEFAULT_ALERTS_PATH, AlertStore
from usb_monitor.storage.atomic import (
    read_json_file,
    write_json_atomic,
    write_text_atomic,
)
from usb_monitor.storage.event_store import DEFAULT_EVENTS_PATH, EventStore

__all__ = [
    "DEFAULT_ALERTS_PATH",
    "DEFAULT_EVENTS_PATH",
    "AlertStore",
    "EventStore",
    "read_json_file",
    "write_json_atomic",
    "write_text_atomic",
]
