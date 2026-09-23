"""Local JSON persistence for events, alerts, and shared atomic writes."""

from usb_monitor.storage.alert_store import (
    DEFAULT_ALERTS_PATH,
    DEFAULT_MAX_ALERTS,
    AlertStore,
)
from usb_monitor.storage.atomic import (
    read_json_file,
    write_json_atomic,
    write_text_atomic,
)
from usb_monitor.storage.bounded import coerce_dropped_total, keep_newest
from usb_monitor.storage.event_store import (
    DEFAULT_EVENTS_PATH,
    DEFAULT_MAX_EVENTS,
    EventStore,
)

__all__ = [
    "DEFAULT_ALERTS_PATH",
    "DEFAULT_EVENTS_PATH",
    "DEFAULT_MAX_ALERTS",
    "DEFAULT_MAX_EVENTS",
    "AlertStore",
    "EventStore",
    "keep_newest",
    "coerce_dropped_total",
    "read_json_file",
    "write_json_atomic",
    "write_text_atomic",
]
