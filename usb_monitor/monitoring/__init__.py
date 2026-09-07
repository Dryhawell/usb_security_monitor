"""USB/removable-device monitoring layer.

EventSource detects OS notifications. USBMonitor + EventNormalizer
turn those into CONNECT/DISCONNECT USBEvent records.
"""

from usb_monitor.monitoring.event_source import (
    EventSource,
    EventSourceUnavailableError,
    RawAction,
    RawDeviceEvent,
    drive_letters_from_unit_mask,
    parse_instance_id_from_path,
    parse_vid_pid_from_path,
    redact_device_path,
)
from usb_monitor.monitoring.monitor import USBMonitor
from usb_monitor.monitoring.normalizer import EventNormalizer, format_live_event
from usb_monitor.monitoring.windows_monitor import WindowsEventSource
from usb_monitor.utils.platform import UnsupportedPlatformError, is_windows


def create_event_source() -> EventSource:
    """Return the native event source for this host.

    Raises:
        UnsupportedPlatformError: live monitoring is not implemented here.
    """
    if not is_windows():
        raise UnsupportedPlatformError(
            "Live USB event source is implemented for Windows only."
        )
    return WindowsEventSource()


def create_monitor() -> USBMonitor:
    """Build a USBMonitor over the native event source."""
    return USBMonitor(create_event_source())


__all__ = [
    "EventNormalizer",
    "EventSource",
    "EventSourceUnavailableError",
    "RawAction",
    "RawDeviceEvent",
    "USBMonitor",
    "WindowsEventSource",
    "create_event_source",
    "create_monitor",
    "drive_letters_from_unit_mask",
    "format_live_event",
    "parse_instance_id_from_path",
    "parse_vid_pid_from_path",
    "redact_device_path",
]
