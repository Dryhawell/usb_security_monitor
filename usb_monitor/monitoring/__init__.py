"""USB/removable-device monitoring layer.

Phase 4 provides the event-source abstraction and the Windows
WM_DEVICECHANGE implementation. USBMonitor (normalization, inventory
hooks) arrives in Phase 5.
"""

from usb_monitor.monitoring.event_source import (
    EventSource,
    EventSourceUnavailableError,
    RawAction,
    RawDeviceEvent,
    drive_letters_from_unit_mask,
    parse_vid_pid_from_path,
    redact_device_path,
)
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


__all__ = [
    "EventSource",
    "EventSourceUnavailableError",
    "RawAction",
    "RawDeviceEvent",
    "WindowsEventSource",
    "create_event_source",
    "drive_letters_from_unit_mask",
    "parse_vid_pid_from_path",
    "redact_device_path",
]
