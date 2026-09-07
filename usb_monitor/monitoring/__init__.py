"""USB/removable-device monitoring layer.

EventSource detects OS notifications. USBMonitor + EventNormalizer
turn those into CONNECT/DISCONNECT USBEvent records. MetadataCollector
fills manufacturer, filesystem, and related OS-exposed fields.
"""

from usb_monitor.inventory import DeviceInventory
from usb_monitor.monitoring.event_source import (
    EventSource,
    EventSourceUnavailableError,
    RawAction,
    RawDeviceEvent,
    device_path_to_instance_id,
    drive_letters_from_unit_mask,
    parse_instance_id_from_path,
    parse_vid_pid_from_path,
    redact_device_path,
    redact_pnp_device_id,
)
from usb_monitor.monitoring.metadata import (
    DeviceMetadata,
    MetadataCollector,
    NullMetadataCollector,
    apply_metadata,
)
from usb_monitor.monitoring.monitor import USBMonitor
from usb_monitor.monitoring.normalizer import EventNormalizer, format_live_event
from usb_monitor.monitoring.windows_metadata import (
    WindowsMetadataCollector,
    list_removable_drive_letters,
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


def create_metadata_collector() -> MetadataCollector:
    """Return a Windows collector, or a no-op collector on other platforms."""
    if is_windows():
        return WindowsMetadataCollector()
    return NullMetadataCollector()


def create_monitor() -> USBMonitor:
    """Build a USBMonitor over the native event source, metadata, and inventory."""
    return USBMonitor(
        create_event_source(),
        collector=create_metadata_collector(),
        inventory=DeviceInventory.load(),
    )


__all__ = [
    "DeviceMetadata",
    "EventNormalizer",
    "EventSource",
    "EventSourceUnavailableError",
    "MetadataCollector",
    "NullMetadataCollector",
    "RawAction",
    "RawDeviceEvent",
    "USBMonitor",
    "WindowsEventSource",
    "WindowsMetadataCollector",
    "apply_metadata",
    "create_event_source",
    "create_metadata_collector",
    "create_monitor",
    "device_path_to_instance_id",
    "drive_letters_from_unit_mask",
    "format_live_event",
    "list_removable_drive_letters",
    "parse_instance_id_from_path",
    "parse_vid_pid_from_path",
    "redact_device_path",
    "redact_pnp_device_id",
]
