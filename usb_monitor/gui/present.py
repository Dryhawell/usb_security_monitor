"""Local operator GUI helpers. Serials stay masked in the window."""

from __future__ import annotations

from usb_monitor.models.alert import Alert
from usb_monitor.models.device import Device
from usb_monitor.models.event import USBEvent
from usb_monitor.utils.time import format_display

DISCLAIMER = (
    "Heuristic scores are not a malware verdict. "
    "USB files are not opened or executed. Local only."
)
MAX_LIVE_ROWS = 200


def event_row(event: USBEvent) -> tuple[str, str, str, str]:
    risk = ""
    if event.risk_level is not None and event.risk_score is not None:
        risk = f"{event.risk_level.value} ({event.risk_score})"
    return (
        event.display_timestamp,
        event.event_type.value,
        event.safe_device_id,
        risk,
    )


def device_row(device: Device) -> tuple[str, str, str, str, str, str]:
    risk = ""
    if device.risk_level is not None and device.risk_score is not None:
        risk = f"{device.risk_level.value} ({device.risk_score})"
    return (
        device.safe_device_id,
        device.display_name,
        str(device.connection_count),
        "yes" if device.trusted else "no",
        risk,
        format_display(device.last_seen) if device.last_seen else "n/a",
    )


def alert_row(alert: Alert) -> tuple[str, str, str, str]:
    return (
        alert.display_timestamp,
        alert.severity.value,
        alert.title,
        alert.safe_device_id,
    )
