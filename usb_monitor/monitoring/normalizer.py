"""Turn raw OS notifications into CONNECT/DISCONNECT USBEvent records.

One physical plug usually produces several WM_DEVICECHANGE messages
(USB interface, disk, volume). This module coalesces compatible signals
in a short quiet window so the rest of the app sees one logical event.

This layer does not query WMI, maintain inventory, or assign risk.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from usb_monitor.models.device import compose_device_id, normalize_drive_letter
from usb_monitor.models.enums import DeviceType, EventType
from usb_monitor.models.event import USBEvent
from usb_monitor.monitoring.event_source import (
    RawAction,
    RawDeviceEvent,
    device_path_to_instance_id,
    parse_instance_id_from_path,
    redact_device_path,
)
from usb_monitor.utils.logger import mask_identifier

Clock = Callable[[], float]

DEFAULT_QUIET_PERIOD = 0.5
DEFAULT_MAX_WAIT = 2.0
_USB_PATH_HINTS = ("USB#", "USBSTOR")


@dataclass
class _Burst:
    action: RawAction
    first_monotonic: float
    last_monotonic: float
    first_timestamp: datetime
    kinds: list[str] = field(default_factory=list)
    drive_letter: str | None = None
    vendor_id: str | None = None
    product_id: str | None = None
    device_path: str | None = None
    instance_id: str | None = None
    raw_count: int = 0
    source: str = "unknown"

    def merge(self, raw: RawDeviceEvent, now: float) -> None:
        self.last_monotonic = now
        self.raw_count += 1
        if raw.kind and raw.kind not in self.kinds:
            self.kinds.append(raw.kind)
        if raw.drive_letter and not self.drive_letter:
            self.drive_letter = raw.drive_letter
        if raw.vendor_id and not self.vendor_id:
            self.vendor_id = raw.vendor_id
            self.product_id = raw.product_id
        instance = parse_instance_id_from_path(raw.device_path)
        if instance and not self.instance_id:
            self.instance_id = instance
        if raw.device_path and _prefer_path(raw.device_path, self.device_path):
            self.device_path = raw.device_path
        if raw.source and self.source == "unknown":
            self.source = raw.source

    def is_compatible(self, raw: RawDeviceEvent) -> bool:
        if self.action != raw.action:
            return False
        raw_letter = normalize_drive_letter(raw.drive_letter)
        if self.drive_letter and raw_letter and self.drive_letter != raw_letter:
            return False
        if (
            self.vendor_id
            and raw.vendor_id
            and (self.vendor_id != raw.vendor_id or self.product_id != raw.product_id)
        ):
            return False
        return True

    def should_emit(self) -> bool:
        """Drop internal-disk noise: require a USB interface or a volume letter."""
        kinds = set(self.kinds)
        if "usb" in kinds:
            return True
        if "volume" in kinds and self.drive_letter:
            return True
        return False


class EventNormalizer:
    """Coalesce raw device-change bursts into USBEvent CONNECT/DISCONNECT records."""

    def __init__(
        self,
        *,
        quiet_period: float = DEFAULT_QUIET_PERIOD,
        max_wait: float = DEFAULT_MAX_WAIT,
        clock: Clock | None = None,
    ) -> None:
        if quiet_period < 0 or max_wait < 0:
            raise ValueError("quiet_period and max_wait must be >= 0")
        self._quiet_period = quiet_period
        self._max_wait = max_wait
        self._clock = clock or time.monotonic
        self._open: list[_Burst] = []

    def ingest(self, raw: RawDeviceEvent) -> list[USBEvent]:
        """Add one raw notification. Return logical events whose window closed."""
        now = self._clock()
        completed = self.flush_ready(now=now)
        burst = self._find_compatible(raw)
        if burst is None:
            burst = _Burst(
                action=raw.action,
                first_monotonic=now,
                last_monotonic=now,
                first_timestamp=raw.timestamp,
                source=raw.source,
            )
            self._open.append(burst)
        burst.merge(raw, now)
        return completed

    def flush_ready(self, now: float | None = None) -> list[USBEvent]:
        """Emit bursts that have been quiet long enough or exceeded max wait."""
        current = self._clock() if now is None else now
        ready: list[_Burst] = []
        pending: list[_Burst] = []
        for burst in self._open:
            quiet = current - burst.last_monotonic
            waited = current - burst.first_monotonic
            if quiet >= self._quiet_period or waited >= self._max_wait:
                ready.append(burst)
            else:
                pending.append(burst)
        self._open = pending
        events: list[USBEvent] = []
        for burst in ready:
            if burst.should_emit():
                events.append(burst_to_event(burst))
        return events

    def flush_all(self) -> list[USBEvent]:
        """Emit every remaining eligible burst (used on shutdown)."""
        remaining = self._open
        self._open = []
        return [burst_to_event(burst) for burst in remaining if burst.should_emit()]

    def _find_compatible(self, raw: RawDeviceEvent) -> _Burst | None:
        for burst in self._open:
            if burst.is_compatible(raw):
                return burst
        return None


def burst_to_event(burst: _Burst) -> USBEvent:
    """Map a completed burst onto the shared USBEvent model."""
    event_type = (
        EventType.CONNECT if burst.action is RawAction.CONNECT else EventType.DISCONNECT
    )
    device_id = compose_device_id(
        vendor_id=burst.vendor_id,
        product_id=burst.product_id,
        serial_number=burst.instance_id,
        pnp_device_id=burst.device_path,
    )
    if device_id is None and burst.drive_letter:
        device_id = f"volume:{burst.drive_letter}"
    pnp_device_id = device_path_to_instance_id(burst.device_path)
    return USBEvent(
        event_type=event_type,
        timestamp=burst.first_timestamp,
        device_id=device_id,
        vendor_id=burst.vendor_id,
        product_id=burst.product_id,
        serial_number=burst.instance_id,
        drive_letter=burst.drive_letter,
        device_type=_device_type_for(burst),
        pnp_device_id=pnp_device_id,
        source=burst.source,
        details={
            "coalesced": burst.raw_count > 1,
            "raw_count": burst.raw_count,
            "kinds": list(burst.kinds),
            "device_path": redact_device_path(burst.device_path),
            "serial": mask_identifier(burst.instance_id),
        },
    )


def format_live_event(event: USBEvent) -> str:
    """Human-readable CONNECT/DISCONNECT/inventory block for live monitor output."""
    titles = {
        EventType.CONNECT: "USB CONNECTED",
        EventType.DISCONNECT: "USB DISCONNECTED",
        EventType.FIRST_SEEN: "NEW USB DEVICE DETECTED",
        EventType.KNOWN_DEVICE: "KNOWN USB DEVICE",
        EventType.SUSPICIOUS_DEVICE: "SUSPICIOUS CHARACTERISTICS",
        EventType.ANALYSIS: "ANALYSIS",
    }
    verb = titles.get(event.event_type, event.event_type.value)
    serial = mask_identifier(event.serial_number) if event.serial_number else "Unknown"
    kinds = event.details.get("kinds") if isinstance(event.details, dict) else None
    signals = ", ".join(kinds) if isinstance(kinds, list) and kinds else "unknown"
    removable = _format_optional_bool(event.removable)
    inventory = event.details.get("inventory") if isinstance(event.details, dict) else None
    status_lines = _format_inventory_status(event, inventory if isinstance(inventory, dict) else None)
    lines = [
        f"[{event.display_timestamp}] {verb}",
        "",
        "Device:",
        f"  Manufacturer: {event.manufacturer or 'Unknown'}",
        f"  Product: {event.device_name or 'Unknown'}",
        f"  Identity: {event.safe_device_id}",
        f"  VID: {event.vendor_id or 'Unknown'}",
        f"  PID: {event.product_id or 'Unknown'}",
        f"  Serial: {serial}",
        f"  Drive: {event.drive_letter or 'Unknown'}",
        f"  Removable: {removable}",
        f"  Filesystem: {event.filesystem or 'Unknown'}",
        f"  Capacity: {_format_capacity(event.capacity)}",
        f"  Type: {event.device_type.value}",
        f"  Signals: {signals}",
        "",
        "Status:",
        *status_lines,
    ]
    if event.event_type is EventType.FIRST_SEEN:
        lines.extend(
            [
                "",
                "Note:",
                "  Verify that this device belongs to an authorized user.",
                "  Trusted does not mean the device is safe.",
            ]
        )
    if event.event_type is EventType.SUSPICIOUS_DEVICE:
        lines.extend(
            [
                "",
                "Note:",
                "  HIGH/CRITICAL is a heuristic from observed characteristics.",
                "  This is not a malware confirmation.",
            ]
        )
    alert = event.details.get("alert") if isinstance(event.details, dict) else None
    if isinstance(alert, dict) and alert.get("title"):
        lines.extend(
            [
                "",
                "Alert:",
                f"  [{alert.get('severity')}] {alert.get('title')}",
                "  Heuristic finding; not a malware confirmation.",
            ]
        )
    suppressed = event.details.get("alert_suppressed") if isinstance(event.details, dict) else None
    if isinstance(suppressed, dict):
        lines.extend(
            [
                "",
                "Alert:",
                "  Suppressed (cooldown; same warning already emitted).",
            ]
        )
    lines.extend(["", "--------------------------------"])
    return "\n".join(lines)


def _format_inventory_status(event: USBEvent, inventory: dict | None) -> list[str]:
    if event.event_type is EventType.FIRST_SEEN:
        baseline = "First seen"
    elif event.event_type is EventType.KNOWN_DEVICE:
        baseline = "Known device"
    elif inventory and inventory.get("is_first_seen"):
        baseline = "First seen"
    elif inventory:
        baseline = "Known device"
    else:
        baseline = "Not in inventory"
    trusted = "Unknown"
    connections = "Unknown"
    if inventory is not None:
        trusted = "Yes" if inventory.get("trusted") else "No"
        count = inventory.get("connection_count")
        connections = str(count) if count is not None else "Unknown"
    lines = [
        f"  {baseline}",
        f"  Trusted: {trusted}",
        f"  Connections: {connections}",
    ]
    if event.risk_level is not None and event.risk_score is not None:
        lines.append(
            f"  Risk: {event.risk_level.value} ({event.risk_score}) "
            "[heuristic, not a malware verdict]"
        )
        risk = event.details.get("risk") if isinstance(event.details, dict) else None
        if isinstance(risk, dict):
            matches = risk.get("matches") or []
            parts = [
                f"{item.get('rule_id')} {item.get('score'):+d}"
                for item in matches
                if isinstance(item, dict)
            ]
            if parts:
                lines.append("  Rules: " + ", ".join(parts))
    anomaly = event.details.get("anomaly") if isinstance(event.details, dict) else None
    if isinstance(anomaly, dict):
        connects = int(anomaly.get("connects_in_window") or 0)
        events = int(anomaly.get("events_in_window") or 0)
        new_devices = int(anomaly.get("new_devices_in_window") or 0)
        if connects >= 2 or events >= 3 or new_devices >= 2:
            lines.append(
                f"  Window: {connects} connects / {events} events / "
                f"{new_devices} new identities"
            )
    return lines


def _format_optional_bool(value: bool | None) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"


def _format_capacity(capacity: int | None) -> str:
    if capacity is None:
        return "Unknown"
    gib = 1024 ** 3
    mib = 1024 ** 2
    if capacity >= gib:
        return f"{capacity / gib:.1f} GiB"
    if capacity >= mib:
        return f"{capacity / mib:.1f} MiB"
    return f"{capacity} bytes"


def _prefer_path(candidate: str, current: str | None) -> bool:
    if current is None:
        return True
    upper = candidate.upper()
    current_upper = current.upper()
    candidate_usb = any(hint in upper for hint in _USB_PATH_HINTS)
    current_usb = any(hint in current_upper for hint in _USB_PATH_HINTS)
    if candidate_usb and not current_usb:
        return True
    return False


def _device_type_for(burst: _Burst) -> DeviceType:
    kinds = set(burst.kinds)
    if "usb" in kinds and ("volume" in kinds or "disk" in kinds):
        return DeviceType.USB_STORAGE
    if "usb" in kinds:
        return DeviceType.USB_DEVICE
    if "volume" in kinds:
        return DeviceType.REMOVABLE_MEDIA
    return DeviceType.UNKNOWN
