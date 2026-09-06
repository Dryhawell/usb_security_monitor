"""USB activity event recorded by the monitor."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from usb_monitor.models.device import normalize_drive_letter, normalize_hardware_id, normalize_optional_text
from usb_monitor.models.enums import DeviceType, EventType, RiskLevel, parse_enum
from usb_monitor.utils.time import format_display, from_iso8601, to_iso8601, utc_now


@dataclass
class USBEvent:
    """A single observed or derived USB-related event.

    ``timestamp`` is stored as timezone-aware UTC. Console and reports
    should use ``display_timestamp`` rather than printing the raw datetime.
    """

    event_type: EventType
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=utc_now)
    device_id: str | None = None
    device_name: str | None = None
    vendor_id: str | None = None
    product_id: str | None = None
    serial_number: str | None = None
    drive_letter: str | None = None
    device_type: DeviceType = DeviceType.UNKNOWN
    source: str = "unknown"
    risk_score: int | None = None
    risk_level: RiskLevel | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        event_id = normalize_optional_text(self.event_id)
        if event_id is None:
            raise ValueError("event_id is required and cannot be empty")
        self.event_id = event_id
        if not isinstance(self.event_type, EventType):
            self.event_type = EventType(str(self.event_type))
        self.device_id = normalize_optional_text(self.device_id)
        self.device_name = normalize_optional_text(self.device_name)
        self.vendor_id = normalize_hardware_id(self.vendor_id)
        self.product_id = normalize_hardware_id(self.product_id)
        self.serial_number = normalize_optional_text(self.serial_number)
        self.drive_letter = normalize_drive_letter(self.drive_letter)
        if not isinstance(self.device_type, DeviceType):
            self.device_type = DeviceType(str(self.device_type))
        source = normalize_optional_text(self.source)
        self.source = source or "unknown"
        if isinstance(self.timestamp, str):
            self.timestamp = from_iso8601(self.timestamp)

    @property
    def display_timestamp(self) -> str:
        """Human-readable UTC timestamp for CLI and reports."""
        return format_display(self.timestamp)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "event_id": self.event_id,
            "timestamp": to_iso8601(self.timestamp),
            "event_type": self.event_type.value,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial_number": self.serial_number,
            "drive_letter": self.drive_letter,
            "device_type": self.device_type.value,
            "source": self.source,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value if self.risk_level else None,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> USBEvent:
        """Rebuild a USBEvent from ``to_dict`` output or stored JSON."""
        event_type = parse_enum(EventType, data.get("event_type"))
        if event_type is None:
            raise ValueError("event_type is required")
        return cls(
            event_id=str(data.get("event_id") or uuid.uuid4()),
            timestamp=from_iso8601(data["timestamp"]) if data.get("timestamp") else utc_now(),
            event_type=event_type,
            device_id=data.get("device_id"),
            device_name=data.get("device_name"),
            vendor_id=data.get("vendor_id"),
            product_id=data.get("product_id"),
            serial_number=data.get("serial_number"),
            drive_letter=data.get("drive_letter"),
            device_type=parse_enum(
                DeviceType, data.get("device_type"), DeviceType.UNKNOWN
            ) or DeviceType.UNKNOWN,
            source=str(data.get("source") or "unknown"),
            risk_score=data.get("risk_score"),
            risk_level=parse_enum(RiskLevel, data.get("risk_level")),
            details=dict(data.get("details") or {}),
        )

    def __str__(self) -> str:
        name = self.device_name or self.device_id or "Unknown"
        return f"[{self.display_timestamp}] {self.event_type.value} {name}"
