"""Device inventory record.

A Device is local observation metadata. Missing OS-exposed fields stay
``None``; the model never invents manufacturer names, serials, or IDs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from usb_monitor.models.enums import (
    DeviceType,
    InterfaceType,
    RiskLevel,
    clamp_risk_score,
    parse_enum,
    risk_level_from_score,
)
from usb_monitor.utils.logger import mask_identifier
from usb_monitor.utils.time import format_display, from_iso8601, to_iso8601, utc_now

_HARDWARE_ID_RE = re.compile(
    r"^(?:0x|VID_|PID_)?([0-9A-Fa-f]{1,4})$",
    re.IGNORECASE,
)


def normalize_optional_text(value: str | None) -> str | None:
    """Strip whitespace and convert empty strings to ``None``."""
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def normalize_hardware_id(value: str | None) -> str | None:
    """Normalize a USB VID/PID to 4-digit uppercase hex, or ``None``.

    Accepted examples: ``781``, ``0781``, ``0x0781``, ``VID_0781``.
    Invalid or empty values become ``None`` rather than a guessed ID.
    """
    cleaned = normalize_optional_text(value)
    if cleaned is None:
        return None
    match = _HARDWARE_ID_RE.fullmatch(cleaned)
    if match is None:
        return None
    return match.group(1).upper().zfill(4)


def normalize_drive_letter(value: str | None) -> str | None:
    """Normalize a Windows drive letter to ``E:`` form, or ``None``."""
    cleaned = normalize_optional_text(value)
    if cleaned is None:
        return None
    letter = cleaned.rstrip("\\/").upper()
    if len(letter) == 1 and letter.isalpha():
        return f"{letter}:"
    if len(letter) == 2 and letter[0].isalpha() and letter[1] == ":":
        return letter
    return None


def compose_device_id(
    *,
    vendor_id: str | None = None,
    product_id: str | None = None,
    serial_number: str | None = None,
    pnp_device_id: str | None = None,
) -> str | None:
    """Build a stable local identity from known parts only.

    Prefers ``VID:PID:SERIAL`` when a serial exists, then ``VID:PID``,
    then a PNP device ID. Returns ``None`` if nothing identifying is known.
    """
    vid = normalize_hardware_id(vendor_id)
    pid = normalize_hardware_id(product_id)
    serial = normalize_optional_text(serial_number)
    pnp = normalize_optional_text(pnp_device_id)

    if vid and pid and serial:
        return f"{vid}:{pid}:{serial}"
    if vid and pid:
        return f"{vid}:{pid}"
    if pnp:
        return pnp
    return None


@dataclass
class Device:
    """Observed USB/removable device as known to this endpoint.

    ``device_id`` is a local identity string, not a globally unique
    hardware guarantee. Two different physical devices can share VID/PID
    when a serial number is missing.
    """

    device_id: str
    vendor_id: str | None = None
    product_id: str | None = None
    serial_number: str | None = None
    manufacturer: str | None = None
    product_name: str | None = None
    device_type: DeviceType = DeviceType.UNKNOWN
    interface_type: InterfaceType = InterfaceType.UNKNOWN
    pnp_device_id: str | None = None
    drive_letter: str | None = None
    filesystem: str | None = None
    capacity: int | None = None
    removable: bool | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    connection_count: int = 0
    trusted: bool = False
    risk_score: int | None = None
    risk_level: RiskLevel | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        device_id = normalize_optional_text(self.device_id)
        if device_id is None:
            raise ValueError("device_id is required and cannot be empty")
        self.device_id = device_id
        self.vendor_id = normalize_hardware_id(self.vendor_id)
        self.product_id = normalize_hardware_id(self.product_id)
        self.serial_number = normalize_optional_text(self.serial_number)
        self.manufacturer = normalize_optional_text(self.manufacturer)
        self.product_name = normalize_optional_text(self.product_name)
        self.pnp_device_id = normalize_optional_text(self.pnp_device_id)
        self.drive_letter = normalize_drive_letter(self.drive_letter)
        self.filesystem = normalize_optional_text(self.filesystem)
        if self.capacity is not None and self.capacity < 0:
            raise ValueError("capacity cannot be negative")
        if self.connection_count < 0:
            raise ValueError("connection_count cannot be negative")
        if self.risk_score is not None:
            self.risk_score = clamp_risk_score(self.risk_score)
            if self.risk_level is None:
                self.risk_level = risk_level_from_score(self.risk_score)

    @property
    def display_name(self) -> str:
        """Human-readable label; falls back to ``Unknown`` for missing names."""
        if self.manufacturer and self.product_name:
            return f"{self.manufacturer} {self.product_name}"
        if self.product_name:
            return self.product_name
        if self.manufacturer:
            return self.manufacturer
        return "Unknown"

    @property
    def masked_serial(self) -> str:
        """Serial suitable for logs and console output."""
        return mask_identifier(self.serial_number)

    @property
    def safe_device_id(self) -> str:
        """Identity string with a masked serial, safe for logs and console."""
        if self.serial_number and self.serial_number in self.device_id:
            return self.device_id.replace(
                self.serial_number, mask_identifier(self.serial_number), 1
            )
        return self.device_id

    def mark_seen(self, when: datetime | None = None) -> None:
        """Update first/last seen and increment the connection count."""
        timestamp = when or utc_now()
        if self.first_seen is None:
            self.first_seen = timestamp
        self.last_seen = timestamp
        self.connection_count += 1

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "device_id": self.device_id,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial_number": self.serial_number,
            "manufacturer": self.manufacturer,
            "product_name": self.product_name,
            "device_type": self.device_type.value,
            "interface_type": self.interface_type.value,
            "pnp_device_id": self.pnp_device_id,
            "drive_letter": self.drive_letter,
            "filesystem": self.filesystem,
            "capacity": self.capacity,
            "removable": self.removable,
            "first_seen": to_iso8601(self.first_seen) if self.first_seen else None,
            "last_seen": to_iso8601(self.last_seen) if self.last_seen else None,
            "connection_count": self.connection_count,
            "trusted": self.trusted,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value if self.risk_level else None,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Device:
        """Rebuild a Device from ``to_dict`` output or stored JSON."""
        first_seen = data.get("first_seen")
        last_seen = data.get("last_seen")
        return cls(
            device_id=str(data["device_id"]),
            vendor_id=data.get("vendor_id"),
            product_id=data.get("product_id"),
            serial_number=data.get("serial_number"),
            manufacturer=data.get("manufacturer"),
            product_name=data.get("product_name"),
            device_type=parse_enum(
                DeviceType, data.get("device_type"), DeviceType.UNKNOWN
            ) or DeviceType.UNKNOWN,
            interface_type=parse_enum(
                InterfaceType, data.get("interface_type"), InterfaceType.UNKNOWN
            ) or InterfaceType.UNKNOWN,
            pnp_device_id=data.get("pnp_device_id"),
            drive_letter=data.get("drive_letter"),
            filesystem=data.get("filesystem"),
            capacity=data.get("capacity"),
            removable=data.get("removable"),
            first_seen=from_iso8601(first_seen) if first_seen else None,
            last_seen=from_iso8601(last_seen) if last_seen else None,
            connection_count=int(data.get("connection_count", 0)),
            trusted=bool(data.get("trusted", False)),
            risk_score=data.get("risk_score"),
            risk_level=parse_enum(RiskLevel, data.get("risk_level")),
            extra=dict(data.get("extra") or {}),
        )

    def __str__(self) -> str:
        first = format_display(self.first_seen) if self.first_seen else "n/a"
        return (
            f"Device(id={self.device_id}, name={self.display_name}, "
            f"vid={self.vendor_id or 'Unknown'}, pid={self.product_id or 'Unknown'}, "
            f"serial={self.masked_serial}, first_seen={first})"
        )
