"""Shared enumerations for USB Security Monitor models.

Risk levels are an internal heuristic scale, not a standardized
cybersecurity score. Elevated values must be justified by triggered
rules; the mapping here only converts a 0-100 score to a band.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, TypeVar

EnumT = TypeVar("EnumT", bound=Enum)


class EventType(str, Enum):
    """Security-relevant USB activity kinds recorded by the monitor."""

    CONNECT = "CONNECT"
    DISCONNECT = "DISCONNECT"
    FIRST_SEEN = "FIRST_SEEN"
    KNOWN_DEVICE = "KNOWN_DEVICE"
    SUSPICIOUS_DEVICE = "SUSPICIOUS_DEVICE"
    ANALYSIS = "ANALYSIS"


class Severity(str, Enum):
    """Alert severity. CRITICAL must never be assigned without a clear reason."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskLevel(str, Enum):
    """Heuristic risk band derived from an explainable 0-100 score."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DeviceType(str, Enum):
    """Logical classification of an observed device.

    These are not interchangeable:

    * ``USB_DEVICE`` — a USB-attached device in general (storage, HID, hub, ...)
    * ``USB_STORAGE`` — a USB mass-storage device (thumb drive, USB disk)
    * ``REMOVABLE_MEDIA`` — media the OS treats as removable (may not be USB)
    * ``UNKNOWN`` — the OS did not expose enough information to classify
    """

    USB_DEVICE = "USB_DEVICE"
    USB_STORAGE = "USB_STORAGE"
    REMOVABLE_MEDIA = "REMOVABLE_MEDIA"
    UNKNOWN = "UNKNOWN"


class InterfaceType(str, Enum):
    """How the device is attached, when the OS exposes that information."""

    USB = "USB"
    UNKNOWN = "UNKNOWN"


def parse_enum(enum_cls: type[EnumT], value: Any, default: EnumT | None = None) -> EnumT | None:
    """Convert a stored string (or enum) into an enum member.

    Empty or missing values return ``default``. Invalid values raise ValueError.
    """
    if value is None or value == "":
        return default
    if isinstance(value, enum_cls):
        return value
    return enum_cls(str(value))


def clamp_risk_score(score: int) -> int:
    """Keep a risk score inside the inclusive 0-100 range."""
    return max(0, min(100, score))


def risk_level_from_score(score: int) -> RiskLevel:
    """Map a clamped score onto the documented heuristic bands.

    * 0-20: LOW
    * 21-50: MEDIUM
    * 51-75: HIGH
    * 76-100: CRITICAL
    """
    clamped = clamp_risk_score(score)
    if clamped <= 20:
        return RiskLevel.LOW
    if clamped <= 50:
        return RiskLevel.MEDIUM
    if clamped <= 75:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL
