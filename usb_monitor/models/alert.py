"""Security alert generated from analysis findings."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from usb_monitor.models.device import normalize_optional_text
from usb_monitor.models.enums import Severity, parse_enum
from usb_monitor.utils.time import format_display, from_iso8601, to_iso8601, utc_now


@dataclass
class Alert:
    """An explainable alert tied to a device and optionally an event.

    ``reasons`` must describe why the severity was chosen. CRITICAL is a
    valid stored value, but later phases must not assign it without a
    documented rule firing.
    """

    severity: Severity
    title: str
    description: str
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=utc_now)
    device_id: str | None = None
    event_id: str | None = None
    reasons: list[str] = field(default_factory=list)
    recommendation: str | None = None

    def __post_init__(self) -> None:
        alert_id = normalize_optional_text(self.alert_id)
        if alert_id is None:
            raise ValueError("alert_id is required and cannot be empty")
        self.alert_id = alert_id
        title = normalize_optional_text(self.title)
        description = normalize_optional_text(self.description)
        if title is None:
            raise ValueError("title is required and cannot be empty")
        if description is None:
            raise ValueError("description is required and cannot be empty")
        self.title = title
        self.description = description
        if not isinstance(self.severity, Severity):
            self.severity = Severity(str(self.severity))
        self.device_id = normalize_optional_text(self.device_id)
        self.event_id = normalize_optional_text(self.event_id)
        self.recommendation = normalize_optional_text(self.recommendation)
        self.reasons = [item.strip() for item in self.reasons if item and item.strip()]
        if isinstance(self.timestamp, str):
            self.timestamp = from_iso8601(self.timestamp)

    @property
    def display_timestamp(self) -> str:
        """Human-readable UTC timestamp for CLI and reports."""
        return format_display(self.timestamp)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "alert_id": self.alert_id,
            "timestamp": to_iso8601(self.timestamp),
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "device_id": self.device_id,
            "event_id": self.event_id,
            "reasons": list(self.reasons),
            "recommendation": self.recommendation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        """Rebuild an Alert from ``to_dict`` output or stored JSON."""
        reasons = data.get("reasons") or []
        if isinstance(reasons, str):
            reasons = [reasons]
        severity = parse_enum(Severity, data.get("severity"))
        if severity is None:
            raise ValueError("severity is required")
        return cls(
            alert_id=str(data.get("alert_id") or uuid.uuid4()),
            timestamp=from_iso8601(data["timestamp"]) if data.get("timestamp") else utc_now(),
            severity=severity,
            title=str(data.get("title", "")),
            description=str(data.get("description", "")),
            device_id=data.get("device_id"),
            event_id=data.get("event_id"),
            reasons=list(reasons),
            recommendation=data.get("recommendation"),
        )

    def __str__(self) -> str:
        return f"[{self.severity.value}] {self.title}"
