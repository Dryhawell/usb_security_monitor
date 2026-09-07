"""Platform-agnostic USB/removable-device event source contract.

Detection lives here. Analysis, inventory, and alerts must not be mixed
into this layer. A raw event means "the OS reported a device change",
not "this device is malicious".
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from usb_monitor.utils.logger import mask_identifier
from usb_monitor.utils.time import format_display, to_iso8601, utc_now

_VID_PID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", re.IGNORECASE)


class RawAction(str, Enum):
    """Low-level arrival/removal as reported by the operating system."""

    CONNECT = "CONNECT"
    DISCONNECT = "DISCONNECT"


class EventSourceUnavailableError(RuntimeError):
    """The selected OS event source could not be started."""


@dataclass(frozen=True)
class RawDeviceEvent:
    """A single OS notification before inventory or risk analysis."""

    action: RawAction
    timestamp: datetime = field(default_factory=utc_now)
    source: str = "unknown"
    kind: str = "unknown"
    drive_letter: str | None = None
    device_path: str | None = None
    vendor_id: str | None = None
    product_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def display_timestamp(self) -> str:
        return format_display(self.timestamp)

    def to_dict(self) -> dict[str, Any]:
        """Full local representation. May include a device path with a serial."""
        return {
            "action": self.action.value,
            "timestamp": to_iso8601(self.timestamp),
            "source": self.source,
            "kind": self.kind,
            "drive_letter": self.drive_letter,
            "device_path": self.device_path,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "details": dict(self.details),
        }

    def to_log_dict(self) -> dict[str, Any]:
        """Same as ``to_dict`` with device-path serial segments masked."""
        payload = self.to_dict()
        payload["device_path"] = redact_device_path(self.device_path)
        return payload

    def format_console(self) -> str:
        """Human-readable line safe for default console output."""
        target = self.drive_letter or redact_device_path(self.device_path) or "unknown"
        vid = self.vendor_id or "Unknown"
        pid = self.product_id or "Unknown"
        return (
            f"[{self.display_timestamp}] RAW {self.action.value} "
            f"kind={self.kind} target={target} VID={vid} PID={pid}"
        )


class EventSource(ABC):
    """Produces raw device events. Implementations must be start/stop safe."""

    @property
    @abstractmethod
    def mechanism(self) -> str:
        """Stable identifier of the OS mechanism, for logs and status."""

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """True after a successful ``start`` until ``stop``."""

    @abstractmethod
    def start(self) -> None:
        """Begin receiving OS notifications.

        Must not crash the process if the mechanism is missing; raise
        ``EventSourceUnavailableError`` or ``UnsupportedPlatformError``.
        """

    @abstractmethod
    def stop(self, timeout: float = 5.0) -> None:
        """Stop the watcher and join background work."""

    @abstractmethod
    def poll(self, timeout: float | None = None) -> RawDeviceEvent | None:
        """Return the next event, or ``None`` if the timeout expires."""


def parse_vid_pid_from_path(device_path: str | None) -> tuple[str | None, str | None]:
    """Extract VID/PID from a Windows device interface path when present."""
    if not device_path:
        return None, None
    match = _VID_PID_RE.search(device_path)
    if match is None:
        return None, None
    return match.group(1).upper(), match.group(2).upper()


def parse_instance_id_from_path(device_path: str | None) -> str | None:
    """Return the instance/serial segment of a device path, if present.

    The OS already placed this value on the path. Missing segments stay
    ``None``; nothing is invented.
    """
    if not device_path:
        return None
    parts = device_path.split("#")
    if len(parts) < 3:
        return None
    instance = parts[2].strip()
    if not instance or instance.startswith("{"):
        return None
    return instance


def device_path_to_instance_id(device_path: str | None) -> str | None:
    """Convert a ``\\\\?\\USB#VID_...`` interface path to a PnP instance ID."""
    if not device_path:
        return None
    text = device_path.strip()
    for prefix in ("\\\\?\\", "\\\\.\\"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    parts = [part for part in text.split("#") if part and not part.startswith("{")]
    if len(parts) < 2:
        return None
    if len(parts) >= 3:
        return f"{parts[0]}\\{parts[1]}\\{parts[2]}"
    return f"{parts[0]}\\{parts[1]}"


def redact_pnp_device_id(pnp_device_id: str | None) -> str | None:
    """Mask the instance/serial segment of a PnP device ID for logs."""
    if not pnp_device_id:
        return None
    parts = pnp_device_id.split("\\")
    if len(parts) >= 3 and parts[-1]:
        parts[-1] = mask_identifier(parts[-1])
        return "\\".join(parts)
    return pnp_device_id


def redact_device_path(device_path: str | None) -> str | None:
    """Mask the instance/serial segment of a Windows device path.

    Example::

        \\\\?\\USB#VID_0781&PID_5581#ABC123#{guid}
        -> \\\\?\\USB#VID_0781&PID_5581#********C123#{guid}
    """
    if not device_path:
        return None
    parts = device_path.split("#")
    if len(parts) >= 3 and parts[2]:
        parts[2] = mask_identifier(parts[2])
        return "#".join(parts)
    return device_path


def drive_letters_from_unit_mask(unit_mask: int) -> tuple[str, ...]:
    """Convert a ``DEV_BROADCAST_VOLUME.dbcv_unitmask`` bit field to ``E:`` letters."""
    letters: list[str] = []
    mask = int(unit_mask) & 0xFFFFFFFF
    for index in range(26):
        if mask & (1 << index):
            letters.append(f"{chr(ord('A') + index)}:")
    return tuple(letters)
