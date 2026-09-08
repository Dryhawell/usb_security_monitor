"""Local USB/removable-device inventory.

This is the endpoint's asset baseline: which identities have been seen
before, when, and how often. It does not decide that a device is safe.

Trusted is an operator flag. It must not hide CONNECT/DISCONNECT events.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from usb_monitor.models.device import Device, compose_device_id, normalize_optional_text
from usb_monitor.models.enums import DeviceType, EventType, InterfaceType, RiskLevel, clamp_risk_score
from usb_monitor.models.event import USBEvent
from usb_monitor.utils.logger import get_logger
from usb_monitor.utils.permissions import DEFAULT_DATA_DIR
from usb_monitor.utils.time import format_display, to_iso8601

DEFAULT_INVENTORY_PATH = DEFAULT_DATA_DIR / "inventory" / "devices.json"
_SCHEMA_VERSION = 1


class DeviceNotFoundError(KeyError):
    """Raised when trust/untrust targets an identity that is not in inventory."""


@dataclass(frozen=True)
class Observation:
    """Result of applying one USBEvent to the inventory."""

    device: Device
    is_first_seen: bool
    derived_event: USBEvent | None
    previous: Device | None = None


class DeviceInventory:
    """In-memory device baseline with optional JSON persistence."""

    def __init__(self, path: Path | None = DEFAULT_INVENTORY_PATH) -> None:
        self._path = path
        self._devices: dict[str, Device] = {}
        self._lock = threading.Lock()
        self._log = get_logger("inventory")

    @classmethod
    def load(cls, path: Path | None = DEFAULT_INVENTORY_PATH) -> DeviceInventory:
        """Create an inventory and load ``path`` if it exists."""
        inventory = cls(path=path)
        inventory.reload()
        return inventory

    def reload(self) -> None:
        """Replace in-memory state from disk. Missing/corrupt files start empty."""
        if self._path is None:
            return
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._log.warning("Inventory file could not be read; starting empty (%s)", exc)
            return
        records = raw.get("devices") if isinstance(raw, dict) else None
        if not isinstance(records, list):
            self._log.warning("Inventory file is missing a devices list; starting empty")
            return
        loaded: dict[str, Device] = {}
        for item in records:
            if not isinstance(item, dict):
                continue
            try:
                device = Device.from_dict(item)
            except (KeyError, TypeError, ValueError):
                self._log.warning("Skipping a malformed inventory record")
                continue
            loaded[device.device_id] = device
        with self._lock:
            self._devices = loaded
        self._log.info("Loaded %s device(s) from local inventory", len(loaded))

    def save(self) -> None:
        """Write inventory to disk atomically. No-op when path is None."""
        if self._path is None:
            return
        payload = {
            "version": _SCHEMA_VERSION,
            "devices": [device.to_dict() for device in self.list_devices()],
        }
        text = json.dumps(payload, indent=2)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                prefix="devices.",
                suffix=".json.tmp",
                dir=str(self._path.parent),
            )
            tmp_path = Path(tmp_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(text)
                    handle.write("\n")
                tmp_path.replace(self._path)
            except OSError:
                tmp_path.unlink(missing_ok=True)
                raise
        except OSError as exc:
            self._log.error("Could not save inventory: %s", exc)

    def observe(self, event: USBEvent) -> Observation | None:
        """Update baseline from a CONNECT/DISCONNECT event.

        CONNECT increments connection_count and may emit FIRST_SEEN or
        KNOWN_DEVICE. DISCONNECT only refreshes last_seen. Unknown
        disconnects are ignored so we do not invent a device.
        """
        identity = _identity_from_event(event)
        if identity is None:
            self._log.debug("Skipping inventory update; event has no usable identity")
            return None

        with self._lock:
            device = self._find_locked(event, identity)
            is_first_seen = device is None
            if event.event_type is EventType.DISCONNECT and is_first_seen:
                return None
            if is_first_seen:
                device = Device(device_id=identity)
            assert device is not None
            previous = None if is_first_seen else _clone_device(device)
            _merge_event_into_device(device, event)
            self._rekey_locked(device, identity)
            if event.event_type is EventType.CONNECT:
                device.mark_seen(event.timestamp)
            else:
                device.last_seen = event.timestamp
                if device.first_seen is None:
                    device.first_seen = event.timestamp
            self._devices[device.device_id] = device
            snapshot = _clone_device(device)
            derived = None
            if event.event_type is EventType.CONNECT:
                derived = _derived_event(event, snapshot, is_first_seen)

        self.save()
        _annotate_event(event, snapshot, is_first_seen)
        if derived is not None:
            _annotate_event(derived, snapshot, is_first_seen)
        return Observation(
            device=snapshot,
            is_first_seen=is_first_seen,
            derived_event=derived,
            previous=previous,
        )

    def get(self, device_id: str) -> Device | None:
        with self._lock:
            device = self._devices.get(device_id)
            return _clone_device(device) if device else None

    def list_devices(self) -> list[Device]:
        with self._lock:
            devices = [_clone_device(item) for item in self._devices.values()]
        devices.sort(key=_last_activity, reverse=True)
        return devices

    def set_trusted(self, device_id: str, trusted: bool) -> Device:
        """Mark a known device trusted or untrusted. Does not hide events."""
        with self._lock:
            device = self._devices.get(device_id)
            if device is None:
                raise DeviceNotFoundError(device_id)
            device.trusted = trusted
            snapshot = _clone_device(device)
        self.save()
        return snapshot

    def update_risk(self, device_id: str, score: int, level: RiskLevel) -> None:
        """Store the latest heuristic score on the inventory record."""
        with self._lock:
            device = self._devices.get(device_id)
            if device is None:
                return
            device.risk_score = clamp_risk_score(score)
            device.risk_level = level
        self.save()

    def stats(self) -> dict[str, int]:
        devices = self.list_devices()
        return {
            "total": len(devices),
            "trusted": sum(1 for item in devices if item.trusted),
            "known": sum(1 for item in devices if item.connection_count > 1),
        }

    def _find_locked(self, event: USBEvent, identity: str) -> Device | None:
        if identity in self._devices:
            return self._devices[identity]
        if event.vendor_id and event.product_id and event.serial_number:
            for device in self._devices.values():
                if (
                    device.vendor_id == event.vendor_id
                    and device.product_id == event.product_id
                    and device.serial_number == event.serial_number
                ):
                    return device
        if event.pnp_device_id:
            for device in self._devices.values():
                if device.pnp_device_id == event.pnp_device_id:
                    return device
        return None

    def _rekey_locked(self, device: Device, new_id: str) -> None:
        if device.device_id == new_id:
            return
        old_id = device.device_id
        self._devices.pop(old_id, None)
        device.device_id = new_id


def format_device_row(device: Device) -> str:
    """One-line inventory listing with a masked serial."""
    seen = format_display(device.last_seen) if device.last_seen else "n/a"
    trusted = "yes" if device.trusted else "no"
    if device.risk_level is not None and device.risk_score is not None:
        risk = f"  risk={device.risk_level.value}({device.risk_score})"
    else:
        risk = ""
    return (
        f"{device.safe_device_id}  {device.display_name}  "
        f"connections={device.connection_count}  trusted={trusted}  "
        f"last_seen={seen}{risk}"
    )


def _identity_from_event(event: USBEvent) -> str | None:
    composed = compose_device_id(
        vendor_id=event.vendor_id,
        product_id=event.product_id,
        serial_number=event.serial_number,
        pnp_device_id=event.pnp_device_id,
    )
    if composed:
        return composed
    return normalize_optional_text(event.device_id)


def _merge_event_into_device(device: Device, event: USBEvent) -> None:
    if device.vendor_id is None:
        device.vendor_id = event.vendor_id
    if device.product_id is None:
        device.product_id = event.product_id
    if device.serial_number is None:
        device.serial_number = event.serial_number
    if device.manufacturer is None:
        device.manufacturer = event.manufacturer
    if device.product_name is None:
        device.product_name = event.device_name
    if device.pnp_device_id is None:
        device.pnp_device_id = event.pnp_device_id
    if event.drive_letter:
        device.drive_letter = event.drive_letter
    if device.filesystem is None:
        device.filesystem = event.filesystem
    if device.capacity is None:
        device.capacity = event.capacity
    if device.removable is None:
        device.removable = event.removable
    if event.device_type is not DeviceType.UNKNOWN:
        device.device_type = event.device_type
    if device.interface_type is InterfaceType.UNKNOWN and event.device_type in (
        DeviceType.USB_DEVICE,
        DeviceType.USB_STORAGE,
    ):
        device.interface_type = InterfaceType.USB


def _derived_event(event: USBEvent, device: Device, is_first_seen: bool) -> USBEvent:
    event_type = EventType.FIRST_SEEN if is_first_seen else EventType.KNOWN_DEVICE
    return USBEvent(
        event_type=event_type,
        timestamp=event.timestamp,
        device_id=device.device_id,
        device_name=event.device_name or device.display_name,
        vendor_id=device.vendor_id,
        product_id=device.product_id,
        serial_number=device.serial_number,
        drive_letter=device.drive_letter,
        device_type=device.device_type,
        manufacturer=device.manufacturer,
        pnp_device_id=device.pnp_device_id,
        removable=device.removable,
        filesystem=device.filesystem,
        capacity=device.capacity,
        source=event.source,
        details={
            "from_event_id": event.event_id,
            "reason": (
                "Device identity was not in the local inventory."
                if is_first_seen
                else "Device identity matches a previously observed endpoint asset."
            ),
        },
    )


def _annotate_event(event: USBEvent, device: Device, is_first_seen: bool) -> None:
    event.details["inventory"] = {
        "is_first_seen": is_first_seen,
        "trusted": device.trusted,
        "connection_count": device.connection_count,
        "first_seen": to_iso8601(device.first_seen) if device.first_seen else None,
        "last_seen": to_iso8601(device.last_seen) if device.last_seen else None,
    }


def _clone_device(device: Device) -> Device:
    return Device.from_dict(device.to_dict())


def _last_activity(device: Device) -> datetime:
    return device.last_seen or device.first_seen or datetime(1970, 1, 1, tzinfo=timezone.utc)
