"""Device metadata collection — fill OS-exposed fields only.

This layer does not scan files, talk to the network, or invent
manufacturer names. Missing properties stay ``None``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from usb_monitor.models.device import compose_device_id, normalize_drive_letter, normalize_hardware_id, normalize_optional_text
from usb_monitor.models.event import USBEvent
from usb_monitor.monitoring.event_source import redact_pnp_device_id
from usb_monitor.utils.logger import mask_identifier


@dataclass(frozen=True)
class DeviceMetadata:
    """Best-effort snapshot of properties the OS actually exposed."""

    vendor_id: str | None = None
    product_id: str | None = None
    serial_number: str | None = None
    manufacturer: str | None = None
    product_name: str | None = None
    pnp_device_id: str | None = None
    drive_letter: str | None = None
    filesystem: str | None = None
    capacity: int | None = None
    removable: bool | None = None
    volume_label: str | None = None
    source: str = "none"

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable view with serial/PnP masked for display."""
        return {
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial_number": mask_identifier(self.serial_number) if self.serial_number else None,
            "manufacturer": self.manufacturer,
            "product_name": self.product_name,
            "pnp_device_id": redact_pnp_device_id(self.pnp_device_id),
            "drive_letter": self.drive_letter,
            "filesystem": self.filesystem,
            "capacity": self.capacity,
            "removable": self.removable,
            "volume_label": self.volume_label,
            "source": self.source,
        }


class MetadataCollector(ABC):
    """Lookup extra device properties after a CONNECT/DISCONNECT is formed."""

    @property
    @abstractmethod
    def mechanism(self) -> str:
        """Identifier of the lookup mechanism."""

    @abstractmethod
    def collect(self, event: USBEvent) -> DeviceMetadata:
        """Return observed metadata. Must not raise on a vanished device."""


class NullMetadataCollector(MetadataCollector):
    """Used when live Windows lookup is unavailable. Invents nothing."""

    @property
    def mechanism(self) -> str:
        return "none"

    def collect(self, event: USBEvent) -> DeviceMetadata:
        return DeviceMetadata(source=self.mechanism)


def apply_metadata(event: USBEvent, metadata: DeviceMetadata) -> USBEvent:
    """Fill empty USBEvent fields from metadata. Never overwrites known values with empty."""
    if event.vendor_id is None:
        event.vendor_id = normalize_hardware_id(metadata.vendor_id)
    if event.product_id is None:
        event.product_id = normalize_hardware_id(metadata.product_id)
    if event.serial_number is None:
        event.serial_number = normalize_optional_text(metadata.serial_number)
    if event.manufacturer is None:
        event.manufacturer = normalize_optional_text(metadata.manufacturer)
    product_name = normalize_optional_text(metadata.product_name)
    if event.device_name is None and product_name:
        event.device_name = product_name
    if event.pnp_device_id is None:
        event.pnp_device_id = normalize_optional_text(metadata.pnp_device_id)
    if event.drive_letter is None:
        event.drive_letter = normalize_drive_letter(metadata.drive_letter)
    if event.filesystem is None:
        event.filesystem = normalize_optional_text(metadata.filesystem)
    if event.capacity is None and metadata.capacity is not None:
        event.capacity = metadata.capacity
    if event.removable is None and metadata.removable is not None:
        event.removable = metadata.removable

    composed = compose_device_id(
        vendor_id=event.vendor_id,
        product_id=event.product_id,
        serial_number=event.serial_number,
        pnp_device_id=event.pnp_device_id,
    )
    if composed:
        event.device_id = composed
    elif event.device_id is None and event.drive_letter:
        event.device_id = f"volume:{event.drive_letter}"

    if metadata.volume_label:
        event.details.setdefault("volume_label", metadata.volume_label)
    event.details["metadata_source"] = metadata.source
    return event
