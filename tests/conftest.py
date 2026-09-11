"""Shared pytest fixtures. Tests never talk to USB hardware."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from usb_monitor.alerts import AlertManager
from usb_monitor.analysis import Analyzer
from usb_monitor.inventory import DeviceInventory
from usb_monitor.monitoring import (
    EventNormalizer,
    MockEventSource,
    NullMetadataCollector,
    RawAction,
    RawDeviceEvent,
    USBMonitor,
)
from usb_monitor.storage import AlertStore, EventStore

USB_INTERFACE_PATH = (
    r"\\?\USB#VID_0781&PID_5581#DEMO1234#{a5dcbf10-6530-11d2-901f-00c04fb951ed}"
)


class FakeClock:
    """Monotonic clock the normalizer can advance without sleeping."""

    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def utc_at(seconds: float = 0.0) -> datetime:
    return datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc).replace(
        microsecond=int(seconds * 1_000_000) % 1_000_000
    )


def raw_event(
    *,
    action: RawAction = RawAction.CONNECT,
    kind: str = "usb",
    drive_letter: str | None = None,
    vendor_id: str | None = "0781",
    product_id: str | None = "5581",
    device_path: str | None = USB_INTERFACE_PATH,
    timestamp: datetime | None = None,
) -> RawDeviceEvent:
    if kind == "volume" and drive_letter is None:
        drive_letter = "E:"
    if kind != "usb" and device_path == USB_INTERFACE_PATH:
        device_path = None
        if kind != "volume":
            vendor_id = None
            product_id = None
    return RawDeviceEvent(
        action=action,
        timestamp=timestamp or utc_at(),
        source="mock",
        kind=kind,
        drive_letter=drive_letter,
        device_path=device_path,
        vendor_id=vendor_id,
        product_id=product_id,
    )


def usb_burst(action: RawAction = RawAction.CONNECT) -> list[RawDeviceEvent]:
    """Typical Windows burst: USB interface + disk + volume."""
    return [
        raw_event(action=action, kind="usb"),
        raw_event(action=action, kind="disk", vendor_id=None, product_id=None, device_path=None),
        raw_event(action=action, kind="volume"),
    ]


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def monitor(clock: FakeClock, tmp_path) -> USBMonitor:
    return USBMonitor(
        MockEventSource(),
        normalizer=EventNormalizer(clock=clock),
        collector=NullMetadataCollector(),
        inventory=DeviceInventory(path=None),
        analyzer=Analyzer(),
        alerts=AlertManager(store=AlertStore(path=None)),
        event_store=EventStore(path=tmp_path / "events.json"),
    )
