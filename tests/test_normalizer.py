"""EventNormalizer coalescing and disk-only drop."""

from usb_monitor.models.enums import EventType
from usb_monitor.monitoring import EventNormalizer, RawAction
from tests.conftest import FakeClock, raw_event, usb_burst


def test_coalesces_usb_disk_volume_into_one_connect() -> None:
    clock = FakeClock()
    normalizer = EventNormalizer(clock=clock)
    produced = []
    for raw in usb_burst():
        produced.extend(normalizer.ingest(raw))
    assert produced == []
    clock.advance(0.5)
    events = normalizer.flush_ready()
    assert len(events) == 1
    event = events[0]
    assert event.event_type is EventType.CONNECT
    assert event.device_id == "0781:5581:DEMO1234"
    assert event.drive_letter == "E:"
    assert event.details["raw_count"] == 3
    assert event.serial_number == "DEMO1234"
    assert "DEMO1234" not in (event.details.get("serial") or "")


def test_disk_only_burst_is_dropped() -> None:
    clock = FakeClock()
    normalizer = EventNormalizer(clock=clock)
    normalizer.ingest(
        raw_event(kind="disk", vendor_id=None, product_id=None, device_path=None)
    )
    clock.advance(0.5)
    assert normalizer.flush_ready() == []
    assert normalizer.flush_all() == []


def test_connect_then_disconnect_are_separate_events() -> None:
    clock = FakeClock()
    normalizer = EventNormalizer(clock=clock)
    for raw in usb_burst(RawAction.CONNECT):
        normalizer.ingest(raw)
    clock.advance(0.5)
    connect = normalizer.flush_ready()
    for raw in usb_burst(RawAction.DISCONNECT):
        normalizer.ingest(raw)
    clock.advance(0.5)
    disconnect = normalizer.flush_ready()
    assert [item.event_type for item in connect + disconnect] == [
        EventType.CONNECT,
        EventType.DISCONNECT,
    ]
