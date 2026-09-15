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


def _usb_path(serial: str) -> str:
    return (
        rf"\\?\USB#VID_0781&PID_5581#{serial}"
        r"#{a5dcbf10-6530-11d2-901f-00c04fb951ed}"
    )


def test_same_vid_pid_different_serials_stay_separate() -> None:
    clock = FakeClock()
    normalizer = EventNormalizer(clock=clock)
    first = raw_event(kind="usb", device_path=_usb_path("STICKAAA"))
    second = raw_event(kind="usb", device_path=_usb_path("STICKBBB"))
    normalizer.ingest(first)
    normalizer.ingest(second)
    clock.advance(0.5)
    events = normalizer.flush_ready()
    serials = {item.serial_number for item in events}
    assert serials == {"STICKAAA", "STICKBBB"}
    assert all(item.event_type is EventType.CONNECT for item in events)


def test_usb_serial_still_merges_with_disk_and_volume() -> None:
    clock = FakeClock()
    normalizer = EventNormalizer(clock=clock)
    for raw in usb_burst():
        normalizer.ingest(raw)
    clock.advance(0.5)
    events = normalizer.flush_ready()
    assert len(events) == 1
    assert events[0].serial_number == "DEMO1234"
    assert events[0].drive_letter == "E:"
