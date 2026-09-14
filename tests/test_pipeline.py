"""USBMonitor pipeline over MockEventSource."""

from usb_monitor.models.enums import EventType, RiskLevel
from usb_monitor.monitoring import USBMonitor
from tests.conftest import FakeClock, usb_burst


def _emit(monitor: USBMonitor, clock: FakeClock) -> list:
    empty = monitor.replay()
    assert empty == []
    clock.advance(0.5)
    return monitor.drain()


def test_first_seen_then_known_device(monitor: USBMonitor, clock: FakeClock) -> None:
    monitor.start()
    source = monitor._source
    source.extend(usb_burst())
    first = _emit(monitor, clock)
    types = [item.event_type for item in first]
    assert EventType.CONNECT in types
    assert EventType.FIRST_SEEN in types
    assert EventType.KNOWN_DEVICE not in types
    connect = next(item for item in first if item.event_type is EventType.CONNECT)
    assert connect.risk_level is not RiskLevel.CRITICAL
    assert connect.safe_device_id == "0781:5581:********1234"

    clock.advance(0.1)
    source.extend(usb_burst())
    second = _emit(monitor, clock)
    types = [item.event_type for item in second]
    assert EventType.CONNECT in types
    assert EventType.KNOWN_DEVICE in types
    assert EventType.FIRST_SEEN not in types
    monitor.stop()


def test_replay_does_not_open_usb_files(monitor: USBMonitor, clock: FakeClock) -> None:
    source = monitor._source
    source.extend(usb_burst())
    events = _emit(monitor, clock)
    assert events
    assert all(item.source == "mock" for item in events)
