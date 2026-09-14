"""MockEventSource contract — no USB hardware."""

from usb_monitor.monitoring import MockEventSource, RawAction
from tests.conftest import raw_event


def test_poll_before_start_returns_none() -> None:
    source = MockEventSource([raw_event()])
    assert source.poll(timeout=0) is None
    assert source.queued == 1


def test_poll_after_start_yields_queued_events() -> None:
    first = raw_event(kind="usb")
    second = raw_event(action=RawAction.DISCONNECT, kind="usb")
    source = MockEventSource([first, second])
    source.start()
    assert source.mechanism == "mock"
    assert source.is_running is True
    assert source.poll(timeout=0) is first
    assert source.poll(timeout=0) is second
    assert source.poll(timeout=0) is None
    source.stop()
    assert source.is_running is False


def test_push_and_take_all() -> None:
    source = MockEventSource()
    source.push(raw_event())
    source.extend([raw_event(kind="volume")])
    taken = source.take_all()
    assert len(taken) == 2
    assert source.queued == 0
