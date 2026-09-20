"""WindowsEventSource queue bounds. Does not start the live watcher."""

import logging

import pytest

from usb_monitor.monitoring import RawAction, RawDeviceEvent, WindowsEventSource
from usb_monitor.utils.platform import is_windows


pytestmark = pytest.mark.skipif(
    not is_windows(),
    reason="WindowsEventSource ctypes bindings are Windows-only",
)


def test_raw_queue_drops_when_full(caplog: pytest.LogCaptureFixture) -> None:
    source = WindowsEventSource(queue_maxsize=2)
    first = RawDeviceEvent(action=RawAction.CONNECT, source="test", kind="usb")
    second = RawDeviceEvent(action=RawAction.CONNECT, source="test", kind="volume")
    overflow = RawDeviceEvent(action=RawAction.DISCONNECT, source="test", kind="usb")
    with caplog.at_level(logging.WARNING, logger="usb_monitor.monitoring.windows"):
        source._enqueue(first)
        source._enqueue(second)
        source._enqueue(overflow)
    assert source.poll(timeout=0) is first
    assert source.poll(timeout=0) is second
    assert source.poll(timeout=0) is None
    assert "dropping" in caplog.text.lower()
    assert "DISCONNECT" in caplog.text
