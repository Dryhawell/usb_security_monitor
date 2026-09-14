"""Exception isolation and graceful shutdown. No USB hardware."""

from usb_monitor.inventory import DeviceInventory
from usb_monitor.models.enums import EventType
from usb_monitor.monitoring import (
    EventNormalizer,
    MockEventSource,
    NullMetadataCollector,
    USBMonitor,
)
from usb_monitor.storage import EventStore
from tests.conftest import FakeClock, raw_event, usb_burst


class _BoomCollector(NullMetadataCollector):
    def collect(self, event):  # type: ignore[no-untyped-def]
        raise OSError("metadata boom")


class _BoomStore(EventStore):
    def append(self, event) -> None:  # type: ignore[no-untyped-def]
        raise OSError("disk full")


class _BoomSource(MockEventSource):
    def __init__(self) -> None:
        super().__init__()
        self.booms = 1

    def poll(self, timeout: float | None = None):
        if self.booms:
            self.booms -= 1
            raise OSError("poll boom")
        return super().poll(timeout)


def test_context_manager_stops_source() -> None:
    source = MockEventSource()
    with USBMonitor(source) as monitor:
        assert monitor.is_running is True
    assert source.is_running is False


def test_stop_is_idempotent() -> None:
    source = MockEventSource()
    monitor = USBMonitor(source)
    monitor.start()
    monitor.stop()
    monitor.stop()
    assert source.is_running is False


def test_poll_survives_source_oserror() -> None:
    source = _BoomSource()
    monitor = USBMonitor(source)
    monitor.start()
    assert monitor.poll(timeout=0.05) is None
    monitor.stop()


def test_pipeline_emits_after_metadata_and_store_failure(clock: FakeClock) -> None:
    source = MockEventSource()
    monitor = USBMonitor(
        source,
        normalizer=EventNormalizer(clock=clock),
        collector=_BoomCollector(),
        inventory=DeviceInventory(path=None),
        event_store=_BoomStore(path=None),
    )
    source.extend(usb_burst())
    monitor.replay()
    clock.advance(0.5)
    events = monitor.drain()
    types = [item.event_type for item in events]
    assert EventType.CONNECT in types
    assert EventType.FIRST_SEEN in types


def test_run_isolates_callback_failure() -> None:
    source = MockEventSource()
    monitor = USBMonitor(
        source,
        normalizer=EventNormalizer(quiet_period=0, max_wait=0),
        collector=NullMetadataCollector(),
        inventory=DeviceInventory(path=None),
    )
    source.push(raw_event(kind="usb"))

    def boom(_event) -> None:
        raise RuntimeError("callback boom")

    seen = monitor.run(timeout=0.3, on_event=boom)
    assert seen >= 1
    assert source.is_running is False
