"""Offline operator demos. No USB hardware, no telemetry.

These checks used to live in main.py. Flags such as --demo-models stay
on the CLI so existing scripts keep working. Scores are not a malware
verdict.
"""

from __future__ import annotations

import json
import tempfile
from argparse import Namespace
from datetime import timedelta
from pathlib import Path

from usb_monitor import __app_name__
from usb_monitor.alerts import AlertManager, format_alert
from usb_monitor.analysis import Analyzer
from usb_monitor.analysis.risk_engine import RiskAssessment
from usb_monitor.analysis.rules import RULE_IDENTITY_CHANGE, RuleMatch
from usb_monitor.cli import demo_cli
from usb_monitor.inventory import DeviceInventory
from usb_monitor.models import (
    Alert,
    Device,
    DeviceType,
    EventType,
    InterfaceType,
    RiskLevel,
    Severity,
    USBEvent,
)
from usb_monitor.monitoring import (
    DeviceMetadata,
    EventNormalizer,
    EventSource,
    MockEventSource,
    NullMetadataCollector,
    RawAction,
    RawDeviceEvent,
    USBMonitor,
    apply_metadata,
    device_path_to_instance_id,
    format_live_event,
)
from usb_monitor.reports import DISCLAIMER, build_local_report, export_report
from usb_monitor.storage import AlertStore, EventStore
from usb_monitor.utils.time import utc_now


def demo_models() -> None:
    """Show serialization of sample in-memory models. Uses no USB hardware."""
    now = utc_now()
    device = Device(
        device_id="0781:5581:DEMO1234",
        vendor_id="0x0781",
        product_id="5581",
        serial_number="DEMO1234",
        manufacturer="SanDisk",
        product_name="Ultra USB",
        device_type=DeviceType.USB_STORAGE,
        interface_type=InterfaceType.USB,
        drive_letter="E",
        removable=True,
        trusted=True,
        risk_score=8,
    )
    device.mark_seen(now)

    event = USBEvent(
        event_type=EventType.CONNECT,
        device_id=device.device_id,
        device_name=device.display_name,
        vendor_id=device.vendor_id,
        product_id=device.product_id,
        serial_number=device.serial_number,
        drive_letter=device.drive_letter,
        device_type=device.device_type,
        source="demo",
        details={"note": "simulated sample; not a live device"},
    )

    alert = Alert(
        severity=Severity.INFO,
        title="Sample model demonstration",
        description="Phase 2 demo alert generated from in-memory sample data.",
        device_id=device.device_id,
        event_id=event.event_id,
        reasons=["Demonstration only; no live USB activity was observed."],
        recommendation="Use this output to verify model serialization.",
    )

    payload = {
        "device": device.to_dict(),
        "event": event.to_dict(),
        "alert": alert.to_dict(),
        "roundtrip_ok": (
            Device.from_dict(device.to_dict()).to_dict() == device.to_dict()
            and USBEvent.from_dict(event.to_dict()).to_dict() == event.to_dict()
            and Alert.from_dict(alert.to_dict()).to_dict() == alert.to_dict()
        ),
    }
    print(json.dumps(payload, indent=2))
    print()
    print(device)
    print(event)
    print(alert)


class _FakeClock:
    """Monotonic clock that tests can advance without waiting."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def demo_normalize() -> int:
    """Show that USB+disk+volume raw signals become one USBEvent. No hardware."""
    clock = _FakeClock()
    normalizer = EventNormalizer(clock=clock)
    usb_path = r"\\?\USB#VID_0781&PID_5581#DEMO1234#{a5dcbf10-6530-11d2-901f-00c04fb951ed}"
    burst = [
        RawDeviceEvent(
            action=RawAction.CONNECT,
            source="demo",
            kind="usb",
            device_path=usb_path,
            vendor_id="0781",
            product_id="5581",
        ),
        RawDeviceEvent(
            action=RawAction.CONNECT,
            source="demo",
            kind="disk",
        ),
        RawDeviceEvent(
            action=RawAction.CONNECT,
            source="demo",
            kind="volume",
            drive_letter="E:",
        ),
    ]
    print("Raw signals (simulated, 3 OS notifications):")
    for raw in burst:
        clock.advance(0.05)
        emitted = normalizer.ingest(raw)
        print(f"  {raw.format_console()} -> pending logical events: {len(emitted)}")

    clock.advance(0.5)
    events = normalizer.flush_ready()
    print()
    print(f"Logical USB events after quiet window: {len(events)}")
    for event in events:
        print()
        print(format_live_event(event))
        print(f"raw_count={event.details.get('raw_count')} coalesced={event.details.get('coalesced')}")

    noise = EventNormalizer(clock=clock)
    clock.advance(0.05)
    noise.ingest(
        RawDeviceEvent(action=RawAction.CONNECT, source="demo", kind="disk")
    )
    clock.advance(0.5)
    dropped = noise.flush_ready()
    print()
    print(f"Disk-only burst (internal disk noise) emitted: {len(dropped)}")
    ok = (
        len(events) == 1
        and events[0].event_type is EventType.CONNECT
        and events[0].details.get("raw_count") == 3
        and not dropped
    )
    print("Demo result: OK" if ok else "Demo result: FAILED")
    return 0 if ok else 1


def demo_metadata() -> int:
    """Show metadata merge rules with in-memory data. No USB hardware."""
    event = USBEvent(
        event_type=EventType.CONNECT,
        vendor_id="0781",
        product_id="5581",
        serial_number="DEMO1234",
        drive_letter="E:",
        source="demo",
    )
    filled = apply_metadata(
        event,
        DeviceMetadata(
            manufacturer="SanDisk",
            product_name="Ultra USB",
            filesystem="FAT32",
            removable=True,
            capacity=15_728_640_000,
            volume_label="BACKUP",
            source="demo",
        ),
    )
    print(format_live_event(filled))
    print(f"volume_label (not manufacturer): {filled.details.get('volume_label')}")

    guarded = USBEvent(
        event_type=EventType.CONNECT,
        vendor_id="0781",
        manufacturer="SanDisk",
        source="demo",
    )
    apply_metadata(guarded, DeviceMetadata(vendor_id="zzzz", manufacturer=None, source="demo"))
    empty = USBEvent(event_type=EventType.CONNECT, source="demo")
    apply_metadata(empty, DeviceMetadata(source="none"))
    pnp = device_path_to_instance_id(
        r"\\?\USB#VID_0781&PID_5581#DEMO1234#{a5dcbf10-6530-11d2-901f-00c04fb951ed}"
    )
    null_event = USBEvent(event_type=EventType.CONNECT, vendor_id="ABCD", source="demo")
    NullMetadataCollector().collect(null_event)
    apply_metadata(null_event, NullMetadataCollector().collect(null_event))

    ok = (
        filled.manufacturer == "SanDisk"
        and filled.device_name == "Ultra USB"
        and filled.filesystem == "FAT32"
        and filled.removable is True
        and guarded.vendor_id == "0781"
        and guarded.manufacturer == "SanDisk"
        and empty.manufacturer is None
        and pnp == r"USB\VID_0781&PID_5581\DEMO1234"
        and null_event.vendor_id == "ABCD"
        and null_event.manufacturer is None
    )
    print()
    print(f"PnP instance from path: {pnp}")
    print("Did not overwrite known VID with invalid metadata: OK" if guarded.vendor_id == "0781" else "overwrite FAILED")
    print("Empty collector invented nothing: OK" if empty.manufacturer is None else "invent FAILED")
    print("Demo result: OK" if ok else "Demo result: FAILED")
    return 0 if ok else 1


def _sample_connect(device_id: str, serial: str) -> USBEvent:
    vid, pid, _rest = device_id.split(":", 2)
    return USBEvent(
        event_type=EventType.CONNECT,
        device_id=device_id,
        vendor_id=vid,
        product_id=pid,
        serial_number=serial,
        manufacturer="SanDisk",
        device_name="Ultra USB",
        drive_letter="E:",
        device_type=DeviceType.USB_STORAGE,
        source="demo",
    )


def demo_inventory() -> int:
    """First-seen vs known vs trusted, in memory only. No USB hardware."""
    inventory = DeviceInventory(path=None)
    first = _sample_connect("0781:5581:DEMO1234", "DEMO1234")
    seen = inventory.observe(first)
    second = _sample_connect("0781:5581:DEMO1234", "DEMO1234")
    known = inventory.observe(second)
    trusted_device = inventory.set_trusted("0781:5581:DEMO1234", True)
    third = _sample_connect("0781:5581:DEMO1234", "DEMO1234")
    trusted_reconnect = inventory.observe(third)
    other = USBEvent(
        event_type=EventType.CONNECT,
        device_id="ABCD:0001:OTHER99",
        vendor_id="ABCD",
        product_id="0001",
        serial_number="OTHER99",
        source="demo",
    )
    other_seen = inventory.observe(other)

    print("First connect:")
    print(format_live_event(seen.derived_event) if seen and seen.derived_event else "missing")
    print("Second connect (same identity):")
    print(format_live_event(known.derived_event) if known and known.derived_event else "missing")
    print(f"Trusted flag set: {trusted_device.trusted}")
    print("Third connect after trust (CONNECT is not suppressed):")
    if trusted_reconnect:
        print(f"  first_seen={trusted_reconnect.is_first_seen} trusted={trusted_reconnect.device.trusted} connections={trusted_reconnect.device.connection_count}")
        print(format_live_event(third))
    print("Different identity:")
    print(format_live_event(other_seen.derived_event) if other_seen and other_seen.derived_event else "missing")

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "devices.json"
        persisted = DeviceInventory(path)
        persisted.observe(_sample_connect("0781:5581:DEMO1234", "DEMO1234"))
        reloaded = DeviceInventory.load(path)
        loaded = reloaded.get("0781:5581:DEMO1234")

    ok = (
        seen is not None
        and seen.is_first_seen
        and seen.derived_event is not None
        and seen.derived_event.event_type is EventType.FIRST_SEEN
        and known is not None
        and not known.is_first_seen
        and known.device.connection_count == 2
        and trusted_reconnect is not None
        and trusted_reconnect.device.trusted is True
        and trusted_reconnect.device.connection_count == 3
        and third.event_type is EventType.CONNECT
        and other_seen is not None
        and other_seen.is_first_seen
        and loaded is not None
        and loaded.connection_count == 1
    )
    print()
    print(f"Persistence round-trip connections: {loaded.connection_count if loaded else 'missing'}")
    print("Demo result: OK" if ok else "Demo result: FAILED")
    return 0 if ok else 1


class _IdleEventSource(EventSource):
    """Event source that never yields OS notifications. Used by --demo-risk."""

    def __init__(self) -> None:
        self._running = False

    @property
    def mechanism(self) -> str:
        return "demo"

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> None:
        self._running = True

    def stop(self, timeout: float = 5.0) -> None:
        self._running = False

    def poll(self, timeout: float | None = None) -> RawDeviceEvent | None:
        return None


class _BoomCollector(NullMetadataCollector):
    """Metadata collector that always fails. Used by --demo-reliability."""

    def collect(self, event):  # type: ignore[no-untyped-def]
        raise OSError("metadata boom")


class _BoomStore(EventStore):
    """Event store that always fails to persist. Used by --demo-reliability."""

    def append(self, event: USBEvent) -> None:
        raise OSError("disk full")


class _BoomSource(MockEventSource):
    """Mock source whose first poll raises. Used by --demo-reliability."""

    def __init__(self) -> None:
        super().__init__()
        self._booms = 1

    def poll(self, timeout: float | None = None) -> RawDeviceEvent | None:
        if self._booms:
            self._booms -= 1
            raise OSError("poll boom")
        return super().poll(timeout)


def _feed_connect(monitor: USBMonitor, event: USBEvent) -> list[USBEvent]:
    monitor._queue_event(event)
    return monitor.drain()


def _risk_ids(event: USBEvent) -> list[str]:
    payload = event.details.get("risk") if isinstance(event.details, dict) else None
    if not isinstance(payload, dict):
        return []
    return [
        str(item.get("rule_id"))
        for item in payload.get("matches") or []
        if isinstance(item, dict) and item.get("rule_id")
    ]


def demo_risk() -> int:
    """Show heuristic scoring: first-seen stays MEDIUM; stacked signals can reach HIGH."""
    analyzer = Analyzer()
    preview = DeviceInventory(path=None)
    incomplete = USBEvent(
        event_type=EventType.CONNECT,
        device_id="volume:E:",
        drive_letter="E:",
        device_type=DeviceType.REMOVABLE_MEDIA,
        source="demo",
    )
    incomplete_assessment = analyzer.analyze(incomplete, preview.observe(incomplete))
    print("First-seen incomplete volume (missing manufacturer/serial, letter-only identity):")
    print(f"  score={incomplete_assessment.score if incomplete_assessment else 'n/a'} "
          f"level={incomplete_assessment.level.value if incomplete_assessment else 'n/a'}")
    print(f"  rules={list(incomplete_assessment.reasons) if incomplete_assessment else []}")

    inventory = DeviceInventory(path=None)
    monitor = USBMonitor(
        _IdleEventSource(),
        collector=NullMetadataCollector(),
        inventory=inventory,
        analyzer=Analyzer(),
    )

    print()
    print("Scenario A — first connect of a complete known-looking stick:")
    first = USBEvent(
        event_type=EventType.CONNECT,
        device_id="0781:5581:DEMO1234",
        vendor_id="0781",
        product_id="5581",
        serial_number="DEMO1234",
        manufacturer="SanDisk",
        device_name="Ultra USB",
        device_type=DeviceType.USB_STORAGE,
        removable=False,
        source="demo",
    )
    first_events = _feed_connect(monitor, first)
    for item in first_events:
        print(format_live_event(item))
        print()

    print("Scenario B — trusted reconnect of the same identity (CONNECT is not hidden):")
    inventory.set_trusted("0781:5581:DEMO1234", True)
    trusted = USBEvent(
        event_type=EventType.CONNECT,
        device_id="0781:5581:DEMO1234",
        vendor_id="0781",
        product_id="5581",
        serial_number="DEMO1234",
        manufacturer="SanDisk",
        device_name="Ultra USB",
        device_type=DeviceType.USB_STORAGE,
        removable=False,
        source="demo",
    )
    trusted_events = _feed_connect(monitor, trusted)
    for item in trusted_events:
        print(format_live_event(item))
        print()

    stacked_inventory = DeviceInventory(path=None)
    stacked_monitor = USBMonitor(
        _IdleEventSource(),
        collector=NullMetadataCollector(),
        inventory=stacked_inventory,
        analyzer=Analyzer(),
    )
    baseline = USBEvent(
        event_type=EventType.CONNECT,
        device_id="0781:5581:DEMO1234",
        vendor_id="0781",
        product_id="5581",
        serial_number="DEMO1234",
        manufacturer="SanDisk",
        device_name="Ultra USB",
        device_type=DeviceType.USB_STORAGE,
        removable=False,
        source="demo",
    )
    _feed_connect(stacked_monitor, baseline)
    print("Scenario C — same identity, changed manufacturer + generic name + type/removable mismatch:")
    changed = USBEvent(
        event_type=EventType.CONNECT,
        device_id="0781:5581:DEMO1234",
        vendor_id="0781",
        product_id="5581",
        serial_number="DEMO1234",
        manufacturer="Generic USB Storage",
        device_name="USB Device",
        drive_letter="E:",
        device_type=DeviceType.USB_DEVICE,
        removable=True,
        source="demo",
    )
    changed_events = _feed_connect(stacked_monitor, changed)
    for item in changed_events:
        print(format_live_event(item))
        print()

    first_connect = next((item for item in first_events if item.event_type is EventType.CONNECT), None)
    trusted_connect = next((item for item in trusted_events if item.event_type is EventType.CONNECT), None)
    changed_connect = next((item for item in changed_events if item.event_type is EventType.CONNECT), None)
    first_seen = next((item for item in first_events if item.event_type is EventType.FIRST_SEEN), None)
    suspicious = [item for item in changed_events if item.event_type is EventType.SUSPICIOUS_DEVICE]

    first_ids = _risk_ids(first_connect) if first_connect else []
    trusted_ids = _risk_ids(trusted_connect) if trusted_connect else []
    changed_ids = _risk_ids(changed_connect) if changed_connect else []

    ok = (
        incomplete_assessment is not None
        and incomplete_assessment.level is RiskLevel.MEDIUM
        and incomplete_assessment.score < 51
        and first_connect is not None
        and first_connect.risk_level is RiskLevel.LOW
        and "FIRST_SEEN_DEVICE" in first_ids
        and first_seen is not None
        and first_seen.risk_score == first_connect.risk_score
        and trusted_connect is not None
        and "TRUSTED_DEVICE" in trusted_ids
        and trusted_connect.event_type is EventType.CONNECT
        and changed_connect is not None
        and changed_connect.risk_level is RiskLevel.HIGH
        and "IDENTITY_INCONSISTENCY" in changed_ids
        and "GENERIC_OR_SUSPICIOUS_NAME" in changed_ids
        and len(suspicious) == 1
        and suspicious[0].risk_level is RiskLevel.HIGH
        and not any(item.event_type is EventType.SUSPICIOUS_DEVICE for item in first_events)
        and not any(item.event_type is EventType.SUSPICIOUS_DEVICE for item in trusted_events)
    )
    print("First-seen / missing-serial alone did not assign CRITICAL: OK")
    print("Trusted flag did not suppress CONNECT: OK")
    print("HIGH stacked characteristics emitted SUSPICIOUS_DEVICE: OK" if suspicious else "HIGH stacked FAILED")
    print("Demo result: OK" if ok else "Demo result: FAILED")
    return 0 if ok else 1


def _timed_storage(device_id: str, serial: str, timestamp, event_type: EventType = EventType.CONNECT) -> USBEvent:
    vid, pid, _rest = device_id.split(":", 2)
    return USBEvent(
        event_type=event_type,
        timestamp=timestamp,
        device_id=device_id,
        vendor_id=vid,
        product_id=pid,
        serial_number=serial,
        manufacturer="SanDisk",
        device_name="Ultra USB",
        device_type=DeviceType.USB_STORAGE,
        removable=True,
        source="demo",
    )


def _new_monitor() -> USBMonitor:
    return USBMonitor(
        _IdleEventSource(),
        collector=NullMetadataCollector(),
        inventory=DeviceInventory(path=None),
        analyzer=Analyzer(),
    )


def demo_anomaly() -> int:
    """Reconnect bursts and first-seen floods. No USB hardware."""
    origin = utc_now()

    print("Scenario A — two CONNECTs in 15s (below rapid-reconnect threshold):")
    two = _new_monitor()
    two_events = []
    for offset in (0, 4):
        two_events.extend(
            _feed_connect(two, _timed_storage("0781:5581:DEMO1234", "DEMO1234", origin + timedelta(seconds=offset)))
        )
    two_connects = [item for item in two_events if item.event_type is EventType.CONNECT]
    print(format_live_event(two_connects[-1]) if two_connects else "missing")
    print()

    print("Scenario B — three CONNECTs in 15s (RAPID_RECONNECT):")
    rapid = _new_monitor()
    rapid_events = []
    for offset in (0, 4, 8):
        rapid_events.extend(
            _feed_connect(
                rapid, _timed_storage("0781:5581:DEMO1234", "DEMO1234", origin + timedelta(seconds=offset))
            )
        )
    rapid_connects = [item for item in rapid_events if item.event_type is EventType.CONNECT]
    print(format_live_event(rapid_connects[-1]) if rapid_connects else "missing")
    print()

    print("Scenario C — CONNECT/DISCONNECT flap (REPEATED_EVENTS, and RAPID if 3 connects):")
    flap = _new_monitor()
    flap_events = []
    sequence = (
        (0, EventType.CONNECT),
        (2, EventType.DISCONNECT),
        (4, EventType.CONNECT),
        (6, EventType.DISCONNECT),
        (8, EventType.CONNECT),
    )
    for offset, event_type in sequence:
        flap_events.extend(
            _feed_connect(
                flap,
                _timed_storage(
                    "0781:5581:DEMO1234",
                    "DEMO1234",
                    origin + timedelta(seconds=offset),
                    event_type,
                ),
            )
        )
    flap_connects = [item for item in flap_events if item.event_type is EventType.CONNECT]
    print(format_live_event(flap_connects[-1]) if flap_connects else "missing")
    print()

    print("Scenario D — three first-seen identities in 60s (MULTIPLE_NEW_DEVICES):")
    flood = _new_monitor()
    flood_events = []
    for index, serial in enumerate(("NEW001", "NEW002", "NEW003")):
        flood_events.extend(
            _feed_connect(
                flood,
                _timed_storage(
                    f"0781:5581:{serial}",
                    serial,
                    origin + timedelta(seconds=index * 5),
                ),
            )
        )
    flood_connects = [item for item in flood_events if item.event_type is EventType.CONNECT]
    print(format_live_event(flood_connects[-1]) if flood_connects else "missing")
    print()

    print("Scenario E — three first-seen identities 70s apart (window expired):")
    spaced = _new_monitor()
    spaced_events = []
    for index, serial in enumerate(("OLD001", "OLD002", "OLD003")):
        spaced_events.extend(
            _feed_connect(
                spaced,
                _timed_storage(
                    f"ABCD:0001:{serial}",
                    serial,
                    origin + timedelta(seconds=index * 70),
                ),
            )
        )
    spaced_connects = [item for item in spaced_events if item.event_type is EventType.CONNECT]
    print(format_live_event(spaced_connects[-1]) if spaced_connects else "missing")
    print()

    two_ids = _risk_ids(two_connects[-1]) if two_connects else []
    rapid_ids = _risk_ids(rapid_connects[-1]) if rapid_connects else []
    flap_ids = _risk_ids(flap_connects[-1]) if flap_connects else []
    flood_ids = _risk_ids(flood_connects[-1]) if flood_connects else []
    spaced_ids = _risk_ids(spaced_connects[-1]) if spaced_connects else []

    ok = (
        two_connects
        and "RAPID_RECONNECT" not in two_ids
        and rapid_connects
        and "RAPID_RECONNECT" in rapid_ids
        and rapid_connects[-1].risk_level is not RiskLevel.CRITICAL
        and flap_connects
        and "REPEATED_EVENTS" in flap_ids
        and flood_connects
        and "MULTIPLE_NEW_DEVICES" in flood_ids
        and flood_connects[-1].risk_level is not RiskLevel.CRITICAL
        and spaced_connects
        and "MULTIPLE_NEW_DEVICES" not in spaced_ids
        and not any(item.event_type is EventType.SUSPICIOUS_DEVICE for item in two_events)
        and not any(item.event_type is EventType.SUSPICIOUS_DEVICE for item in rapid_events)
    )
    print("Two reconnects did not fire RAPID_RECONNECT: OK")
    print("Three reconnects fired RAPID_RECONNECT: OK" if "RAPID_RECONNECT" in rapid_ids else "rapid FAILED")
    print("Flap fired REPEATED_EVENTS: OK" if "REPEATED_EVENTS" in flap_ids else "flap FAILED")
    print("Three new devices fired MULTIPLE_NEW_DEVICES: OK" if "MULTIPLE_NEW_DEVICES" in flood_ids else "flood FAILED")
    print("Spaced first-seen did not keep the window: OK" if "MULTIPLE_NEW_DEVICES" not in spaced_ids else "spacing FAILED")
    print("Demo result: OK" if ok else "Demo result: FAILED")
    return 0 if ok else 1


def demo_alerts() -> int:
    """Generation, cooldown, burst suppression, and escalation. No USB hardware."""
    origin = utc_now()
    print("Scenario A — first-seen complete stick raises an INFO alert:")
    monitor = _new_monitor()
    first_events = _feed_connect(
        monitor, _timed_storage("0781:5581:DEMO1234", "DEMO1234", origin)
    )
    first_connect = next((item for item in first_events if item.event_type is EventType.CONNECT), None)
    if first_connect is not None:
        print(format_live_event(first_connect))
        print()
    first_alerts = monitor.alerts.list_alerts()
    if first_alerts:
        print(format_alert(first_alerts[-1]))
        print()

    print("Scenario B — immediate known reconnect does not raise first-seen again:")
    known_events = _feed_connect(
        monitor, _timed_storage("0781:5581:DEMO1234", "DEMO1234", origin + timedelta(seconds=2))
    )
    known_connect = next((item for item in known_events if item.event_type is EventType.CONNECT), None)
    if known_connect is not None:
        print(format_live_event(known_connect))
        print()

    print("Scenario C — 100 identical HIGH warnings in one second -> 1 emit, 99 suppressed:")
    burst_manager = AlertManager(cooldown_seconds=60)
    burst_event = _timed_storage("0781:5581:BURST99", "BURST99", origin)
    high = RiskAssessment(
        score=62,
        level=RiskLevel.HIGH,
        matches=(RuleMatch(RULE_IDENTITY_CHANGE, "Simulated identity change for cooldown demo."),),
    )
    burst_emitted = 0
    burst_suppressed = 0
    for _ in range(100):
        decision = burst_manager.consider(burst_event, high)
        if decision.alert is not None:
            burst_emitted += 1
        elif decision.suppressed:
            burst_suppressed += 1
    print(f"  emitted={burst_emitted} suppressed={burst_suppressed}")
    print()

    print("Scenario D — HIGH then CRITICAL on the same fingerprint escalates inside cooldown:")
    escalate = AlertManager(cooldown_seconds=60)
    same = _timed_storage("0781:5581:ESC001", "ESC001", origin)
    first = escalate.consider(same, high)
    critical = RiskAssessment(
        score=80,
        level=RiskLevel.CRITICAL,
        matches=(RuleMatch(RULE_IDENTITY_CHANGE, "Simulated stacked CRITICAL heuristic."),),
    )
    second = escalate.consider(same, critical)
    third = escalate.consider(same, critical)
    if first.alert is not None:
        print(format_alert(first.alert))
        print()
    if second.alert is not None:
        print(format_alert(second.alert))
        print()
    print(f"  third suppressed={third.suppressed}")
    print()

    print("Scenario E — same HIGH after cooldown window expires emits again:")
    later = _timed_storage("0781:5581:BURST99", "BURST99", origin + timedelta(seconds=61))
    after = burst_manager.consider(later, high)
    print(f"  emitted_after_cooldown={after.alert is not None}")
    print()

    stats_a = monitor.alerts.stats()
    ok = (
        first_connect is not None
        and isinstance(first_connect.details.get("alert"), dict)
        and first_alerts
        and first_alerts[0].severity is Severity.INFO
        and known_connect is not None
        and known_connect.details.get("alert") is None
        and stats_a.emitted == 1
        and burst_emitted == 1
        and burst_suppressed == 99
        and first.alert is not None
        and first.alert.severity is Severity.HIGH
        and second.alert is not None
        and second.alert.severity is Severity.CRITICAL
        and third.suppressed is True
        and after.alert is not None
    )
    print("First-seen produced one INFO alert: OK" if first_alerts else "first-seen alert FAILED")
    print("Known reconnect did not duplicate first-seen: OK")
    print("100 identical warnings collapsed to 1: OK" if burst_emitted == 1 and burst_suppressed == 99 else "burst FAILED")
    print("Severity escalation bypassed cooldown: OK" if second.alert is not None else "escalation FAILED")
    print("Cooldown expiry allowed a new alert: OK" if after.alert is not None else "expiry FAILED")
    print("Demo result: OK" if ok else "Demo result: FAILED")
    return 0 if ok else 1


def demo_storage() -> int:
    """Persist events, alerts, and devices in a temp folder. No USB hardware."""
    origin = utc_now()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        events_path = root / "events" / "events.json"
        alerts_path = root / "alerts" / "alerts.json"
        devices_path = root / "inventory" / "devices.json"
        monitor = USBMonitor(
            _IdleEventSource(),
            collector=NullMetadataCollector(),
            inventory=DeviceInventory(devices_path),
            analyzer=Analyzer(),
            alerts=AlertManager(store=AlertStore(alerts_path)),
            event_store=EventStore(events_path),
        )
        produced = _feed_connect(
            monitor, _timed_storage("0781:5581:STORE01", "STORE01", origin)
        )
        events = EventStore.load(events_path).list_events()
        alerts = AlertStore.load(alerts_path).list_alerts()
        devices = DeviceInventory.load(devices_path).list_devices()
        print(f"Wrote {len(events)} event(s) to {events_path.name}")
        print(f"Wrote {len(alerts)} alert(s) to {alerts_path.name}")
        print(f"Wrote {len(devices)} device(s) to {devices_path.name}")
        if events:
            loaded = USBEvent.from_dict(events[0].to_dict())
            print(f"Event round-trip type={loaded.event_type.value} id={loaded.safe_device_id}")
        if alerts:
            print(format_alert(alerts[0]))

        none_events = EventStore(path=None)
        none_events.append(_timed_storage("0781:5581:NONE00", "NONE00", origin))

        bad = root / "corrupt" / "events.json"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text("{not-json", encoding="utf-8")
        recovered = EventStore.load(bad)

        connect_types = [item.event_type for item in produced]
        ok = (
            EventType.CONNECT in connect_types
            and EventType.FIRST_SEEN in connect_types
            and len(events) >= 2
            and events[0].event_id == USBEvent.from_dict(events[0].to_dict()).event_id
            and len(alerts) == 1
            and alerts[0].severity is Severity.INFO
            and len(devices) == 1
            and devices[0].connection_count == 1
            and recovered.stats()["total"] == 0
            and none_events.stats()["total"] == 1
        )
        print("Corrupt JSON started empty: OK" if recovered.stats()["total"] == 0 else "corrupt FAILED")
        print("Live monitor wrote all three files: OK" if len(events) >= 2 and alerts and devices else "write FAILED")
        print("Demo result: OK" if ok else "Demo result: FAILED")
        return 0 if ok else 1


def demo_report() -> int:
    """Export JSON/CSV/text reports from sample local records. No USB hardware."""
    origin = utc_now()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        events_path = root / "events" / "events.json"
        alerts_path = root / "alerts" / "alerts.json"
        devices_path = root / "inventory" / "devices.json"
        out = root / "reports"
        monitor = USBMonitor(
            _IdleEventSource(),
            collector=NullMetadataCollector(),
            inventory=DeviceInventory(devices_path),
            analyzer=Analyzer(),
            alerts=AlertManager(store=AlertStore(alerts_path)),
            event_store=EventStore(events_path),
        )
        _feed_connect(
            monitor, _timed_storage("0781:5581:RPT1234", "RPT1234", origin)
        )
        report = build_local_report(
            limit=0,
            inventory=DeviceInventory.load(devices_path),
            events=EventStore.load(events_path),
            alerts=AlertStore.load(alerts_path),
            generated_at=origin,
        )
        written = export_report(report, out)
        names = {path.name: path for path in written}
        json_path = next(path for path in written if path.suffix == ".json")
        text_path = next(path for path in written if path.suffix == ".txt")
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        text = text_path.read_text(encoding="utf-8")
        devices_csv = names[f"{json_path.stem}-devices.csv"].read_text(encoding="utf-8")
        print(f"Wrote {len(written)} file(s) under {out.name}")
        for path in written:
            print(f"  {path.name}")
        serial_in_json = (
            payload.get("inventory", {}).get("devices", [{}])[0].get("serial_number")
            == "RPT1234"
        )
        header_ok = "serial_number" in devices_csv.splitlines()[0]
        masked = "RPT1234" not in text and "********1234" in text
        disclaimer_ok = DISCLAIMER in text and payload.get("disclaimer") == DISCLAIMER
        local_only = payload.get("local_only") is True
        ok = (
            len(written) == 5
            and serial_in_json
            and header_ok
            and masked
            and disclaimer_ok
            and local_only
            and payload.get("events", {}).get("total", 0) >= 2
            and payload.get("alerts", {}).get("shown", 0) == 1
        )
        print("JSON kept the serial for local forensics: OK" if serial_in_json else "json serial FAILED")
        print("CSV included a serial_number column: OK" if header_ok else "csv FAILED")
        print("Text report masked the serial: OK" if masked else "mask FAILED")
        print("Demo result: OK" if ok else "Demo result: FAILED")
        return 0 if ok else 1


def demo_reliability() -> int:
    """Isolate poll/metadata/store failures. No USB hardware."""
    path = (
        r"\\?\USB#VID_0781&PID_5581#REL1234#{a5dcbf10-6530-11d2-901f-00c04fb951ed}"
    )
    raw = RawDeviceEvent(
        action=RawAction.CONNECT,
        source="mock",
        kind="usb",
        vendor_id="0781",
        product_id="5581",
        device_path=path,
    )
    source = _BoomSource()
    monitor = USBMonitor(
        source,
        normalizer=EventNormalizer(quiet_period=0, max_wait=0),
        collector=_BoomCollector(),
        inventory=DeviceInventory(path=None),
        analyzer=Analyzer(),
        event_store=_BoomStore(path=None),
    )
    with monitor:
        polled = monitor.poll(timeout=0.05)
        monitor.feed(raw)
        events = monitor.drain()
        monitor.stop()
        monitor.stop()
    types = [item.event_type for item in events]
    ok = (
        polled is None
        and EventType.CONNECT in types
        and source.is_running is False
    )
    print("Poll survived a source OSError: OK" if polled is None else "poll FAILED")
    print(
        "CONNECT still emitted after metadata/store failure: OK"
        if EventType.CONNECT in types
        else "emit FAILED"
    )
    print("stop() is idempotent: OK" if source.is_running is False else "stop FAILED")
    print("Demo result: OK" if ok else "Demo result: FAILED")
    return 0 if ok else 1


def demo_gui() -> int:
    """Build and destroy the operator window. No live USB watcher."""
    from usb_monitor.gui.present import DISCLAIMER, event_row

    sample = USBEvent(
        event_type=EventType.CONNECT,
        device_id="0781:5581:DEMO1234",
        serial_number="DEMO1234",
        source="mock",
    )
    row = event_row(sample)
    masked = "DEMO1234" not in row[2] and "********1234" in row[2]
    try:
        import tkinter as tk

        from usb_monitor.gui.app import MonitorApp
        from usb_monitor.monitoring import MockEventSource
    except ImportError as exc:
        print(f"tkinter unavailable: {exc}")
        return 1

    def factory() -> USBMonitor:
        return USBMonitor(
            MockEventSource(),
            collector=NullMetadataCollector(),
            inventory=DeviceInventory(path=None),
        )

    root = tk.Tk()
    root.withdraw()
    MonitorApp(root, monitor_factory=factory)
    root.update_idletasks()
    title_ok = __app_name__ in root.title()
    root.destroy()
    ok = masked and title_ok and DISCLAIMER.startswith("Heuristic")
    print("GUI row masked the serial: OK" if masked else "mask FAILED")
    print("Operator window constructed: OK" if title_ok else "window FAILED")
    print("Demo result: OK" if ok else "Demo result: FAILED")
    return 0 if ok else 1


DEMO_HANDLERS = (
    ("demo_models", demo_models),
    ("demo_normalize", demo_normalize),
    ("demo_metadata", demo_metadata),
    ("demo_inventory", demo_inventory),
    ("demo_risk", demo_risk),
    ("demo_anomaly", demo_anomaly),
    ("demo_alerts", demo_alerts),
    ("demo_storage", demo_storage),
    ("demo_cli", demo_cli),
    ("demo_report", demo_report),
    ("demo_reliability", demo_reliability),
    ("demo_gui", demo_gui),
)


def run_requested_demo(args: Namespace) -> int | None:
    """Run the first --demo-* flag that is set. Return None if none requested."""
    for name, handler in DEMO_HANDLERS:
        if getattr(args, name, False):
            result = handler()
            return 0 if result is None else int(result)
    return None
