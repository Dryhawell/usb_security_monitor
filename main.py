"""USB Security Monitor entry point.

Phase 7 adds a local device inventory (first seen / known / trusted).
Risk analysis is still deferred.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

from usb_monitor import __app_name__, __version__
from usb_monitor.inventory import DeviceInventory, DeviceNotFoundError, format_device_row
from usb_monitor.models import (
    Alert,
    Device,
    DeviceType,
    EventType,
    InterfaceType,
    Severity,
    USBEvent,
)
from usb_monitor.monitoring import (
    DeviceMetadata,
    EventNormalizer,
    EventSourceUnavailableError,
    NullMetadataCollector,
    RawAction,
    RawDeviceEvent,
    WindowsEventSource,
    WindowsMetadataCollector,
    apply_metadata,
    create_event_source,
    create_monitor,
    device_path_to_instance_id,
    format_live_event,
    list_removable_drive_letters,
)
from usb_monitor.utils.logger import get_logger, setup_logging
from usb_monitor.utils.permissions import (
    PermissionStatus,
    check_permissions,
    format_elevation,
)
from usb_monitor.utils.platform import (
    PlatformInfo,
    UnsupportedPlatformError,
    detect_platform,
)
from usb_monitor.utils.time import utc_now


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for the current phase skeleton."""
    parser = argparse.ArgumentParser(
        prog="usb-security-monitor",
        description=(
            "Defensive endpoint-security tool that monitors USB and "
            "removable-storage activity on the local computer you are "
            "authorized to administer."
        ),
        epilog=(
            "This tool does not exploit devices, execute USB contents, "
            "or send data off the local machine."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__app_name__} {__version__}",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging on the console.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Show warnings and errors only on the console.",
    )
    parser.add_argument(
        "--demo-models",
        action="store_true",
        help="Print sample Device, USBEvent, and Alert JSON (no USB access).",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show platform, permission, and monitoring-capability status.",
    )
    parser.add_argument(
        "--probe-source",
        action="store_true",
        help="Start and stop the Windows event source without waiting for USB devices.",
    )
    parser.add_argument(
        "--listen-source",
        action="store_true",
        help="Listen for raw WM_DEVICECHANGE events (does not execute USB files).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        metavar="SECONDS",
        help="Listen duration for --listen-source and --monitor (default: 15).",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Show coalesced CONNECT/DISCONNECT events (does not execute USB files).",
    )
    parser.add_argument(
        "--demo-normalize",
        action="store_true",
        help="Run sample raw-event coalescing without USB hardware.",
    )
    parser.add_argument(
        "--demo-metadata",
        action="store_true",
        help="Run sample metadata merge without USB hardware.",
    )
    parser.add_argument(
        "--probe-metadata",
        action="store_true",
        help="Inspect currently mounted removable volumes (does not open USB files).",
    )
    parser.add_argument(
        "--demo-inventory",
        action="store_true",
        help="Run first-seen / known / trusted inventory scenarios without USB hardware.",
    )
    parser.add_argument(
        "--devices",
        action="store_true",
        help="List locally observed devices from inventory.",
    )
    parser.add_argument(
        "--trust",
        metavar="DEVICE_ID",
        help="Mark a known device as trusted (does not hide future events).",
    )
    parser.add_argument(
        "--untrust",
        metavar="DEVICE_ID",
        help="Remove trusted status from a known device.",
    )
    return parser.parse_args(argv)


def format_status(info: PlatformInfo, perms: PermissionStatus) -> str:
    """Build a human-readable local status report. No device data included."""
    live = "supported (not started yet)" if info.live_monitoring_supported else "not supported"
    if WindowsEventSource.is_available():
        source_label = "windows_wm_devicechange (idle)"
    else:
        source_label = "unavailable on this platform"
    stats = DeviceInventory.load().stats()
    inventory_line = f"{stats['total']} device(s), {stats['trusted']} trusted"
    lines = [
        f"{__app_name__} v{__version__}",
        "",
        "Platform",
        f"  OS: {info.display_name}",
        f"  Architecture: {info.architecture}",
        f"  Python: {info.python_version}",
        f"  Live USB monitoring: {live}",
        f"  Event source: {source_label}",
        f"  USBMonitor: ready (coalesced CONNECT/DISCONNECT)",
        f"  Metadata: {'windows_setupapi' if WindowsEventSource.is_available() else 'none'}",
        f"  Inventory: {inventory_line}",
        f"  PowerShell on PATH: {'Yes' if info.powershell_available else 'No'}",
        "",
        "Permissions",
        f"  Elevated administrator: {format_elevation(perms.is_elevated)}",
        f"  data/ writable: {'Yes' if perms.data_writable else 'No'}",
        f"  logs/ writable: {'Yes' if perms.logs_writable else 'No'}",
        "",
        "Notes",
    ]
    for note in info.notes:
        lines.append(f"  - {note}")
    if perms.is_elevated is False:
        lines.append(
            "  - Running as a standard user is expected. Elevation is optional."
        )
    for issue in perms.issues:
        lines.append(f"  - {issue}")
    return "\n".join(lines)


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


def probe_event_source() -> int:
    """Verify the native source can start and stop. Does not need a USB device."""
    try:
        source = create_event_source()
        source.start()
    except (UnsupportedPlatformError, EventSourceUnavailableError) as exc:
        print(f"Event source unavailable: {exc}")
        return 1
    try:
        time.sleep(0.3)
        running = source.is_running
        print(f"Mechanism: {source.mechanism}")
        print(f"Running: {running}")
        print("Probe result: OK" if running else "Probe result: FAILED")
        return 0 if running else 1
    finally:
        source.stop()


def listen_event_source(timeout: float) -> int:
    """Print raw OS events until timeout. Does not open or run USB files."""
    if timeout < 0:
        print("timeout must be >= 0")
        return 2
    print(f"Listening via windows_wm_devicechange for {timeout:.0f}s.")
    print("Plug or unplug authorized USB storage to see RAW events.")
    print("No files on the device will be opened or executed. Ctrl+C to stop.")
    print()
    try:
        source = create_event_source()
        source.start()
    except (UnsupportedPlatformError, EventSourceUnavailableError) as exc:
        print(f"Event source unavailable: {exc}")
        return 1
    seen = 0
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            event = source.poll(timeout=min(0.5, remaining))
            if event is None:
                continue
            seen += 1
            print(event.format_console())
    finally:
        source.stop()
    print()
    print(f"Raw events observed: {seen}")
    return 0


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
    disk_path = r"\\?\USBSTOR#Disk&Ven_Generic&Prod_Storage#DEMO1234&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
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
            device_path=disk_path,
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
    ok = len(events) == 1 and events[0].event_type is EventType.CONNECT and not dropped
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


def probe_metadata() -> int:
    """Look up currently mounted removable volumes. Does not open files."""
    letters = list_removable_drive_letters()
    print("Currently mounted removable volumes:")
    if not letters:
        print("  (none)")
        print("Plug authorized USB storage and re-run, or use --monitor to catch CONNECT.")
        return 0
    collector = WindowsMetadataCollector()
    for letter in letters:
        meta = collector.collect_drive(letter)
        print(f"  {letter} manufacturer={meta.manufacturer or 'Unknown'} "
              f"fs={meta.filesystem or 'Unknown'} "
              f"removable={meta.removable}")
        print(f"      {meta.to_dict()}")
    return 0


def run_monitor(timeout: float) -> int:
    """Listen for coalesced CONNECT/DISCONNECT events. Does not touch USB files."""
    if timeout < 0:
        print("timeout must be >= 0")
        return 2
    print(f"USBMonitor listening for {timeout:.0f}s.")
    print("Plug or unplug authorized USB storage.")
    print("No files on the device will be opened or executed. Ctrl+C to stop.")
    print()
    try:
        monitor = create_monitor()
        monitor.start()
    except (UnsupportedPlatformError, EventSourceUnavailableError) as exc:
        print(f"USB monitor unavailable: {exc}")
        return 1
    seen = 0
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            event = monitor.poll(timeout=min(0.5, remaining))
            if event is None:
                continue
            seen += 1
            print(format_live_event(event))
            print()
    finally:
        monitor.stop()
        for event in monitor.drain():
            seen += 1
            print(format_live_event(event))
            print()
    print(f"Logical USB events observed: {seen}")
    return 0


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


def list_inventory() -> int:
    inventory = DeviceInventory.load()
    stats = inventory.stats()
    print(f"Local inventory: {stats['total']} device(s), {stats['trusted']} trusted")
    devices = inventory.list_devices()
    if not devices:
        print("(empty)")
        return 0
    for device in devices:
        print(format_device_row(device))
    return 0


def change_trust(device_id: str, trusted: bool) -> int:
    inventory = DeviceInventory.load()
    try:
        device = inventory.set_trusted(device_id, trusted)
    except DeviceNotFoundError:
        print(f"Device not in inventory: {device_id}")
        print("Observe it with --monitor first, then trust/untrust.")
        return 1
    state = "trusted" if device.trusted else "untrusted"
    print(f"{device.safe_device_id} is now {state}.")
    print("Trusted status does not hide CONNECT/DISCONNECT events.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the current-phase application skeleton."""
    args = parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    logger = get_logger("main")

    logger.info("%s %s started", __app_name__, __version__)
    logger.info("Phase 7: local device inventory (first seen / known / trusted)")

    info = detect_platform()
    perms = check_permissions()
    logger.info("Platform: %s", info.display_name)
    if not info.live_monitoring_supported:
        logger.warning("Live USB monitoring is not supported on this platform")
    if not perms.can_persist:
        logger.error("Local data or log directories are not writable")

    if args.status:
        print(format_status(info, perms))
        return 0 if perms.can_persist else 1

    if args.demo_models:
        demo_models()
        return 0

    if args.demo_normalize:
        return demo_normalize()

    if args.demo_metadata:
        return demo_metadata()

    if args.demo_inventory:
        return demo_inventory()

    if args.devices:
        return list_inventory()

    if args.trust:
        return change_trust(args.trust, True)

    if args.untrust:
        return change_trust(args.untrust, False)

    if args.probe_metadata:
        return probe_metadata()

    if args.probe_source:
        return probe_event_source()

    if args.listen_source:
        return listen_event_source(args.timeout)

    if args.monitor:
        return run_monitor(args.timeout)

    print(f"{__app_name__} v{__version__}")
    print(f"Platform: {info.display_name}")
    print("Phase 7 complete: local inventory tracks first-seen vs known devices.")
    print("Run --demo-inventory (no USB), --devices, or --monitor to update the baseline.")
    return 0 if perms.can_persist else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
