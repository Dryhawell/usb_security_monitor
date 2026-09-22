"""USB Security Monitor entry point.

v1.1.0: live watching, CLI, reports, and the local GUI are the operator
surface. Offline --demo-* checks live in usb_monitor.demos. Scores are
not a malware verdict.
"""

from __future__ import annotations

import sys
import time

from usb_monitor import __app_name__, __version__
from usb_monitor.cli import (
    list_alerts,
    list_events,
    monitor_timeout,
    parse_args,
    print_report,
    resolve_command,
    trust_device_id,
    untrust_device_id,
)
from usb_monitor.demos import run_requested_demo
from usb_monitor.inventory import DeviceInventory, DeviceNotFoundError, format_device_row
from usb_monitor.models import USBEvent
from usb_monitor.monitoring import (
    EventSourceUnavailableError,
    WindowsEventSource,
    WindowsMetadataCollector,
    create_event_source,
    create_monitor,
    format_live_event,
    list_removable_drive_letters,
)
from usb_monitor.storage import AlertStore, EventStore
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
from usb_monitor.utils.protect import is_protection_enabled


def format_status(info: PlatformInfo, perms: PermissionStatus) -> str:
    """Build a human-readable local status report. No device data included."""
    live = "supported (not started yet)" if info.live_monitoring_supported else "not supported"
    if WindowsEventSource.is_available():
        source_label = "windows_wm_devicechange (idle)"
    else:
        source_label = "unavailable on this platform"
    event_stats = EventStore.load().stats()
    alert_stats = AlertStore.load().stats()
    stats = DeviceInventory.load().stats()
    inventory_line = f"{stats['total']} device(s), {stats['trusted']} trusted"
    storage_line = (
        f"events.json {event_stats['total']}, "
        f"alerts.json {alert_stats['total']}, "
        f"devices.json {stats['total']}"
    )
    lines = [
        f"{__app_name__} v{__version__}",
        "",
        "Platform",
        f"  OS: {info.display_name}",
        f"  Architecture: {info.architecture}",
        f"  Python: {info.python_version}",
        f"  Live USB monitoring: {live}",
        f"  Event source: {source_label}",
        f"  USBMonitor: ready (context manager, isolated failures, graceful stop)",
        f"  Metadata: {'windows_setupapi' if WindowsEventSource.is_available() else 'none'}",
        f"  Inventory: {inventory_line}",
        f"  Risk analyzer: rule-based heuristic (not a malware verdict)",
        f"  Anomaly windows: rapid reconnect / repeated events / multiple new devices",
        f"  Alert manager: in-memory cooldown; emitted alerts persist locally",
        f"  CLI: subcommands (legacy flags such as --status still work)",
        f"  Storage: {storage_line} (local only, owner-only ACL, no telemetry)",
        f"  Store DPAPI: {'on (USB_MONITOR_DPAPI=1)' if is_protection_enabled() else 'off (set USB_MONITOR_DPAPI=1 to encrypt new store writes)'}",
        f"  Reports: JSON/CSV/text under data/reports/ (report --export)",
        f"  GUI: local tkinter window (python main.py gui)",
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
        with create_monitor() as monitor:
            def on_event(event: USBEvent) -> None:
                print(format_live_event(event))
                print()

            seen = monitor.run(timeout, on_event=on_event)
            stats = monitor.alerts.stats()
    except (UnsupportedPlatformError, EventSourceUnavailableError) as exc:
        print(f"USB monitor unavailable: {exc}")
        return 1
    except KeyboardInterrupt:
        print("\nStopping monitor.")
        return 130
    print(f"Logical USB events observed: {seen}")
    print(
        f"Alerts emitted: {stats.emitted}, suppressed: {stats.suppressed} "
        f"(cooldown {stats.cooldown_seconds:.0f}s)"
    )
    return 0


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
        print("Observe it with monitor (or --monitor) first, then trust/untrust.")
        return 1
    state = "trusted" if device.trusted else "untrusted"
    print(f"{device.safe_device_id} is now {state}.")
    print("Trusted status does not hide CONNECT/DISCONNECT events.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Dispatch operator commands and offline demos."""
    args = parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    logger = get_logger("main")

    logger.info("%s %s started", __app_name__, __version__)
    logger.info("v%s: local USB visibility monitor", __version__)

    info = detect_platform()
    perms = check_permissions()
    logger.info("Platform: %s", info.display_name)
    if not info.live_monitoring_supported:
        logger.warning("Live USB monitoring is not supported on this platform")
    if not perms.can_persist:
        logger.error("Local data or log directories are not writable")

    demo_status = run_requested_demo(args)
    if demo_status is not None:
        return demo_status

    if args.probe_metadata:
        return probe_metadata()

    if args.probe_source:
        return probe_event_source()

    if args.listen_source:
        return listen_event_source(args.timeout)

    command = resolve_command(args)
    if command == "status":
        print(format_status(info, perms))
        return 0 if perms.can_persist else 1
    if command == "monitor":
        return run_monitor(monitor_timeout(args))
    if command == "devices":
        return list_inventory()
    if command == "events":
        return list_events(limit=args.limit, event_type=args.event_type)
    if command == "alerts":
        return list_alerts(limit=args.limit, severity=args.alert_severity)
    if command == "report":
        return print_report(
            limit=args.limit,
            export=args.export_report,
            fmt=args.report_format,
            output_dir=args.output_dir,
        )
    if command == "trust":
        device_id = trust_device_id(args)
        if not device_id:
            print("Missing device identity. Usage: python main.py trust DEVICE_ID")
            return 2
        return change_trust(device_id, True)
    if command == "untrust":
        device_id = untrust_device_id(args)
        if not device_id:
            print("Missing device identity. Usage: python main.py untrust DEVICE_ID")
            return 2
        return change_trust(device_id, False)
    if command == "gui":
        from usb_monitor.gui import run_gui

        return run_gui()

    print(f"{__app_name__} v{__version__}")
    print(f"Platform: {info.display_name}")
    print(f"v{__version__}: local USB visibility. See docs/REVIEW.md")
    print("Also: status, monitor, devices, events, alerts, report, trust ID, untrust ID")
    print("Legacy flags such as --status and --monitor still work.")
    return 0 if perms.can_persist else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
