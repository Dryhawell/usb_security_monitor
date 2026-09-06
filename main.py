"""USB Security Monitor entry point.

Phase 4 adds a Windows WM_DEVICECHANGE event source. Full USBMonitor
normalization, inventory, and analysis are still deferred.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from usb_monitor import __app_name__, __version__
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
    EventSourceUnavailableError,
    WindowsEventSource,
    create_event_source,
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
        help="Listen duration for --listen-source (default: 15).",
    )
    return parser.parse_args(argv)


def format_status(info: PlatformInfo, perms: PermissionStatus) -> str:
    """Build a human-readable local status report. No device data included."""
    live = "supported (not started yet)" if info.live_monitoring_supported else "not supported"
    if WindowsEventSource.is_available():
        source_label = "windows_wm_devicechange (idle)"
    else:
        source_label = "unavailable on this platform"
    lines = [
        f"{__app_name__} v{__version__}",
        "",
        "Platform",
        f"  OS: {info.display_name}",
        f"  Architecture: {info.architecture}",
        f"  Python: {info.python_version}",
        f"  Live USB monitoring: {live}",
        f"  Event source: {source_label}",
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


def main(argv: list[str] | None = None) -> int:
    """Run the current-phase application skeleton."""
    args = parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    logger = get_logger("main")

    logger.info("%s %s started", __app_name__, __version__)
    logger.info("Phase 4: Windows event source available; USBMonitor not started")

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

    if args.probe_source:
        return probe_event_source()

    if args.listen_source:
        return listen_event_source(args.timeout)

    print(f"{__app_name__} v{__version__}")
    print(f"Platform: {info.display_name}")
    print("Phase 4 complete: Windows WM_DEVICECHANGE event source is ready.")
    print("Run --probe-source (no USB needed) or --listen-source to wait for RAW events.")
    return 0 if perms.can_persist else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)
