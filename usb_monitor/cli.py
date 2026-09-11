"""Command-line interface for USB Security Monitor.

Subcommands are the Phase 12 surface. Older top-level flags remain as
aliases so existing scripts keep working. This module lists local
records; JSON/CSV report files belong to a later phase.
"""

from __future__ import annotations

import argparse
from typing import Any

from usb_monitor import __app_name__, __version__
from usb_monitor.inventory import DeviceInventory, format_device_row
from usb_monitor.models.alert import Alert
from usb_monitor.models.enums import EventType, Severity, parse_enum
from usb_monitor.models.event import USBEvent
from usb_monitor.storage import AlertStore, EventStore

DEFAULT_LIST_LIMIT = 50
DEFAULT_REPORT_LIMIT = 20


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse flags and optional subcommands."""
    parser = argparse.ArgumentParser(
        prog="usb-security-monitor",
        description=(
            "Defensive endpoint-security tool that monitors USB and "
            "removable-storage activity on the local computer you are "
            "authorized to administer."
        ),
        epilog=(
            "Commands: status, monitor, devices, events, alerts, report, "
            "trust, untrust. Legacy flags such as --status and --monitor "
            "still work. This tool does not exploit devices, execute USB "
            "contents, or send data off the local machine."
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
        help="Listen duration for --listen-source and monitor (default: 15).",
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
        "--demo-risk",
        action="store_true",
        help="Run rule-based risk scoring scenarios without USB hardware.",
    )
    parser.add_argument(
        "--demo-anomaly",
        action="store_true",
        help="Run reconnect/new-device window scenarios without USB hardware.",
    )
    parser.add_argument(
        "--demo-alerts",
        action="store_true",
        help="Run alert generation, dedup, and cooldown scenarios without USB hardware.",
    )
    parser.add_argument(
        "--demo-storage",
        action="store_true",
        help="Round-trip events.json / alerts.json / devices.json without USB hardware.",
    )
    parser.add_argument(
        "--demo-cli",
        action="store_true",
        help="Verify subcommand parsing without USB hardware.",
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

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.add_parser("status", help="Show platform and local storage status.")

    monitor_cmd = subparsers.add_parser(
        "monitor",
        help="Listen for coalesced USB CONNECT/DISCONNECT events.",
    )
    monitor_cmd.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        dest="command_timeout",
        help="Listen duration in seconds (default: same as --timeout).",
    )

    subparsers.add_parser("devices", help="List the local device inventory.")

    events_cmd = subparsers.add_parser("events", help="List persisted USB events (newest first).")
    events_cmd.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIST_LIMIT,
        metavar="N",
        help=f"Maximum rows to print (default: {DEFAULT_LIST_LIMIT}; 0 = all).",
    )
    events_cmd.add_argument(
        "--type",
        dest="event_type",
        metavar="TYPE",
        help="Filter by event type (CONNECT, DISCONNECT, FIRST_SEEN, ...).",
    )

    alerts_cmd = subparsers.add_parser("alerts", help="List persisted alerts (newest first).")
    alerts_cmd.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIST_LIMIT,
        metavar="N",
        help=f"Maximum rows to print (default: {DEFAULT_LIST_LIMIT}; 0 = all).",
    )
    alerts_cmd.add_argument(
        "--severity",
        dest="alert_severity",
        metavar="LEVEL",
        help="Filter by severity (INFO, LOW, MEDIUM, HIGH, CRITICAL).",
    )

    report_cmd = subparsers.add_parser(
        "report",
        help="Print a local human-readable summary of inventory, events, and alerts.",
    )
    report_cmd.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_REPORT_LIMIT,
        metavar="N",
        help=f"Rows per section (default: {DEFAULT_REPORT_LIMIT}; 0 = all).",
    )

    trust_cmd = subparsers.add_parser(
        "trust",
        help="Mark a known inventory identity as trusted.",
    )
    trust_cmd.add_argument("device_id", help="Device identity (for example VID:PID:SERIAL).")

    untrust_cmd = subparsers.add_parser(
        "untrust",
        help="Remove trusted status from a known inventory identity.",
    )
    untrust_cmd.add_argument("device_id", help="Device identity (for example VID:PID:SERIAL).")

    parser.set_defaults(
        command=None,
        device_id=None,
        limit=None,
        event_type=None,
        alert_severity=None,
        command_timeout=None,
    )
    return parser.parse_args(argv)


def resolve_command(args: argparse.Namespace) -> str | None:
    """Map a subcommand or a legacy flag onto one command name."""
    if args.command:
        return args.command
    if args.status:
        return "status"
    if args.monitor:
        return "monitor"
    if args.devices:
        return "devices"
    if args.trust:
        return "trust"
    if args.untrust:
        return "untrust"
    return None


def monitor_timeout(args: argparse.Namespace) -> float:
    """Prefer the monitor subcommand timeout when it was provided."""
    extra = getattr(args, "command_timeout", None)
    if extra is not None:
        return extra
    return float(args.timeout)


def trust_device_id(args: argparse.Namespace) -> str | None:
    if args.command == "trust":
        return args.device_id
    return args.trust


def untrust_device_id(args: argparse.Namespace) -> str | None:
    if args.command == "untrust":
        return args.device_id
    return args.untrust


def format_event_row(event: USBEvent) -> str:
    """One-line event listing with a masked identity."""
    risk = ""
    if event.risk_level is not None and event.risk_score is not None:
        risk = f"  risk={event.risk_level.value}({event.risk_score})"
    return (
        f"{event.display_timestamp}  {event.event_type.value}  "
        f"{event.safe_device_id}{risk}"
    )


def format_alert_row(alert: Alert) -> str:
    """One-line alert listing with a masked identity."""
    return (
        f"{alert.display_timestamp}  {alert.severity.value}  "
        f"{alert.title}  {alert.safe_device_id}"
    )


def _apply_limit(items: list[Any], limit: int | None) -> list[Any]:
    newest_first = list(reversed(items))
    if limit is None or limit == 0:
        return newest_first
    if limit < 0:
        raise ValueError("limit must be >= 0")
    return newest_first[:limit]


def list_events(*, limit: int | None = DEFAULT_LIST_LIMIT, event_type: str | None = None) -> int:
    """Print persisted events. Does not open USB files."""
    store = EventStore.load()
    events = store.list_events()
    if event_type:
        try:
            parsed = parse_enum(EventType, event_type.upper())
        except ValueError:
            print(f"Unknown event type: {event_type}")
            return 2
        events = [item for item in events if item.event_type is parsed]
    try:
        rows = _apply_limit(events, limit)
    except ValueError as exc:
        print(exc)
        return 2
    print(f"Local events: {len(events)} shown={len(rows)} (newest first)")
    if not rows:
        print("(empty)")
        return 0
    for event in rows:
        print(format_event_row(event))
    return 0


def list_alerts(*, limit: int | None = DEFAULT_LIST_LIMIT, severity: str | None = None) -> int:
    """Print persisted alerts. Suppressed cooldown hits are not stored."""
    store = AlertStore.load()
    alerts = store.list_alerts()
    if severity:
        try:
            parsed = parse_enum(Severity, severity.upper())
        except ValueError:
            print(f"Unknown severity: {severity}")
            return 2
        alerts = [item for item in alerts if item.severity is parsed]
    try:
        rows = _apply_limit(alerts, limit)
    except ValueError as exc:
        print(exc)
        return 2
    print(f"Local alerts: {len(alerts)} shown={len(rows)} (newest first)")
    if not rows:
        print("(empty)")
        return 0
    for alert in rows:
        print(format_alert_row(alert))
    return 0


def print_report(*, limit: int | None = DEFAULT_REPORT_LIMIT) -> int:
    """Human-readable local summary. Not a JSON/CSV export."""
    inventory = DeviceInventory.load()
    stats = inventory.stats()
    events = EventStore.load().list_events()
    alerts = AlertStore.load().list_alerts()
    try:
        event_rows = _apply_limit(events, limit)
        alert_rows = _apply_limit(alerts, limit)
    except ValueError as exc:
        print(exc)
        return 2
    lines = [
        f"{__app_name__} local summary",
        "",
        f"Inventory: {stats['total']} device(s), {stats['trusted']} trusted",
        f"Events: {len(events)} (showing {len(event_rows)})",
        f"Alerts: {len(alerts)} (showing {len(alert_rows)})",
        "Heuristic scores are not a malware verdict.",
        "",
        "Devices:",
    ]
    devices = inventory.list_devices()
    if limit is None or limit == 0:
        shown_devices = devices
    elif limit < 0:
        print("limit must be >= 0")
        return 2
    else:
        shown_devices = devices[:limit]
    if not shown_devices:
        lines.append("  (empty)")
    else:
        for device in shown_devices:
            lines.append(f"  {format_device_row(device)}")
    lines.extend(["", "Recent events:"])
    if not event_rows:
        lines.append("  (empty)")
    else:
        for event in event_rows:
            lines.append(f"  {format_event_row(event)}")
    lines.extend(["", "Recent alerts:"])
    if not alert_rows:
        lines.append("  (empty)")
    else:
        for alert in alert_rows:
            lines.append(f"  {format_alert_row(alert)}")
    lines.extend(
        [
            "",
            "This is a local console summary. JSON/CSV file export is a later phase.",
            "--------------------------------",
        ]
    )
    print("\n".join(lines))
    return 0


def demo_cli() -> int:
    """Verify subcommand and legacy-flag parsing. No USB hardware."""
    checks: list[tuple[str, bool]] = []

    status = parse_args(["status"])
    checks.append(("subcommand status", resolve_command(status) == "status"))

    flag_status = parse_args(["--status"])
    checks.append(("flag --status", resolve_command(flag_status) == "status"))

    monitor = parse_args(["monitor", "--timeout", "7"])
    checks.append(
        (
            "monitor --timeout 7",
            resolve_command(monitor) == "monitor" and monitor_timeout(monitor) == 7.0,
        )
    )

    legacy_monitor = parse_args(["--monitor", "--timeout", "9"])
    checks.append(
        (
            "flag --monitor --timeout 9",
            resolve_command(legacy_monitor) == "monitor"
            and monitor_timeout(legacy_monitor) == 9.0,
        )
    )

    prefix_timeout = parse_args(["--timeout", "11", "monitor"])
    checks.append(
        (
            "--timeout 11 monitor",
            resolve_command(prefix_timeout) == "monitor"
            and monitor_timeout(prefix_timeout) == 11.0,
        )
    )

    trust = parse_args(["trust", "0781:5581:DEMO1234"])
    checks.append(
        (
            "trust positional",
            resolve_command(trust) == "trust"
            and trust_device_id(trust) == "0781:5581:DEMO1234",
        )
    )

    flag_trust = parse_args(["--trust", "0781:5581:DEMO1234"])
    checks.append(
        (
            "flag --trust",
            resolve_command(flag_trust) == "trust"
            and trust_device_id(flag_trust) == "0781:5581:DEMO1234",
        )
    )

    untrust = parse_args(["untrust", "0781:5581:DEMO1234"])
    checks.append(
        (
            "untrust positional",
            resolve_command(untrust) == "untrust"
            and untrust_device_id(untrust) == "0781:5581:DEMO1234",
        )
    )

    events = parse_args(["events", "--limit", "3", "--type", "CONNECT"])
    checks.append(
        (
            "events --limit/--type",
            resolve_command(events) == "events"
            and events.limit == 3
            and events.event_type == "CONNECT",
        )
    )

    alerts = parse_args(["alerts", "--severity", "HIGH"])
    checks.append(
        (
            "alerts --severity",
            resolve_command(alerts) == "alerts" and alerts.alert_severity == "HIGH",
        )
    )

    report = parse_args(["report", "--limit", "5"])
    checks.append(
        (
            "report --limit",
            resolve_command(report) == "report" and report.limit == 5,
        )
    )

    devices = parse_args(["devices"])
    checks.append(("subcommand devices", resolve_command(devices) == "devices"))

    flag_devices = parse_args(["--devices"])
    checks.append(("flag --devices", resolve_command(flag_devices) == "devices"))

    none = parse_args([])
    checks.append(("no command", resolve_command(none) is None))

    ok = True
    for label, passed in checks:
        print(f"{label}: {'OK' if passed else 'FAILED'}")
        if not passed:
            ok = False
    print("Demo result: OK" if ok else "Demo result: FAILED")
    return 0 if ok else 1
