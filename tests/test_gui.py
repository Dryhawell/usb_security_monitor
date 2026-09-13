"""Local GUI helpers and a short-lived tkinter window. No USB hardware."""

import threading

from usb_monitor.gui.present import DISCLAIMER, alert_row, device_row, event_row
from usb_monitor.inventory import DeviceInventory
from usb_monitor.models.alert import Alert
from usb_monitor.models.device import Device
from usb_monitor.models.enums import EventType, Severity
from usb_monitor.models.event import USBEvent
from usb_monitor.monitoring import EventNormalizer, MockEventSource, USBMonitor
from usb_monitor.cli import parse_args, resolve_command


def test_gui_rows_mask_serial() -> None:
    event = USBEvent(
        event_type=EventType.CONNECT,
        device_id="0781:5581:DEMO1234",
        serial_number="DEMO1234",
        source="mock",
    )
    device = Device(
        device_id="0781:5581:DEMO1234",
        serial_number="DEMO1234",
        manufacturer="SanDisk",
        product_name="Ultra USB",
    )
    alert = Alert(
        severity=Severity.INFO,
        title="New USB device observed",
        description="First seen",
        device_id="0781:5581:DEMO1234",
    )
    assert "DEMO1234" not in event_row(event)[2]
    assert "********1234" in event_row(event)[2]
    assert "DEMO1234" not in device_row(device)[0]
    assert "DEMO1234" not in alert_row(alert)[3]
    assert "malware" in DISCLAIMER.lower()


def test_cli_gui_command() -> None:
    assert resolve_command(parse_args(["gui"])) == "gui"
    assert resolve_command(parse_args(["--gui"])) == "gui"


def test_run_until_stop_when() -> None:
    stop = threading.Event()
    stop.set()
    monitor = USBMonitor(
        MockEventSource(),
        normalizer=EventNormalizer(quiet_period=0, max_wait=0),
        inventory=DeviceInventory(path=None),
    )
    seen = monitor.run(None, stop_when=stop.is_set)
    assert seen == 0
    assert monitor.is_running is False


def test_operator_window_constructs_without_usb() -> None:
    import tkinter as tk

    from usb_monitor.gui.app import MonitorApp

    def factory() -> USBMonitor:
        return USBMonitor(
            MockEventSource(),
            inventory=DeviceInventory(path=None),
        )

    root = tk.Tk()
    root.withdraw()
    try:
        MonitorApp(root, monitor_factory=factory)
        root.update_idletasks()
        assert "USB Security Monitor" in root.title()
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass
