"""Model round-trips, serial masking, and CLI parsing."""

from usb_monitor.cli import parse_args, resolve_command
from usb_monitor.models.alert import Alert
from usb_monitor.models.device import Device
from usb_monitor.models.enums import DeviceType, EventType, Severity
from usb_monitor.models.event import USBEvent
from usb_monitor.monitoring.event_source import (
    parse_vid_pid_from_path,
    redact_device_path,
)
from usb_monitor.utils.logger import mask_identifier
from tests.conftest import USB_INTERFACE_PATH


def test_device_event_alert_json_round_trip() -> None:
    device = Device(
        device_id="0781:5581:DEMO1234",
        vendor_id="0781",
        product_id="5581",
        serial_number="DEMO1234",
        manufacturer="SanDisk",
        device_type=DeviceType.USB_STORAGE,
    )
    event = USBEvent(
        event_type=EventType.CONNECT,
        device_id=device.device_id,
        serial_number=device.serial_number,
        vendor_id=device.vendor_id,
        product_id=device.product_id,
        source="mock",
    )
    alert = Alert(
        severity=Severity.INFO,
        title="New USB device observed",
        description="First seen",
        device_id=device.device_id,
        event_id=event.event_id,
    )
    assert Device.from_dict(device.to_dict()).device_id == device.device_id
    assert USBEvent.from_dict(event.to_dict()).event_id == event.event_id
    assert Alert.from_dict(alert.to_dict()).alert_id == alert.alert_id


def test_serial_is_masked_for_console() -> None:
    event = USBEvent(
        event_type=EventType.CONNECT,
        device_id="0781:5581:DEMO1234",
        serial_number="DEMO1234",
        source="mock",
    )
    assert event.safe_device_id == "0781:5581:********1234"
    assert mask_identifier("DEMO1234") == "********1234"
    redacted = redact_device_path(USB_INTERFACE_PATH)
    assert redacted is not None
    assert "DEMO1234" not in redacted
    assert parse_vid_pid_from_path(USB_INTERFACE_PATH) == ("0781", "5581")


def test_cli_subcommands_and_legacy_flags() -> None:
    assert resolve_command(parse_args(["status"])) == "status"
    assert resolve_command(parse_args(["--status"])) == "status"
    report = parse_args(["report", "--export", "--format", "json"])
    assert resolve_command(report) == "report"
    assert report.export_report is True
    assert report.report_format == "json"
    assert resolve_command(parse_args([])) is None
