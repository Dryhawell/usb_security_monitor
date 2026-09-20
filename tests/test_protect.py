"""Optional DPAPI wrapping for JSON stores. No USB hardware."""

import json

import pytest

from usb_monitor.models.enums import EventType
from usb_monitor.models.event import USBEvent
from usb_monitor.reports import build_local_report, export_report
from usb_monitor.storage import AlertStore, EventStore, read_json_file, write_json_atomic
from usb_monitor.inventory import DeviceInventory
from usb_monitor.utils.platform import is_windows
from usb_monitor.utils.protect import (
    ENV_NAME,
    is_protected_document,
    is_protection_enabled,
    protect_bytes,
    unprotect_bytes,
    unwrap_document,
)
from usb_monitor.utils.time import utc_now


def _xor_protect(data: bytes) -> bytes:
    return bytes(byte ^ 0x5A for byte in data)


def test_protection_flag_defaults_off(monkeypatch) -> None:
    monkeypatch.delenv(ENV_NAME, raising=False)
    assert is_protection_enabled() is False
    monkeypatch.setenv(ENV_NAME, "1")
    assert is_protection_enabled() is True
    monkeypatch.setenv(ENV_NAME, "no")
    assert is_protection_enabled() is False


def test_wrapped_store_hides_serial_and_round_trips(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(ENV_NAME, "1")
    monkeypatch.setattr("usb_monitor.utils.protect.protect_bytes", _xor_protect)
    monkeypatch.setattr("usb_monitor.utils.protect.unprotect_bytes", _xor_protect)
    path = tmp_path / "events.json"
    payload = {"version": 1, "events": [{"serial_number": "STORE01"}]}
    write_json_atomic(path, payload)
    raw_text = path.read_text(encoding="utf-8")
    assert "STORE01" not in raw_text
    wrapper = json.loads(raw_text)
    assert is_protected_document(wrapper)
    assert read_json_file(path) == payload


def test_plaintext_store_still_loads_when_flag_off(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv(ENV_NAME, raising=False)
    path = tmp_path / "events.json"
    write_json_atomic(path, {"ok": True, "serial_number": "STORE01"})
    text = path.read_text(encoding="utf-8")
    assert "STORE01" in text
    assert read_json_file(path) == {"ok": True, "serial_number": "STORE01"}


def test_corrupt_wrapper_is_empty(tmp_path) -> None:
    path = tmp_path / "events.json"
    path.write_text(
        json.dumps({"protection": "dpapi", "version": 1, "payload": "%%%"}),
        encoding="utf-8",
    )
    assert read_json_file(path) is None


def test_event_store_round_trip_with_protection(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(ENV_NAME, "1")
    monkeypatch.setattr("usb_monitor.utils.protect.protect_bytes", _xor_protect)
    monkeypatch.setattr("usb_monitor.utils.protect.unprotect_bytes", _xor_protect)
    path = tmp_path / "events.json"
    event = USBEvent(
        event_type=EventType.CONNECT,
        device_id="0781:5581:STORE01",
        serial_number="STORE01",
        timestamp=utc_now(),
        source="mock",
    )
    EventStore(path).append(event)
    assert "STORE01" not in path.read_text(encoding="utf-8")
    loaded = EventStore.load(path)
    assert loaded.list_events()[0].serial_number == "STORE01"


def test_report_json_stays_plaintext_when_dpapi_on(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(ENV_NAME, "1")
    monkeypatch.setattr("usb_monitor.utils.protect.protect_bytes", _xor_protect)
    monkeypatch.setattr("usb_monitor.utils.protect.unprotect_bytes", _xor_protect)
    devices_path = tmp_path / "devices.json"
    events_path = tmp_path / "events.json"
    inventory = DeviceInventory(devices_path)
    events = EventStore(events_path)
    event = USBEvent(
        event_type=EventType.CONNECT,
        device_id="0781:5581:RPT1234",
        serial_number="RPT1234",
        timestamp=utc_now(),
        source="mock",
    )
    inventory.observe(event)
    events.append(event)
    report = build_local_report(
        limit=0,
        inventory=DeviceInventory.load(devices_path),
        events=EventStore.load(events_path),
        alerts=AlertStore(path=None),
    )
    written = export_report(report, tmp_path / "reports", formats=("json",))
    json_path = written[0]
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["inventory"]["devices"][0]["serial_number"] == "RPT1234"
    assert "RPT1234" in json_path.read_text(encoding="utf-8")


def test_unwrap_leaves_plain_documents() -> None:
    assert unwrap_document({"events": []}) == {"events": []}
    assert is_protected_document({"events": []}) is False


@pytest.mark.skipif(not is_windows(), reason="DPAPI is Windows-only")
def test_windows_dpapi_round_trip() -> None:
    secret = b'{"serial_number":"STORE01"}'
    recovered = unprotect_bytes(protect_bytes(secret))
    assert recovered == secret
