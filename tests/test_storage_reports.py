"""Local JSON stores, atomic writes, and report export."""

import json

import pytest

from usb_monitor.models.enums import EventType, Severity
from usb_monitor.models.event import USBEvent
from usb_monitor.models.alert import Alert
from usb_monitor.reports import build_local_report, export_report
from usb_monitor.storage import AlertStore, EventStore, keep_newest, read_json_file
from usb_monitor.inventory import DeviceInventory
from usb_monitor.utils.time import utc_now


def test_event_store_round_trip_and_corrupt_file(tmp_path) -> None:
    path = tmp_path / "events.json"
    store = EventStore(path)
    event = USBEvent(
        event_type=EventType.CONNECT,
        device_id="0781:5581:STORE01",
        serial_number="STORE01",
        timestamp=utc_now(),
        source="mock",
    )
    store.append(event)
    loaded = EventStore.load(path)
    assert loaded.stats()["total"] == 1
    assert loaded.list_events()[0].event_id == event.event_id

    path.write_text("{not-json", encoding="utf-8")
    recovered = EventStore.load(path)
    assert recovered.stats()["total"] == 0
    assert read_json_file(path) is None


def test_alert_store_skips_suppressed_by_never_appending(tmp_path) -> None:
    path = tmp_path / "alerts.json"
    store = AlertStore(path)
    store.append(
        Alert(
            severity=Severity.INFO,
            title="New USB device observed",
            description="First seen",
            device_id="0781:5581:STORE01",
        )
    )
    assert AlertStore.load(path).stats()["total"] == 1


def test_report_export_masks_text_keeps_json_serial(tmp_path) -> None:
    devices_path = tmp_path / "devices.json"
    events_path = tmp_path / "events.json"
    inventory = DeviceInventory(devices_path)
    events = EventStore(events_path)
    event = USBEvent(
        event_type=EventType.CONNECT,
        device_id="0781:5581:RPT1234",
        serial_number="RPT1234",
        manufacturer="SanDisk",
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
    written = export_report(report, tmp_path / "reports")
    names = {path.name: path for path in written}
    payload = json.loads(next(path for path in written if path.suffix == ".json").read_text(encoding="utf-8"))
    text = next(path for path in written if path.suffix == ".txt").read_text(encoding="utf-8")
    assert payload["inventory"]["devices"][0]["serial_number"] == "RPT1234"
    assert payload["local_only"] is True
    assert "RPT1234" not in text
    assert "********1234" in text
    assert "serial_number" in names[f"{report_stem_from(written)}-devices.csv"].read_text(encoding="utf-8")


def test_keep_newest_drops_oldest() -> None:
    assert keep_newest(["a", "b", "c"], 2) == (["b", "c"], 1)
    assert keep_newest(["a"], 5) == (["a"], 0)
    with pytest.raises(ValueError, match="max_records"):
        keep_newest(["a"], 0)


def test_event_store_keeps_newest_within_cap(tmp_path) -> None:
    path = tmp_path / "events.json"
    store = EventStore(path, max_records=3)
    ids: list[str] = []
    for index in range(5):
        serial = f"CAP{index:04d}"
        event = USBEvent(
            event_type=EventType.CONNECT,
            device_id=f"0781:5581:{serial}",
            serial_number=serial,
            source="mock",
        )
        ids.append(event.event_id)
        store.append(event)
    kept = [event.event_id for event in store.list_events()]
    assert kept == ids[-3:]
    assert store.stats()["max_records"] == 3
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert [row["event_id"] for row in payload["events"]] == ids[-3:]
    assert payload["events"][-1]["serial_number"] == "CAP0004"
    loaded = EventStore.load(path, max_records=3)
    assert [event.event_id for event in loaded.list_events()] == ids[-3:]


def test_event_store_trims_oversized_file_on_load(tmp_path) -> None:
    path = tmp_path / "events.json"
    store = EventStore(path, max_records=10)
    ids: list[str] = []
    for index in range(4):
        event = USBEvent(
            event_type=EventType.CONNECT,
            device_id=f"0781:5581:OLD{index}",
            serial_number=f"OLD{index}",
            source="mock",
        )
        ids.append(event.event_id)
        store.append(event)
    trimmed = EventStore.load(path, max_records=2)
    assert [event.event_id for event in trimmed.list_events()] == ids[-2:]
    rewritten = json.loads(path.read_text(encoding="utf-8"))
    assert [row["event_id"] for row in rewritten["events"]] == ids[-2:]


def test_alert_store_keeps_newest_within_cap(tmp_path) -> None:
    path = tmp_path / "alerts.json"
    store = AlertStore(path, max_records=2)
    ids: list[str] = []
    for index in range(4):
        alert = Alert(
            severity=Severity.INFO,
            title=f"Alert {index}",
            description="Local cap check",
            device_id=f"0781:5581:ALRT{index}",
        )
        ids.append(alert.alert_id)
        store.append(alert)
    assert [alert.alert_id for alert in store.list_alerts()] == ids[-2:]
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert [row["alert_id"] for row in payload["alerts"]] == ids[-2:]
    assert payload["alerts"][-1]["device_id"] == "0781:5581:ALRT3"


def report_stem_from(written) -> str:
    json_path = next(path for path in written if path.suffix == ".json")
    return json_path.stem
