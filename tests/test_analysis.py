"""Risk, anomaly, and alert behaviour without USB hardware."""

from datetime import timedelta

from usb_monitor.alerts import AlertManager
from usb_monitor.analysis import Analyzer
from usb_monitor.analysis.risk_engine import evaluate_risk
from usb_monitor.analysis.rules import AnalysisContext
from usb_monitor.inventory import DeviceInventory
from usb_monitor.models.enums import EventType, RiskLevel, Severity
from usb_monitor.models.event import USBEvent
from usb_monitor.utils.time import utc_now


def _connect(
    *,
    device_id: str,
    serial: str | None,
    timestamp=None,
    manufacturer: str | None = None,
) -> USBEvent:
    parts = device_id.split(":")
    vid = parts[0] if len(parts) >= 2 else None
    pid = parts[1] if len(parts) >= 2 else None
    return USBEvent(
        event_type=EventType.CONNECT,
        timestamp=timestamp or utc_now(),
        device_id=device_id,
        vendor_id=vid,
        product_id=pid,
        serial_number=serial,
        manufacturer=manufacturer,
        source="mock",
    )


def test_first_seen_and_missing_serial_are_not_critical() -> None:
    event = _connect(device_id="0781:5581", serial=None, manufacturer=None)
    assessment = evaluate_risk(AnalysisContext(event=event, is_first_seen=True))
    assert assessment.level is not RiskLevel.CRITICAL
    ids = {match.rule.rule_id for match in assessment.matches}
    assert "FIRST_SEEN_DEVICE" in ids
    assert "MISSING_SERIAL" in ids
    assert assessment.to_dict()["malware_verdict"] is False


def test_rapid_reconnect_needs_three_connects() -> None:
    origin = utc_now()
    analyzer = Analyzer()
    inventory = DeviceInventory(path=None)
    last = None
    for index in range(3):
        event = _connect(
            device_id="0781:5581:BURST01",
            serial="BURST01",
            manufacturer="SanDisk",
            timestamp=origin + timedelta(seconds=index * 2),
        )
        observation = inventory.observe(event)
        last = analyzer.analyze(event, observation)
    assert last is not None
    ids = {match.rule.rule_id for match in last.matches}
    assert "RAPID_RECONNECT" in ids
    assert last.level is not RiskLevel.CRITICAL


def test_alert_cooldown_suppresses_same_fingerprint() -> None:
    origin = utc_now()
    manager = AlertManager(cooldown_seconds=60)
    event = _connect(
        device_id="0781:5581:ALERT01",
        serial="ALERT01",
        manufacturer="SanDisk",
        timestamp=origin,
    )
    medium = evaluate_risk(
        AnalysisContext(event=event, is_first_seen=True, connects_in_window=1)
    )
    first = manager.consider(event, medium)
    assert first.alert is not None
    assert first.alert.severity is Severity.INFO
    second = manager.consider(event, medium)
    assert second.suppressed is True
    assert second.alert is None
    assert manager.stats().emitted == 1
    assert manager.stats().suppressed == 1


def test_alert_escalation_bypasses_cooldown() -> None:
    origin = utc_now()
    manager = AlertManager(cooldown_seconds=60)
    event = _connect(
        device_id="0781:5581",
        serial=None,
        timestamp=origin,
    )
    high = evaluate_risk(
        AnalysisContext(
            event=event,
            is_first_seen=True,
            connects_in_window=3,
        )
    )
    assert high.level is RiskLevel.HIGH
    first = manager.consider(event, high)
    assert first.alert is not None
    assert first.alert.severity is Severity.HIGH
    duplicate = manager.consider(event, high)
    assert duplicate.suppressed is True
    critical = evaluate_risk(
        AnalysisContext(
            event=event,
            is_first_seen=True,
            connects_in_window=3,
            events_in_window=4,
            new_devices_in_window=3,
        )
    )
    assert critical.level is RiskLevel.CRITICAL
    escalated = manager.consider(event, critical)
    assert escalated.alert is not None
    assert escalated.alert.severity is Severity.CRITICAL
