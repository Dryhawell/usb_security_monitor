"""Build a local, explainable summary of inventory, events, and alerts.

Reports stay on this machine. JSON/CSV may include serial numbers, like
the event store; the human-readable text uses masked identities.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from usb_monitor import __app_name__, __version__
from usb_monitor.inventory import DeviceInventory, format_device_row
from usb_monitor.models.alert import Alert
from usb_monitor.models.device import Device
from usb_monitor.models.event import USBEvent
from usb_monitor.storage import AlertStore, EventStore
from usb_monitor.utils.time import to_iso8601, utc_now

DISCLAIMER = "Heuristic scores are not a malware verdict."
LOCAL_ONLY_NOTE = (
    "This report is local-only. It is not telemetry and does not leave "
    "this computer unless you copy the files yourself."
)

DEFAULT_REPORT_LIMIT = 20


@dataclass
class LocalReport:
    """Snapshot of local USB monitoring records for export or console print."""

    generated_at: datetime
    inventory_stats: dict[str, int]
    devices: list[Device]
    events: list[USBEvent]
    alerts: list[Alert]
    event_total: int
    alert_total: int
    limit: int | None = DEFAULT_REPORT_LIMIT

    def to_dict(self) -> dict[str, Any]:
        """Full JSON payload. Serials are unmasked, matching events.json."""
        return {
            "generated_at": to_iso8601(self.generated_at),
            "app_name": __app_name__,
            "version": __version__,
            "disclaimer": DISCLAIMER,
            "local_only": True,
            "identifiers_unmasked": True,
            "inventory": {
                "stats": dict(self.inventory_stats),
                "devices": [device.to_dict() for device in self.devices],
            },
            "events": {
                "total": self.event_total,
                "shown": len(self.events),
                "items": [event.to_dict() for event in self.events],
            },
            "alerts": {
                "total": self.alert_total,
                "shown": len(self.alerts),
                "items": [alert.to_dict() for alert in self.alerts],
            },
        }

    def to_text(self) -> str:
        """Human-readable summary with masked serials."""
        lines = [
            f"{__app_name__} local report",
            f"Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            (
                f"Inventory: {self.inventory_stats.get('total', 0)} device(s), "
                f"{self.inventory_stats.get('trusted', 0)} trusted"
            ),
            f"Events: {self.event_total} (showing {len(self.events)})",
            f"Alerts: {self.alert_total} (showing {len(self.alerts)})",
            DISCLAIMER,
            LOCAL_ONLY_NOTE,
            "",
            "Devices:",
        ]
        if not self.devices:
            lines.append("  (empty)")
        else:
            for device in self.devices:
                lines.append(f"  {format_device_row(device)}")
        lines.extend(["", "Recent events:"])
        if not self.events:
            lines.append("  (empty)")
        else:
            for event in self.events:
                lines.append(f"  {_format_event_row(event)}")
        lines.extend(["", "Recent alerts:"])
        if not self.alerts:
            lines.append("  (empty)")
        else:
            for alert in self.alerts:
                lines.append(f"  {_format_alert_row(alert)}")
        lines.extend(["", "--------------------------------"])
        return "\n".join(lines)


def build_local_report(
    *,
    limit: int | None = DEFAULT_REPORT_LIMIT,
    inventory: DeviceInventory | None = None,
    events: EventStore | None = None,
    alerts: AlertStore | None = None,
    generated_at: datetime | None = None,
) -> LocalReport:
    """Load local stores and apply the per-section row limit."""
    if limit is not None and limit < 0:
        raise ValueError("limit must be >= 0")
    loaded_inventory = inventory if inventory is not None else DeviceInventory.load()
    event_store = events if events is not None else EventStore.load()
    alert_store = alerts if alerts is not None else AlertStore.load()
    all_events = event_store.list_events()
    all_alerts = alert_store.list_alerts()
    devices = loaded_inventory.list_devices()
    return LocalReport(
        generated_at=generated_at or utc_now(),
        inventory_stats=loaded_inventory.stats(),
        devices=_apply_limit(devices, limit, newest_first=False),
        events=_apply_limit(all_events, limit, newest_first=True),
        alerts=_apply_limit(all_alerts, limit, newest_first=True),
        event_total=len(all_events),
        alert_total=len(all_alerts),
        limit=limit,
    )


def _apply_limit(
    items: list[Any],
    limit: int | None,
    *,
    newest_first: bool,
) -> list[Any]:
    ordered = list(reversed(items)) if newest_first else list(items)
    if limit is None or limit == 0:
        return ordered
    return ordered[:limit]


def _format_event_row(event: USBEvent) -> str:
    risk = ""
    if event.risk_level is not None and event.risk_score is not None:
        risk = f"  risk={event.risk_level.value}({event.risk_score})"
    return (
        f"{event.display_timestamp}  {event.event_type.value}  "
        f"{event.safe_device_id}{risk}"
    )


def _format_alert_row(alert: Alert) -> str:
    return (
        f"{alert.display_timestamp}  {alert.severity.value}  "
        f"{alert.title}  {alert.safe_device_id}"
    )
