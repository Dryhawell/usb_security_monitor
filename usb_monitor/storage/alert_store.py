"""Append-only local alert history (alerts.json).

Suppressed (cooldown) warnings are not stored. Documents stay local;
serials may be present in device_id like inventory records.
"""

from __future__ import annotations

import threading
from pathlib import Path

from usb_monitor.models.alert import Alert
from usb_monitor.storage.atomic import read_json_file, write_json_atomic
from usb_monitor.utils.logger import get_logger
from usb_monitor.utils.permissions import DEFAULT_DATA_DIR

DEFAULT_ALERTS_PATH = DEFAULT_DATA_DIR / "alerts" / "alerts.json"
_SCHEMA_VERSION = 1


class AlertStore:
    """In-memory alert list with optional JSON persistence."""

    def __init__(self, path: Path | None = DEFAULT_ALERTS_PATH) -> None:
        self._path = path
        self._alerts: list[Alert] = []
        self._lock = threading.Lock()
        self._log = get_logger("storage.alerts")

    @classmethod
    def load(cls, path: Path | None = DEFAULT_ALERTS_PATH) -> AlertStore:
        store = cls(path=path)
        store.reload()
        return store

    def reload(self) -> None:
        if self._path is None:
            return
        raw = read_json_file(self._path)
        records = raw.get("alerts") if isinstance(raw, dict) else None
        if raw is None:
            return
        if not isinstance(records, list):
            self._log.warning("Alerts file is missing an alerts list; starting empty")
            return
        loaded: list[Alert] = []
        seen: set[str] = set()
        for item in records:
            if not isinstance(item, dict):
                continue
            try:
                alert = Alert.from_dict(item)
            except (KeyError, TypeError, ValueError):
                self._log.warning("Skipping a malformed alert record")
                continue
            if alert.alert_id in seen:
                continue
            seen.add(alert.alert_id)
            loaded.append(alert)
        with self._lock:
            self._alerts = loaded
        self._log.info("Loaded %s alert(s) from local store", len(loaded))

    def append(self, alert: Alert) -> None:
        with self._lock:
            if any(item.alert_id == alert.alert_id for item in self._alerts):
                return
            self._alerts.append(alert)
        self.save()

    def list_alerts(self) -> list[Alert]:
        with self._lock:
            return list(self._alerts)

    def stats(self) -> dict[str, int]:
        return {"total": len(self.list_alerts())}

    def save(self) -> None:
        if self._path is None:
            return
        payload = {
            "version": _SCHEMA_VERSION,
            "alerts": [alert.to_dict() for alert in self.list_alerts()],
        }
        try:
            write_json_atomic(self._path, payload, prefix="alerts.")
        except OSError as exc:
            self._log.error("Could not save alerts: %s", exc)
