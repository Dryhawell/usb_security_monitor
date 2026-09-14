"""Bounded local alert history (alerts.json).

Suppressed (cooldown) warnings are not stored. Documents stay local;
serials may be present in device_id like inventory records. Oldest
alerts are dropped when the record cap is exceeded.
"""

from __future__ import annotations

import threading
from pathlib import Path

from usb_monitor.models.alert import Alert
from usb_monitor.storage.atomic import read_json_file, write_json_atomic
from usb_monitor.storage.bounded import keep_newest
from usb_monitor.utils.logger import get_logger
from usb_monitor.utils.permissions import DEFAULT_DATA_DIR

DEFAULT_ALERTS_PATH = DEFAULT_DATA_DIR / "alerts" / "alerts.json"
DEFAULT_MAX_ALERTS = 2000
_SCHEMA_VERSION = 1


class AlertStore:
    """In-memory alert list with optional JSON persistence."""

    def __init__(
        self,
        path: Path | None = DEFAULT_ALERTS_PATH,
        *,
        max_records: int = DEFAULT_MAX_ALERTS,
    ) -> None:
        if max_records < 1:
            raise ValueError("max_records must be >= 1")
        self._path = path
        self._max_records = max_records
        self._alerts: list[Alert] = []
        self._lock = threading.Lock()
        self._log = get_logger("storage.alerts")

    @classmethod
    def load(
        cls,
        path: Path | None = DEFAULT_ALERTS_PATH,
        *,
        max_records: int = DEFAULT_MAX_ALERTS,
    ) -> AlertStore:
        store = cls(path=path, max_records=max_records)
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
        loaded, dropped = keep_newest(loaded, self._max_records)
        with self._lock:
            self._alerts = loaded
        self._log.info("Loaded %s alert(s) from local store", len(loaded))
        if dropped:
            self._log.info(
                "Dropped %s oldest alert(s) to stay within %s records",
                dropped,
                self._max_records,
            )
            self.save()

    def append(self, alert: Alert) -> None:
        dropped = 0
        with self._lock:
            if any(item.alert_id == alert.alert_id for item in self._alerts):
                return
            self._alerts.append(alert)
            self._alerts, dropped = keep_newest(self._alerts, self._max_records)
        self.save()
        if dropped:
            self._log.info(
                "Dropped %s oldest alert(s) to stay within %s records",
                dropped,
                self._max_records,
            )

    def list_alerts(self) -> list[Alert]:
        with self._lock:
            return list(self._alerts)

    def stats(self) -> dict[str, int]:
        return {
            "total": len(self.list_alerts()),
            "max_records": self._max_records,
        }

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
