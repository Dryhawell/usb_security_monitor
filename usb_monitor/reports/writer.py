"""Write local report files (JSON, CSV, human-readable text)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Iterable

from usb_monitor.reports.builder import LocalReport
from usb_monitor.storage.atomic import write_json_atomic, write_text_atomic
from usb_monitor.utils.permissions import DEFAULT_DATA_DIR

DEFAULT_REPORTS_DIR = DEFAULT_DATA_DIR / "reports"
REPORT_FORMATS = ("text", "json", "csv", "all")

DEVICE_CSV_FIELDS = (
    "device_id",
    "vendor_id",
    "product_id",
    "serial_number",
    "manufacturer",
    "product_name",
    "device_type",
    "interface_type",
    "pnp_device_id",
    "drive_letter",
    "filesystem",
    "capacity",
    "removable",
    "first_seen",
    "last_seen",
    "connection_count",
    "trusted",
    "risk_score",
    "risk_level",
    "extra",
)

EVENT_CSV_FIELDS = (
    "event_id",
    "timestamp",
    "event_type",
    "device_id",
    "device_name",
    "vendor_id",
    "product_id",
    "serial_number",
    "drive_letter",
    "device_type",
    "manufacturer",
    "pnp_device_id",
    "removable",
    "filesystem",
    "capacity",
    "source",
    "risk_score",
    "risk_level",
    "details",
)

ALERT_CSV_FIELDS = (
    "alert_id",
    "timestamp",
    "severity",
    "title",
    "description",
    "device_id",
    "event_id",
    "reasons",
    "recommendation",
)


def resolve_formats(name: str | None, *, exported: bool) -> tuple[str, ...]:
    """Map a CLI format name onto the files that should be written."""
    if name is None:
        return REPORT_FORMATS[:-1] if exported else ("text",)
    key = name.strip().lower()
    if key == "all":
        return ("text", "json", "csv")
    if key in ("text", "json", "csv"):
        return (key,)
    raise ValueError(f"Unknown report format: {name}")


def report_stem(report: LocalReport) -> str:
    """Filesystem-safe UTC stamp used as the shared report prefix."""
    return "usb-report-" + report.generated_at.strftime("%Y%m%dT%H%M%SZ")


def export_report(
    report: LocalReport,
    directory: Path | None = None,
    *,
    formats: Iterable[str] | None = None,
) -> list[Path]:
    """Write selected formats under ``directory`` and return created paths."""
    target = directory or DEFAULT_REPORTS_DIR
    target.mkdir(parents=True, exist_ok=True)
    selected = tuple(formats) if formats is not None else ("text", "json", "csv")
    stem = report_stem(report)
    written: list[Path] = []
    if "json" in selected:
        path = target / f"{stem}.json"
        write_json_atomic(path, report.to_dict(), prefix="report.")
        written.append(path)
    if "text" in selected:
        path = target / f"{stem}.txt"
        write_text_atomic(path, report.to_text(), prefix="report.", suffix=".txt.tmp")
        written.append(path)
    if "csv" in selected:
        written.extend(_write_csv_set(report, target, stem))
    return written


def _write_csv_set(report: LocalReport, directory: Path, stem: str) -> list[Path]:
    devices = directory / f"{stem}-devices.csv"
    events = directory / f"{stem}-events.csv"
    alerts = directory / f"{stem}-alerts.csv"
    write_text_atomic(
        devices,
        _csv_text(DEVICE_CSV_FIELDS, [device.to_dict() for device in report.devices]),
        prefix="report.",
        suffix=".csv.tmp",
    )
    write_text_atomic(
        events,
        _csv_text(EVENT_CSV_FIELDS, [event.to_dict() for event in report.events]),
        prefix="report.",
        suffix=".csv.tmp",
    )
    write_text_atomic(
        alerts,
        _csv_text(
            ALERT_CSV_FIELDS,
            [_alert_csv_row(alert.to_dict()) for alert in report.alerts],
        ),
        prefix="report.",
        suffix=".csv.tmp",
    )
    return [devices, events, alerts]


def _alert_csv_row(data: dict[str, Any]) -> dict[str, Any]:
    row = dict(data)
    reasons = row.get("reasons") or []
    if isinstance(reasons, list):
        row["reasons"] = "; ".join(str(item) for item in reasons)
    return row


def _csv_text(fields: tuple[str, ...], rows: list[dict[str, Any]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(fields), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _csv_cell(row.get(key)) for key in fields})
    return buffer.getvalue()


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)
