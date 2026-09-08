"""Local permission checks for persistence paths and process elevation.

The application is designed to run as a standard user. Elevation is
optional extra visibility, not a requirement and not a bypass of OS
security. These checks never disable antivirus or UAC.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from usb_monitor.utils.platform import is_windows

DEFAULT_DATA_DIR = Path("data")
DEFAULT_LOG_DIR = Path("logs")
_DATA_SUBDIRS = ("events", "inventory", "reports", "alerts")
_PROBE_NAME = ".write_probe"


class PersistenceError(RuntimeError):
    """Raised later when the app cannot write events, inventory, or logs."""


@dataclass(frozen=True)
class PermissionStatus:
    """Result of local filesystem and elevation checks."""

    is_elevated: bool | None
    data_dir: str
    log_dir: str
    data_writable: bool
    logs_writable: bool
    issues: tuple[str, ...] = field(default_factory=tuple)

    @property
    def can_persist(self) -> bool:
        """True when event/inventory/report/log directories can be written."""
        return self.data_writable and self.logs_writable

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "is_elevated": self.is_elevated,
            "data_dir": self.data_dir,
            "log_dir": self.log_dir,
            "data_writable": self.data_writable,
            "logs_writable": self.logs_writable,
            "can_persist": self.can_persist,
            "issues": list(self.issues),
        }


def is_process_elevated() -> bool | None:
    """Return whether this process is an elevated Windows administrator.

    * ``True`` / ``False`` on Windows when the check succeeds
    * ``None`` on non-Windows, or when the check is unavailable
    """
    if not is_windows():
        return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return None


def directory_is_writable(path: Path) -> bool:
    """Create ``path`` if needed and probe it with a short-lived temp file."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / _PROBE_NAME
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError:
        return False
    return True


def check_permissions(
    *,
    data_dir: Path | None = None,
    log_dir: Path | None = None,
    elevated: bool | None | object = ...,
) -> PermissionStatus:
    """Verify local data/log write access. Does not touch USB devices.

    ``elevated is ...`` means detect via the OS. Pass ``True``/``False``/``None``
    in tests to skip the Windows API call.
    """
    resolved_data = data_dir or DEFAULT_DATA_DIR
    resolved_logs = log_dir or DEFAULT_LOG_DIR
    issues: list[str] = []

    if elevated is ...:
        elevation = is_process_elevated()
    else:
        elevation = elevated  # type: ignore[assignment]

    data_ok = True
    for name in _DATA_SUBDIRS:
        target = resolved_data / name
        if not directory_is_writable(target):
            data_ok = False
            issues.append(f"Cannot write to {target}")

    logs_ok = directory_is_writable(resolved_logs)
    if not logs_ok:
        issues.append(f"Cannot write to {resolved_logs}")

    return PermissionStatus(
        is_elevated=elevation,
        data_dir=str(resolved_data),
        log_dir=str(resolved_logs),
        data_writable=data_ok,
        logs_writable=logs_ok,
        issues=tuple(issues),
    )


def format_elevation(value: bool | None) -> str:
    """Human-readable elevation state."""
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"
