"""Operating-system detection and monitoring-capability flags.

Live USB monitoring is Windows-only. Other platforms should still load
models and utilities; they must not crash at import time.
"""

from __future__ import annotations

import platform
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any


class UnsupportedPlatformError(RuntimeError):
    """Raised later when live monitoring is requested on a non-Windows OS."""


@dataclass(frozen=True)
class PlatformInfo:
    """Snapshot of the local runtime. Contains no device or user identity."""

    system: str
    release: str
    version: str
    architecture: str
    python_version: str
    is_windows: bool
    live_monitoring_supported: bool
    powershell_available: bool
    display_name: str
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "system": self.system,
            "release": self.release,
            "version": self.version,
            "architecture": self.architecture,
            "python_version": self.python_version,
            "is_windows": self.is_windows,
            "live_monitoring_supported": self.live_monitoring_supported,
            "powershell_available": self.powershell_available,
            "display_name": self.display_name,
            "notes": list(self.notes),
        }


def is_windows(system: str | None = None) -> bool:
    """Return True when running on native Windows (not Cygwin/WSL as POSIX)."""
    if system is not None:
        return system.lower() == "windows"
    return sys.platform == "win32"


def detect_platform(
    *,
    system: str | None = None,
    release: str | None = None,
    version: str | None = None,
    architecture: str | None = None,
    python_version: str | None = None,
    powershell_path: str | None | object = ...,
) -> PlatformInfo:
    """Inspect the current (or injected) platform without probing USB or WMI.

    Keyword overrides exist so tests can simulate Linux/macOS without those
    operating systems. ``powershell_path is ...`` means "look it up".
    """
    system_name = system if system is not None else platform.system()
    release_name = release if release is not None else platform.release()
    version_name = version if version is not None else _windows_version() if is_windows(system_name) else platform.version()
    arch_name = architecture if architecture is not None else platform.machine() or "unknown"
    py_version = python_version if python_version is not None else platform.python_version()
    windows = is_windows(system_name)

    if powershell_path is ...:
        found_powershell = shutil.which("powershell") is not None or shutil.which("pwsh") is not None
    else:
        found_powershell = bool(powershell_path)

    notes: list[str] = []
    if windows:
        notes.append(
            "Live USB events use WM_DEVICECHANGE (windows_wm_devicechange)."
        )
        if not found_powershell:
            notes.append(
                "PowerShell was not found on PATH; it is only a future fallback, not required yet."
            )
    else:
        notes.append(
            "Live USB monitoring is Windows-only. Models, storage, and reports can still run."
        )
        notes.append(
            "A mock event source will be added later so non-Windows machines can test the pipeline."
        )

    display = _display_name(system_name, release_name, version_name, windows)
    return PlatformInfo(
        system=system_name or "Unknown",
        release=release_name or "Unknown",
        version=version_name or "Unknown",
        architecture=arch_name,
        python_version=py_version,
        is_windows=windows,
        live_monitoring_supported=windows,
        powershell_available=found_powershell,
        display_name=display,
        notes=tuple(notes),
    )


def _windows_version() -> str:
    """Best-effort Windows version string; never raises to the caller."""
    try:
        win_release, win_version, _csd, _ptype = platform.win32_ver()
    except (AttributeError, OSError, ValueError):
        return platform.version()
    return win_version or win_release or platform.version()


def _display_name(system: str, release: str, version: str, windows: bool) -> str:
    if windows:
        build = _windows_build_number(version)
        if build is not None and build >= 22000:
            label = "Windows 11"
        elif release:
            label = f"Windows {release}"
        else:
            label = "Windows"
        if version:
            return f"{label} ({version})"
        return label
    parts = [system or "Unknown"]
    if release:
        parts.append(release)
    return " ".join(parts)


def _windows_build_number(version: str) -> int | None:
    """Extract the build from a string such as ``10.0.26200``."""
    parts = version.split(".")
    if len(parts) >= 3 and parts[2].isdigit():
        return int(parts[2])
    if version.isdigit():
        return int(version)
    return None
