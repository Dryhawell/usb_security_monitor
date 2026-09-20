"""Optional local DPAPI protection for JSON stores.

Default is off: events.json stays plaintext for local forensics.
Set USB_MONITOR_DPAPI=1 to encrypt new store writes with the current
Windows user key (CryptProtectData). There is no telemetry and no
network. The same user can still decrypt; another machine or account
cannot. Reports stay plaintext exports even when this flag is on.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
from ctypes import wintypes
from typing import Any

from usb_monitor.utils.platform import is_windows

ENV_NAME = "USB_MONITOR_DPAPI"
PROTECTION_KIND = "dpapi"
PROTECTION_VERSION = 1
_DESCRIPTION = "usb_security_monitor"
CRYPTPROTECT_UI_FORBIDDEN = 0x01
_TRUTHY = {"1", "true", "yes", "on"}


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def is_protection_enabled() -> bool:
    """True when the operator asked new JSON store writes to use DPAPI."""
    value = os.environ.get(ENV_NAME, "").strip().lower()
    return value in _TRUTHY


def is_protected_document(raw: Any) -> bool:
    """True when ``raw`` is a local DPAPI wrapper, not an events payload."""
    return (
        isinstance(raw, dict)
        and raw.get("protection") == PROTECTION_KIND
        and raw.get("version") == PROTECTION_VERSION
        and isinstance(raw.get("payload"), str)
        and bool(raw["payload"])
    )


def wrap_json_text(text: str) -> str:
    """Encrypt UTF-8 JSON and return a small wrapper document."""
    blob = protect_bytes(text.encode("utf-8"))
    return json.dumps(
        {
            "protection": PROTECTION_KIND,
            "version": PROTECTION_VERSION,
            "payload": base64.standard_b64encode(blob).decode("ascii"),
        },
        indent=2,
    )


def unwrap_document(raw: Any) -> Any:
    """Decrypt a wrapper, or return ``raw`` unchanged if it is plaintext JSON."""
    if not is_protected_document(raw):
        return raw
    blob = base64.b64decode(raw["payload"], validate=True)
    inner = unprotect_bytes(blob)
    return json.loads(inner.decode("utf-8"))


def protect_bytes(data: bytes) -> bytes:
    """Protect ``data`` with the current Windows user DPAPI key."""
    if not is_windows():
        raise OSError("DPAPI protection is only available on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    protect = crypt32.CryptProtectData
    protect.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    protect.restype = wintypes.BOOL
    return _run_blob_api(protect, data, _DESCRIPTION)


def unprotect_bytes(data: bytes) -> bytes:
    """Reverse ``protect_bytes`` for the current Windows user."""
    if not is_windows():
        raise OSError("DPAPI protection is only available on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    unprotect = crypt32.CryptUnprotectData
    unprotect.argtypes = [
        ctypes.POINTER(_DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DATA_BLOB),
    ]
    unprotect.restype = wintypes.BOOL
    return _run_blob_api(unprotect, data, None)


def _run_blob_api(func: Any, data: bytes, description: str | None) -> bytes:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    inbound = _DATA_BLOB()
    inbound.cbData = len(data)
    inbound_buf = ctypes.create_string_buffer(data or b"\x00", max(len(data), 1))
    inbound.pbData = ctypes.cast(inbound_buf, ctypes.POINTER(ctypes.c_byte))
    outbound = _DATA_BLOB()
    if not func(
        ctypes.byref(inbound),
        description,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(outbound),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(outbound.pbData, outbound.cbData)
    finally:
        if outbound.pbData:
            kernel32.LocalFree(outbound.pbData)
