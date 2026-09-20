"""Restrict local persistence files to the current user.

Identifiers stay plaintext on disk. There is no encryption and no
telemetry. This only narrows which other accounts on the machine can
open events.json, alerts.json, devices.json, and exported reports.
Optional DPAPI wrapping of store JSON is separate
(`USB_MONITOR_DPAPI=1`).

On Windows the DACL is current user + SYSTEM + Administrators, with
inheritance blocked. On POSIX the mode is 0600. Failures are logged
and must not block a successful write.
"""

from __future__ import annotations

import ctypes
import os
import re
import stat
from ctypes import wintypes
from pathlib import Path

from usb_monitor.utils.logger import get_logger
from usb_monitor.utils.platform import is_windows

_log = get_logger("acl")

_SID_RE = re.compile(r"^S-\d+(-\d+)+$", re.ASCII)

TOKEN_QUERY = 0x0008
TokenUser = 1
ERROR_INSUFFICIENT_BUFFER = 122
SDDL_REVISION_1 = 1
DACL_SECURITY_INFORMATION = 0x00000004


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", _SID_AND_ATTRIBUTES)]


def owner_only_sddl(user_sid: str) -> str:
    """Build a protected DACL SDDL for one user SID plus SYSTEM/Administrators."""
    sid = (user_sid or "").strip()
    if not _SID_RE.fullmatch(sid):
        raise ValueError("user_sid must be a Windows SID string")
    return f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"


def restrict_owner_only(path: Path) -> bool:
    """Limit ``path`` to the current user. Return True when the OS accepted it."""
    try:
        if not path.is_file():
            return False
        if os.name == "posix":
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            return True
        if is_windows():
            _restrict_windows(path)
            return True
        return False
    except (OSError, ValueError) as exc:
        _log.warning("Could not restrict %s (%s)", path, exc)
        return False


def _restrict_windows(path: Path) -> None:
    sddl = owner_only_sddl(_current_user_sid())
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    convert.restype = wintypes.BOOL

    set_security = advapi32.SetFileSecurityW
    set_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    set_security.restype = wintypes.BOOL

    descriptor = ctypes.c_void_p()
    if not convert(sddl, SDDL_REVISION_1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not set_security(str(path), DACL_SECURITY_INFORMATION, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.LocalFree(descriptor)


def _current_user_sid() -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    open_token = advapi32.OpenProcessToken
    open_token.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_token.restype = wintypes.BOOL

    get_info = advapi32.GetTokenInformation
    get_info.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_info.restype = wintypes.BOOL

    sid_to_string = advapi32.ConvertSidToStringSidW
    sid_to_string.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    sid_to_string.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not open_token(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD(0)
        get_info(token, TokenUser, None, 0, ctypes.byref(needed))
        if needed.value == 0:
            raise ctypes.WinError(ctypes.get_last_error() or ERROR_INSUFFICIENT_BUFFER)
        buf = ctypes.create_string_buffer(needed.value)
        if not get_info(token, TokenUser, buf, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        user = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER)).contents
        text = wintypes.LPWSTR()
        if not sid_to_string(user.User.Sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            sid = text.value or ""
        finally:
            kernel32.LocalFree(text)
        if not sid:
            raise OSError("current user SID was empty")
        return sid
    finally:
        kernel32.CloseHandle(token)
