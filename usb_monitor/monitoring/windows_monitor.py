"""Windows WM_DEVICECHANGE event source.

Selected mechanism
    Native ``WM_DEVICECHANGE`` notifications via a hidden top-level
    window (Windows Management / user32), not a WMI poll loop.

Why this mechanism
    * Event-based: Windows pushes arrival/removal; we do not scan USB
      ports on an interval.
    * Standard library only (ctypes). No pywin32/WMI package required.
    * Works as a standard user for typical removable storage.
    * Exposes volume drive letters and, when present, USB device
      interface paths that already contain VID/PID.

Permissions
    Standard user is enough for these broadcasts. Administrator rights
    are not requested and UAC is not bypassed. The Windows event log
    is not opened here.

What it exposes
    * Volume arrival/removal with drive letter (``E:``)
    * USB/disk/volume interface arrival/removal with a device path
    * VID/PID when the path contains ``VID_xxxx&PID_yyyy``

Limitations
    * USB HID / BadUSB keyboards often have no volume and may still
      appear only as a USB interface — or not in a way that proves
      malice. This source cannot detect malicious firmware.
    * One physical stick usually generates several raw events
      (USB + disk + volume). Correlation is Phase 5+.
    * Device names, serials, and manufacturer strings are not queried
      here (Phase 6 metadata).
    * A message-only window would miss broadcasts; this source uses a
      hidden top-level window plus RegisterDeviceNotification.

If unavailable
    ``start()`` raises ``EventSourceUnavailableError``. The rest of the
    application stays up. Non-Windows hosts raise
    ``UnsupportedPlatformError``.
"""

from __future__ import annotations

import ctypes
import queue
import sys
import threading
import uuid
from ctypes import wintypes
from typing import Any

from usb_monitor.monitoring.event_source import (
    EventSource,
    EventSourceUnavailableError,
    RawAction,
    RawDeviceEvent,
    drive_letters_from_unit_mask,
    parse_vid_pid_from_path,
)
from usb_monitor.utils.logger import get_logger
from usb_monitor.utils.platform import UnsupportedPlatformError, is_windows

WM_QUIT = 0x0012
WM_DEVICECHANGE = 0x0219
WM_DESTROY = 0x0002

DBT_DEVICEARRIVAL = 0x8000
DBT_DEVICEREMOVECOMPLETE = 0x8004

DBT_DEVTYP_VOLUME = 0x00000002
DBT_DEVTYP_DEVICEINTERFACE = 0x00000005

DEVICE_NOTIFY_WINDOW_HANDLE = 0x00000000

WS_EX_NOACTIVATE = 0x08000000
WS_EX_TOOLWINDOW = 0x00000080
WS_POPUP = 0x80000000

GUID_DEVINTERFACE_USB_DEVICE = uuid.UUID("{A5DCBF10-6530-11D2-901F-00C04FB951ED}")
GUID_DEVINTERFACE_DISK = uuid.UUID("{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}")
GUID_DEVINTERFACE_VOLUME = uuid.UUID("{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}")

SOURCE_ID = "windows_wm_devicechange"
_QUEUE_MAX = 1024
_START_TIMEOUT_SECONDS = 5.0

WNDPROC = ctypes.WINFUNCTYPE(
    ctypes.c_ssize_t,
    wintypes.HWND,
    ctypes.c_uint,
    wintypes.WPARAM,
    wintypes.LPARAM,
)


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", ctypes.c_uint),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HANDLE),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HANDLE),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class DEV_BROADCAST_HDR(ctypes.Structure):
    _fields_ = [
        ("dbch_size", wintypes.DWORD),
        ("dbch_devicetype", wintypes.DWORD),
        ("dbch_reserved", wintypes.DWORD),
    ]


class DEV_BROADCAST_VOLUME(ctypes.Structure):
    _fields_ = [
        ("dbcv_size", wintypes.DWORD),
        ("dbcv_devicetype", wintypes.DWORD),
        ("dbcv_reserved", wintypes.DWORD),
        ("dbcv_unitmask", wintypes.DWORD),
        ("dbcv_flags", wintypes.WORD),
    ]


class DEV_BROADCAST_DEVICEINTERFACE_W(ctypes.Structure):
    _fields_ = [
        ("dbcc_size", wintypes.DWORD),
        ("dbcc_devicetype", wintypes.DWORD),
        ("dbcc_reserved", wintypes.DWORD),
        ("dbcc_classguid", GUID),
        ("dbcc_name", wintypes.WCHAR * 1),
    ]


def _guid_from_uuid(value: uuid.UUID) -> GUID:
    return GUID.from_buffer_copy(value.bytes_le)


class WindowsEventSource(EventSource):
    """Background WM_DEVICECHANGE watcher for removable/USB arrival and removal."""

    def __init__(self, *, queue_maxsize: int = _QUEUE_MAX) -> None:
        self._log = get_logger("monitoring.windows")
        self._queue: queue.Queue[RawDeviceEvent] = queue.Queue(maxsize=queue_maxsize)
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._start_error: BaseException | None = None
        self._hwnd: int | None = None
        self._thread_id: int | None = None
        self._class_name = f"UsbSecMon_{uuid.uuid4().hex}"
        self._wndproc = WNDPROC(self._wnd_proc)
        self._notify_handles: list[int] = []
        self._user32: Any = None
        self._kernel32: Any = None
        self._class_atom = 0

    @property
    def mechanism(self) -> str:
        return SOURCE_ID

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._ready.is_set() and self._start_error is None

    @classmethod
    def is_available(cls) -> bool:
        """True when this host can attempt the native Windows source."""
        return is_windows()

    def start(self) -> None:
        if self.is_running:
            return
        if not is_windows():
            raise UnsupportedPlatformError(
                "Live USB event source is Windows-only "
                f"(sys.platform={sys.platform!r})."
            )

        self._stop.clear()
        self._ready.clear()
        self._start_error = None
        self._thread = threading.Thread(
            target=self._run,
            name="usb-wm-devicechange",
            daemon=True,
        )
        self._thread.start()
        if not self._ready.wait(timeout=_START_TIMEOUT_SECONDS):
            self.stop()
            raise EventSourceUnavailableError(
                "Windows event source did not become ready in time."
            )
        if self._start_error is not None:
            error = self._start_error
            self.stop()
            raise EventSourceUnavailableError(
                f"Windows event source failed to start: {error}"
            ) from error
        self._log.info("Windows event source started (%s)", self.mechanism)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        user32 = self._user32
        if user32 is not None and self._thread_id:
            try:
                user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)
            except OSError:
                self._log.debug("PostThreadMessageW failed during stop")
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
            if thread.is_alive():
                self._log.warning("Windows event source thread did not stop in time")
        self._thread = None
        self._hwnd = None
        self._thread_id = None
        self._ready.clear()

    def poll(self, timeout: float | None = None) -> RawDeviceEvent | None:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _run(self) -> None:
        try:
            self._kernel32, self._user32 = _load_winapi()
            self._thread_id = int(self._kernel32.GetCurrentThreadId())
            self._hwnd = self._create_hidden_window()
            self._notify_handles = self._register_device_notifications(self._hwnd)
        except (OSError, ValueError, EventSourceUnavailableError) as exc:
            self._start_error = exc
            self._ready.set()
            self._cleanup_window()
            return

        self._ready.set()
        message = wintypes.MSG()
        while not self._stop.is_set():
            result = self._user32.GetMessageW(ctypes.byref(message), None, 0, 0)
            if result == 0 or result == -1:
                break
            self._user32.TranslateMessage(ctypes.byref(message))
            self._user32.DispatchMessageW(ctypes.byref(message))
        self._cleanup_window()
        self._log.info("Windows event source stopped")

    def _create_hidden_window(self) -> int:
        user32 = self._user32
        kernel32 = self._kernel32
        class_name = self._class_name
        wndclass = WNDCLASSW()
        wndclass.style = 0
        wndclass.lpfnWndProc = self._wndproc
        wndclass.hInstance = kernel32.GetModuleHandleW(None)
        wndclass.lpszClassName = class_name
        atom = user32.RegisterClassW(ctypes.byref(wndclass))
        if not atom:
            error = ctypes.get_last_error()
            raise EventSourceUnavailableError(f"RegisterClassW failed (Win32 error {error})")
        self._class_atom = atom

        hwnd = user32.CreateWindowExW(
            WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            class_name,
            "USB Security Monitor",
            WS_POPUP,
            0,
            0,
            0,
            0,
            None,
            None,
            wndclass.hInstance,
            None,
        )
        if not hwnd:
            error = ctypes.get_last_error()
            raise EventSourceUnavailableError(f"CreateWindowExW failed (Win32 error {error})")
        return int(hwnd)

    def _register_device_notifications(self, hwnd: int) -> list[int]:
        handles: list[int] = []
        for guid in (
            GUID_DEVINTERFACE_USB_DEVICE,
            GUID_DEVINTERFACE_DISK,
            GUID_DEVINTERFACE_VOLUME,
        ):
            filt = DEV_BROADCAST_DEVICEINTERFACE_W()
            filt.dbcc_size = ctypes.sizeof(DEV_BROADCAST_DEVICEINTERFACE_W)
            filt.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE
            filt.dbcc_classguid = _guid_from_uuid(guid)
            handle = self._user32.RegisterDeviceNotificationW(
                wintypes.HWND(hwnd),
                ctypes.byref(filt),
                DEVICE_NOTIFY_WINDOW_HANDLE,
            )
            if handle:
                handles.append(int(handle))
            else:
                error = ctypes.get_last_error()
                self._log.warning(
                    "RegisterDeviceNotificationW failed for %s (Win32 error %s)",
                    guid,
                    error,
                )
        if not handles:
            self._log.warning(
                "No device interface notifications registered; "
                "volume broadcasts on the hidden window may still arrive"
            )
        return handles

    def _cleanup_window(self) -> None:
        user32 = self._user32
        if user32 is None:
            return
        for handle in self._notify_handles:
            try:
                user32.UnregisterDeviceNotification(handle)
            except OSError:
                self._log.debug("UnregisterDeviceNotification failed")
        self._notify_handles = []
        if self._hwnd:
            try:
                user32.DestroyWindow(self._hwnd)
            except OSError:
                self._log.debug("DestroyWindow failed")
        if self._class_atom:
            try:
                user32.UnregisterClassW(self._class_name, self._kernel32.GetModuleHandleW(None))
            except OSError:
                self._log.debug("UnregisterClassW failed")
            self._class_atom = 0

    def _wnd_proc(
        self,
        hwnd: int,
        msg: int,
        wparam: int,
        lparam: int,
    ) -> int:
        # Native callbacks must not leak Python exceptions into user32.
        try:
            if msg == WM_DEVICECHANGE:
                self._on_device_change(int(wparam), int(lparam))
            elif msg == WM_DESTROY:
                self._user32.PostQuitMessage(0)
        except Exception:
            self._log.exception("WM_DEVICECHANGE handler failed")
        return int(self._user32.DefWindowProcW(hwnd, msg, wparam, lparam))

    def _on_device_change(self, wparam: int, lparam: int) -> None:
        if wparam not in (DBT_DEVICEARRIVAL, DBT_DEVICEREMOVECOMPLETE):
            return
        if not lparam:
            return
        action = RawAction.CONNECT if wparam == DBT_DEVICEARRIVAL else RawAction.DISCONNECT
        header = DEV_BROADCAST_HDR.from_address(lparam)
        if header.dbch_devicetype == DBT_DEVTYP_VOLUME:
            self._emit_volume_events(action, lparam)
            return
        if header.dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE:
            self._emit_interface_event(action, lparam)

    def _emit_volume_events(self, action: RawAction, lparam: int) -> None:
        volume = DEV_BROADCAST_VOLUME.from_address(lparam)
        letters = drive_letters_from_unit_mask(volume.dbcv_unitmask)
        if not letters:
            self._enqueue(
                RawDeviceEvent(
                    action=action,
                    source=SOURCE_ID,
                    kind="volume",
                    details={"unit_mask": int(volume.dbcv_unitmask)},
                )
            )
            return
        for letter in letters:
            self._enqueue(
                RawDeviceEvent(
                    action=action,
                    source=SOURCE_ID,
                    kind="volume",
                    drive_letter=letter,
                    details={"unit_mask": int(volume.dbcv_unitmask)},
                )
            )

    def _emit_interface_event(self, action: RawAction, lparam: int) -> None:
        interface = DEV_BROADCAST_DEVICEINTERFACE_W.from_address(lparam)
        name_offset = (
            DEV_BROADCAST_DEVICEINTERFACE_W.dbcc_name.offset  # type: ignore[attr-defined]
        )
        try:
            device_path = ctypes.wstring_at(lparam + name_offset)
        except (ValueError, OSError):
            device_path = None
        if device_path == "":
            device_path = None
        vendor_id, product_id = parse_vid_pid_from_path(device_path)
        kind = _kind_from_path(device_path)
        self._enqueue(
            RawDeviceEvent(
                action=action,
                source=SOURCE_ID,
                kind=kind,
                device_path=device_path,
                vendor_id=vendor_id,
                product_id=product_id,
            )
        )

    def _enqueue(self, event: RawDeviceEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._log.warning("Raw event queue is full; dropping a %s event", event.action.value)
        else:
            self._log.info("%s", event.format_console())


def _kind_from_path(device_path: str | None) -> str:
    if not device_path:
        return "device_interface"
    lowered = device_path.upper()
    if "USBSTOR" in lowered or "USB#" in lowered:
        return "usb"
    if "DISK#" in lowered or "SCSI#" in lowered:
        return "disk"
    if "VOLUME#" in lowered:
        return "volume"
    return "device_interface"


def _load_winapi() -> tuple[Any, Any]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)

    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GetCurrentThreadId.argtypes = []
    kernel32.GetCurrentThreadId.restype = wintypes.DWORD

    user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
    user32.RegisterClassW.restype = wintypes.ATOM
    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HANDLE,
        wintypes.HINSTANCE,
        wintypes.LPVOID,
    ]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.DefWindowProcW.argtypes = [
        wintypes.HWND,
        ctypes.c_uint,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    user32.DefWindowProcW.restype = ctypes.c_ssize_t
    user32.GetMessageW.argtypes = [
        ctypes.POINTER(wintypes.MSG),
        wintypes.HWND,
        ctypes.c_uint,
        ctypes.c_uint,
    ]
    user32.GetMessageW.restype = ctypes.c_int
    user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.TranslateMessage.restype = wintypes.BOOL
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DispatchMessageW.restype = ctypes.c_ssize_t
    user32.PostThreadMessageW.argtypes = [
        wintypes.DWORD,
        ctypes.c_uint,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    user32.PostThreadMessageW.restype = wintypes.BOOL
    user32.PostQuitMessage.argtypes = [ctypes.c_int]
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.DestroyWindow.restype = wintypes.BOOL
    user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
    user32.UnregisterClassW.restype = wintypes.BOOL
    user32.RegisterDeviceNotificationW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    user32.RegisterDeviceNotificationW.restype = wintypes.HANDLE
    user32.UnregisterDeviceNotification.argtypes = [wintypes.HANDLE]
    user32.UnregisterDeviceNotification.restype = wintypes.BOOL
    return kernel32, user32
