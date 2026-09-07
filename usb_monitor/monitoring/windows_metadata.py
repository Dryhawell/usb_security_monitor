"""Windows SetupAPI + volume queries for device metadata.

Selected mechanism
    * ``GetDriveType`` / ``GetVolumeInformation`` / ``GetDiskFreeSpaceEx``
      for drive letter, removable flag, filesystem, and capacity.
    * SetupAPI ``SetupDiOpenDeviceInfo`` for manufacturer, product name,
      and PnP instance ID (standard user, no extra packages).

Why not WMI here
    A one-shot SetupAPI lookup is event-triggered (after CONNECT), not a
    poll loop. It stays in the standard library (ctypes).

Permissions
    Standard user. Does not require elevation, does not open files on the
    volume, and does not disable security software.

Limitations
    * USB hard disks often report ``DRIVE_FIXED``; ``removable=False``
      does not mean "not USB".
    * Volume label is not the manufacturer.
    * The device may disappear before lookup (especially DISCONNECT);
      missing fields stay ``None``.
    * Firmware / BadUSB identity cannot be proven from these properties.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import Any

from usb_monitor.models.device import normalize_drive_letter, normalize_hardware_id
from usb_monitor.models.enums import EventType
from usb_monitor.models.event import USBEvent
from usb_monitor.monitoring.event_source import (
    parse_instance_id_from_path,
    parse_vid_pid_from_path,
)
from usb_monitor.monitoring.metadata import DeviceMetadata, MetadataCollector
from usb_monitor.utils.logger import get_logger
from usb_monitor.utils.platform import is_windows

DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2

SPDRP_DEVICEDESC = 0x00000000
SPDRP_HARDWAREID = 0x00000001
SPDRP_MFG = 0x0000000B
SPDRP_FRIENDLYNAME = 0x0000000C

CR_SUCCESS = 0
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("ClassGuid", GUID),
        ("DevInst", wintypes.DWORD),
        ("Reserved", ctypes.c_void_p),
    ]


class WindowsMetadataCollector(MetadataCollector):
    """Best-effort local lookup. Never fabricates missing OEM strings."""

    def __init__(self) -> None:
        self._log = get_logger("monitoring.metadata")
        self._kernel32: Any = None
        self._setupapi: Any = None
        self._cfgmgr32: Any = None
        if is_windows():
            self._kernel32, self._setupapi, self._cfgmgr32 = _load_metadata_apis()

    @property
    def mechanism(self) -> str:
        return "windows_setupapi"

    def collect(self, event: USBEvent) -> DeviceMetadata:
        if not is_windows() or self._kernel32 is None:
            return DeviceMetadata(source="unavailable")
        try:
            return self._collect(event)
        except (OSError, ValueError, ctypes.ArgumentError):
            self._log.debug("Metadata lookup failed; leaving unknown fields empty")
            return DeviceMetadata(source=self.mechanism)

    def collect_drive(self, drive_letter: str) -> DeviceMetadata:
        """Inspect a currently mounted letter. Used by --probe-metadata."""
        event = USBEvent(
            event_type=EventType.CONNECT,
            drive_letter=drive_letter,
            source="probe",
        )
        return self.collect(event)

    def _collect(self, event: USBEvent) -> DeviceMetadata:
        letter = normalize_drive_letter(event.drive_letter)
        volume = self._query_volume(letter) if letter else {}
        instance_id = event.pnp_device_id or _instance_id_from_event(event)
        pnp = self._query_pnp(instance_id) if instance_id else {}
        if instance_id and not pnp.get("manufacturer"):
            parent_id = self._parent_instance_id(instance_id)
            if parent_id:
                parent = self._query_pnp(parent_id)
                for key in ("manufacturer", "product_name", "vendor_id", "product_id"):
                    if not pnp.get(key) and parent.get(key):
                        pnp[key] = parent[key]

        vendor_id = event.vendor_id or pnp.get("vendor_id")
        product_id = event.product_id or pnp.get("product_id")
        serial = event.serial_number or pnp.get("serial_number")
        return DeviceMetadata(
            vendor_id=vendor_id,
            product_id=product_id,
            serial_number=serial,
            manufacturer=pnp.get("manufacturer"),
            product_name=pnp.get("product_name"),
            pnp_device_id=instance_id,
            drive_letter=letter,
            filesystem=volume.get("filesystem"),
            capacity=volume.get("capacity"),
            removable=volume.get("removable"),
            volume_label=volume.get("volume_label"),
            source=self.mechanism,
        )

    def _query_volume(self, letter: str) -> dict[str, Any]:
        root = f"{letter}\\"
        drive_type = int(self._kernel32.GetDriveTypeW(root))
        removable: bool | None
        if drive_type in (DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR):
            removable = None
        else:
            removable = drive_type == DRIVE_REMOVABLE

        volume_label = None
        filesystem = None
        label_buf = ctypes.create_unicode_buffer(261)
        fs_buf = ctypes.create_unicode_buffer(261)
        ok = self._kernel32.GetVolumeInformationW(
            root,
            label_buf,
            len(label_buf),
            None,
            None,
            None,
            fs_buf,
            len(fs_buf),
        )
        if ok:
            volume_label = label_buf.value.strip() or None
            filesystem = fs_buf.value.strip() or None

        capacity = None
        total = ctypes.c_ulonglong(0)
        if self._kernel32.GetDiskFreeSpaceExW(root, None, ctypes.byref(total), None):
            capacity = int(total.value)

        return {
            "removable": removable,
            "volume_label": volume_label,
            "filesystem": filesystem,
            "capacity": capacity,
        }

    def _query_pnp(self, instance_id: str) -> dict[str, Any]:
        setup = self._setupapi
        handle = setup.SetupDiCreateDeviceInfoList(None, None)
        if not handle or handle == INVALID_HANDLE_VALUE:
            return {}
        info = SP_DEVINFO_DATA()
        info.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
        try:
            opened = setup.SetupDiOpenDeviceInfoW(handle, instance_id, None, 0, ctypes.byref(info))
            if not opened:
                return {}
            manufacturer = _read_dev_property(setup, handle, info, SPDRP_MFG)
            friendly = _read_dev_property(setup, handle, info, SPDRP_FRIENDLYNAME)
            description = _read_dev_property(setup, handle, info, SPDRP_DEVICEDESC)
            hardware_id = _read_dev_property(setup, handle, info, SPDRP_HARDWAREID)
            vendor_id, product_id = parse_vid_pid_from_path(hardware_id)
            if vendor_id is None:
                vendor_id, product_id = parse_vid_pid_from_path(instance_id.replace("\\", "#"))
            serial = parse_instance_id_from_path(instance_id.replace("\\", "#"))
            if serial is None:
                parts = instance_id.split("\\")
                serial = parts[-1] if len(parts) >= 3 else None
            return {
                "manufacturer": manufacturer,
                "product_name": friendly or description,
                "vendor_id": normalize_hardware_id(vendor_id),
                "product_id": normalize_hardware_id(product_id),
                "serial_number": serial,
                "pnp_device_id": instance_id,
            }
        finally:
            setup.SetupDiDestroyDeviceInfoList(handle)

    def _parent_instance_id(self, instance_id: str) -> str | None:
        if self._cfgmgr32 is None or self._setupapi is None:
            return None
        setup = self._setupapi
        handle = setup.SetupDiCreateDeviceInfoList(None, None)
        if not handle or handle == INVALID_HANDLE_VALUE:
            return None
        info = SP_DEVINFO_DATA()
        info.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
        try:
            if not setup.SetupDiOpenDeviceInfoW(handle, instance_id, None, 0, ctypes.byref(info)):
                return None
            parent = wintypes.DWORD(0)
            status = self._cfgmgr32.CM_Get_Parent(ctypes.byref(parent), info.DevInst, 0)
            if status != CR_SUCCESS:
                return None
            buf = ctypes.create_unicode_buffer(512)
            status = self._cfgmgr32.CM_Get_Device_IDW(parent, buf, len(buf), 0)
            if status != CR_SUCCESS:
                return None
            return buf.value.strip() or None
        finally:
            setup.SetupDiDestroyDeviceInfoList(handle)


def list_removable_drive_letters() -> list[str]:
    """Return currently mounted letters Windows classifies as removable."""
    if not is_windows():
        return []
    kernel32, _, _ = _load_metadata_apis()
    mask = int(kernel32.GetLogicalDrives())
    letters: list[str] = []
    for index in range(26):
        if not mask & (1 << index):
            continue
        letter = f"{chr(ord('A') + index)}:"
        drive_type = int(kernel32.GetDriveTypeW(f"{letter}\\"))
        if drive_type == DRIVE_REMOVABLE:
            letters.append(letter)
    return letters


def _instance_id_from_event(event: USBEvent) -> str | None:
    if event.pnp_device_id:
        return event.pnp_device_id
    if event.vendor_id and event.product_id and event.serial_number:
        return f"USB\\VID_{event.vendor_id}&PID_{event.product_id}\\{event.serial_number}"
    return None


def _read_dev_property(setup: Any, handle: Any, info: SP_DEVINFO_DATA, prop: int) -> str | None:
    buf = ctypes.create_unicode_buffer(1024)
    ok = setup.SetupDiGetDeviceRegistryPropertyW(
        handle,
        ctypes.byref(info),
        prop,
        None,
        ctypes.cast(buf, ctypes.c_void_p),
        ctypes.sizeof(buf),
        None,
    )
    if not ok:
        return None
    text = buf.value.strip()
    return text or None


def _load_metadata_apis() -> tuple[Any, Any, Any]:
    if sys.platform != "win32":
        raise OSError("Windows metadata APIs require win32")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
    cfgmgr32 = ctypes.WinDLL("cfgmgr32", use_last_error=True)

    kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetDriveTypeW.restype = wintypes.UINT
    kernel32.GetLogicalDrives.argtypes = []
    kernel32.GetLogicalDrives.restype = wintypes.DWORD
    kernel32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    kernel32.GetVolumeInformationW.restype = wintypes.BOOL
    kernel32.GetDiskFreeSpaceExW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong),
    ]
    kernel32.GetDiskFreeSpaceExW.restype = wintypes.BOOL

    setupapi.SetupDiCreateDeviceInfoList.argtypes = [ctypes.c_void_p, wintypes.HWND]
    setupapi.SetupDiCreateDeviceInfoList.restype = wintypes.HANDLE
    setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
    setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL
    setupapi.SetupDiOpenDeviceInfoW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.HWND,
        wintypes.DWORD,
        ctypes.POINTER(SP_DEVINFO_DATA),
    ]
    setupapi.SetupDiOpenDeviceInfoW.restype = wintypes.BOOL
    setupapi.SetupDiGetDeviceRegistryPropertyW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(SP_DEVINFO_DATA),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    setupapi.SetupDiGetDeviceRegistryPropertyW.restype = wintypes.BOOL

    cfgmgr32.CM_Get_Parent.argtypes = [
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
        wintypes.ULONG,
    ]
    cfgmgr32.CM_Get_Parent.restype = wintypes.DWORD
    cfgmgr32.CM_Get_Device_IDW.argtypes = [
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    cfgmgr32.CM_Get_Device_IDW.restype = wintypes.DWORD
    return kernel32, setupapi, cfgmgr32
