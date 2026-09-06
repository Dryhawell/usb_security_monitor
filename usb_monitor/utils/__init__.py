"""Shared utilities for USB Security Monitor."""

from usb_monitor.utils.logger import get_logger, mask_identifier, setup_logging
from usb_monitor.utils.permissions import check_permissions
from usb_monitor.utils.platform import detect_platform, is_windows
from usb_monitor.utils.time import format_display, utc_now

__all__ = [
    "check_permissions",
    "detect_platform",
    "format_display",
    "get_logger",
    "is_windows",
    "mask_identifier",
    "setup_logging",
    "utc_now",
]
