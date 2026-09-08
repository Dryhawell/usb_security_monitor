"""Session alert package — generation, dedup, and cooldown. Not persistence."""

from usb_monitor.alerts.manager import (
    DEFAULT_COOLDOWN_SECONDS,
    AlertDecision,
    AlertManager,
    AlertStats,
    attach_decision,
    format_alert,
)

__all__ = [
    "DEFAULT_COOLDOWN_SECONDS",
    "AlertDecision",
    "AlertManager",
    "AlertStats",
    "attach_decision",
    "format_alert",
]
