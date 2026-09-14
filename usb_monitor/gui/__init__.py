"""Optional local operator GUI (tkinter)."""

from usb_monitor.gui.present import DISCLAIMER, alert_row, device_row, event_row

__all__ = ["DISCLAIMER", "alert_row", "device_row", "event_row", "run_gui"]


def run_gui(*, monitor_factory=None) -> int:
    """Start the Tk window. Imported lazily so CLI help works without Tk."""
    try:
        from usb_monitor.gui.app import launch
    except ImportError as exc:
        print(f"GUI is unavailable (tkinter missing?): {exc}")
        return 1
    return launch(monitor_factory=monitor_factory)
