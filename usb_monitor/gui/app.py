"""Tkinter operator window for local USB monitoring.

The live watcher runs on a worker thread. This module does not open or
execute files from USB media and does not send data off the machine.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import messagebox, ttk

from usb_monitor import __app_name__, __version__
from usb_monitor.gui.present import (
    DISCLAIMER,
    MAX_LIVE_ROWS,
    alert_row,
    device_row,
    event_row,
)
from usb_monitor.inventory import DeviceInventory, DeviceNotFoundError
from usb_monitor.monitoring import USBMonitor, create_monitor
from usb_monitor.monitoring.event_source import EventSourceUnavailableError
from usb_monitor.reports import build_local_report, export_report
from usb_monitor.storage import AlertStore, EventStore
from usb_monitor.utils.logger import get_logger
from usb_monitor.utils.platform import UnsupportedPlatformError

MonitorFactory = Callable[[], USBMonitor]


class MonitorApp:
    """Local ttk window: live events, inventory, alerts, trust, report export."""

    def __init__(
        self,
        root: tk.Tk,
        *,
        monitor_factory: MonitorFactory | None = None,
    ) -> None:
        self._root = root
        self._factory = monitor_factory or create_monitor
        self._log = get_logger("gui")
        self._monitor: USBMonitor | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._build()
        self.refresh_tables()
        self._root.after(200, self._pump)
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build(self) -> None:
        self._root.title(f"{__app_name__} {__version__}")
        self._root.geometry("960x560")
        self._root.minsize(720, 420)

        header = ttk.Frame(self._root, padding=8)
        header.pack(fill=tk.X)
        ttk.Label(header, text=__app_name__, font=("Segoe UI", 14, "bold")).pack(
            anchor=tk.W
        )
        ttk.Label(header, text=DISCLAIMER, wraplength=900).pack(anchor=tk.W, pady=(4, 0))

        controls = ttk.Frame(self._root, padding=(8, 0, 8, 8))
        controls.pack(fill=tk.X)
        self._start_btn = ttk.Button(controls, text="Start", command=self.start_monitor)
        self._start_btn.pack(side=tk.LEFT)
        self._stop_btn = ttk.Button(
            controls, text="Stop", command=self.stop_monitor, state=tk.DISABLED
        )
        self._stop_btn.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(controls, text="Refresh", command=self.refresh_tables).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Button(controls, text="Export report", command=self.export_report).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Button(controls, text="Trust selected", command=self._trust_selected).pack(
            side=tk.LEFT, padx=(16, 0)
        )
        ttk.Button(
            controls, text="Untrust selected", command=self._untrust_selected
        ).pack(side=tk.LEFT, padx=(8, 0))
        self._status = tk.StringVar(value="Idle. Start listening to watch local USB activity.")
        ttk.Label(controls, textvariable=self._status).pack(side=tk.LEFT, padx=(16, 0))

        notebook = ttk.Notebook(self._root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self._events = self._make_tree(
            notebook,
            "Events",
            ("time", "type", "identity", "risk"),
            {"time": 180, "type": 140, "identity": 280, "risk": 140},
        )
        self._devices = self._make_tree(
            notebook,
            "Devices",
            ("identity", "name", "connections", "trusted", "risk", "last_seen"),
            {
                "identity": 220,
                "name": 160,
                "connections": 90,
                "trusted": 80,
                "risk": 120,
                "last_seen": 180,
            },
        )
        self._alerts = self._make_tree(
            notebook,
            "Alerts",
            ("time", "severity", "title", "identity"),
            {"time": 180, "severity": 90, "title": 280, "identity": 220},
        )

    def _make_tree(
        self,
        notebook: ttk.Notebook,
        title: str,
        columns: tuple[str, ...],
        widths: dict[str, int],
    ) -> ttk.Treeview:
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=title)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for name in columns:
            tree.heading(name, text=name.replace("_", " ").title())
            tree.column(name, width=widths.get(name, 120), stretch=True)
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        return tree

    def start_monitor(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        try:
            self._monitor = self._factory()
        except (UnsupportedPlatformError, EventSourceUnavailableError) as exc:
            messagebox.showerror(__app_name__, str(exc))
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._worker,
            name="usb-gui-monitor",
            daemon=True,
        )
        self._thread.start()
        self._start_btn.configure(state=tk.DISABLED)
        self._stop_btn.configure(state=tk.NORMAL)
        self._status.set("Listening. Plug or unplug authorized USB storage.")

    def stop_monitor(self) -> None:
        self._stop.set()
        self._start_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)
        self._status.set("Stopping...")

    def _worker(self) -> None:
        monitor = self._monitor
        if monitor is None:
            return
        try:
            monitor.run(
                None,
                on_event=lambda event: self._queue.put(("event", event)),
                stop_when=self._stop.is_set,
            )
        except (UnsupportedPlatformError, EventSourceUnavailableError) as exc:
            self._queue.put(("error", str(exc)))
        except Exception as exc:
            self._log.exception("GUI monitor worker failed")
            self._queue.put(("error", str(exc)))
        finally:
            self._queue.put(("stopped", None))

    def _pump(self) -> None:
        while True:
            try:
                kind, payload = self._queue.get_nowait()
            except queue.Empty:
                break
            if kind == "event":
                self._append_event(payload)
                self.refresh_tables(live_event=payload)
            elif kind == "error":
                messagebox.showerror(__app_name__, str(payload))
                self._mark_idle("Idle.")
            elif kind == "stopped":
                self._mark_idle("Stopped.")
                self.refresh_tables()
        if self._root.winfo_exists():
            self._root.after(200, self._pump)

    def _append_event(self, event: object) -> None:
        from usb_monitor.models.event import USBEvent

        if not isinstance(event, USBEvent):
            return
        self._events.insert("", 0, values=event_row(event))
        children = self._events.get_children()
        if len(children) > MAX_LIVE_ROWS:
            for iid in children[MAX_LIVE_ROWS:]:
                self._events.delete(iid)

    def refresh_tables(self, live_event: object | None = None) -> None:
        inventory = self._live_inventory()
        devices = (
            inventory.list_devices()
            if inventory is not None
            else DeviceInventory.load().list_devices()
        )
        self._fill(
            self._devices,
            [device_row(item) for item in devices],
            iids=[item.device_id for item in devices],
        )
        if live_event is None:
            events = list(reversed(EventStore.load().list_events()))[:MAX_LIVE_ROWS]
            self._fill(self._events, [event_row(item) for item in events])
        if self._monitor is not None:
            alerts = list(reversed(self._monitor.alerts.list_alerts()))[:MAX_LIVE_ROWS]
        else:
            alerts = list(reversed(AlertStore.load().list_alerts()))[:MAX_LIVE_ROWS]
        self._fill(self._alerts, [alert_row(item) for item in alerts])

    def _fill(
        self,
        tree: ttk.Treeview,
        rows: list[tuple[str, ...]],
        iids: list[str] | None = None,
    ) -> None:
        selected = tree.selection()
        tree.delete(*tree.get_children())
        for index, row in enumerate(rows):
            iid = iids[index] if iids is not None else str(index)
            tree.insert("", tk.END, iid=iid, values=row)
        if selected:
            try:
                tree.selection_set(selected)
            except tk.TclError:
                pass

    def _live_inventory(self) -> DeviceInventory | None:
        if self._monitor is not None:
            return self._monitor.inventory
        return None

    def _selected_device_id(self) -> str | None:
        selection = self._devices.selection()
        if not selection:
            messagebox.showinfo(__app_name__, "Select a device in the Devices tab first.")
            return None
        return str(selection[0])

    def _trust_selected(self) -> None:
        self._set_trust(True)

    def _untrust_selected(self) -> None:
        self._set_trust(False)

    def _set_trust(self, trusted: bool) -> None:
        device_id = self._selected_device_id()
        if not device_id:
            return
        inventory = self._live_inventory() or DeviceInventory.load()
        try:
            device = inventory.set_trusted(device_id, trusted)
        except DeviceNotFoundError:
            messagebox.showerror(__app_name__, f"Device not in inventory: {device_id}")
            return
        state = "trusted" if device.trusted else "untrusted"
        self._status.set(f"{device.safe_device_id} is now {state}. Events are still recorded.")
        self.refresh_tables()

    def export_report(self, directory: Path | None = None) -> None:
        try:
            report = build_local_report(limit=0)
            written = export_report(report, directory)
        except (OSError, ValueError) as exc:
            messagebox.showerror(__app_name__, str(exc))
            return
        folder = written[0].parent if written else directory
        self._status.set(f"Wrote {len(written)} report file(s) under {folder}/")

    def _mark_idle(self, text: str) -> None:
        self._start_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)
        self._status.set(text)
        self._monitor = None

    def _on_close(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=3.0)
        self._root.destroy()


def launch(*, monitor_factory: MonitorFactory | None = None) -> int:
    """Open the local operator window. Returns when the window is closed."""
    root = tk.Tk()
    MonitorApp(root, monitor_factory=monitor_factory)
    root.mainloop()
    return 0
