# Architecture

USB Security Monitor is a local Blue Team visibility tool. Detection,
analysis, storage, and presentation are separate layers. None of them
execute USB files or send data off the machine.

## Pipeline

```
WM_DEVICECHANGE
  hidden top-level window + RegisterDeviceNotification
        ↓
  RawDeviceEvent (USB / disk / volume)
        ↓
  EventNormalizer
  quiet 0.5s / max 2s; drop disk-only bursts
  different USB serials stay separate even if VID/PID match
        ↓
  USBEvent CONNECT / DISCONNECT
        ↓
  WindowsMetadataCollector (fill empty fields only)
        ↓
  DeviceInventory.observe()
  FIRST_SEEN or KNOWN_DEVICE
        ↓
  Analyzer (CONNECT only; DISCONNECT still updates windows)
        ↓
  AlertManager.consider() (dedup + 60s cooldown)
        ↓
  EventStore / AlertStore  (create_monitor path)
        ↓
  CLI, reports, or tkinter GUI
```

`USBMonitor.run()` isolates per-stage failures. A metadata, disk, or
callback error must not kill the watcher. `stop()` is idempotent.
The Windows message thread is non-daemon so shutdown can join it.

## Event source

Live watching is Windows-only (`windows_wm_devicechange`).

A message-only window misses device-change broadcasts, so the source
uses a hidden top-level window. Tests and demos use `MockEventSource`,
which never talks to `WM_DEVICECHANGE`. Live plug/unplug checks with
authorized storage: [HARDWARE.md](HARDWARE.md).

The GUI runs Tk on the main thread and `USBMonitor.run(timeout=None,
stop_when=...)` on a worker. The Windows source keeps its own thread.

## Identity

Preferred identity is `VID:PID:SERIAL` when the OS exposed a serial.
The model never fabricates missing manufacturer, serial, or VID/PID.
The coalescer keeps two USB paths separate when both expose an
instance/serial and those values differ, even if VID/PID match.

Volume label is not treated as manufacturer. USB hard disks often
report as `DRIVE_FIXED` (`removable=False`). Trust is an operator flag;
it does not hide CONNECT/DISCONNECT events.

Console, logs, and the GUI mask serials (`********1234`). Local JSON
and JSON/CSV report files keep unmasked identifiers for local forensics
unless store DPAPI is enabled (`USB_MONITOR_DPAPI=1`). Reports stay
plaintext even then.

## Storage

Writes use a temp file plus replace, then an owner-only ACL (Windows
DACL / POSIX 0600). New `events.json` / `alerts.json` / `devices.json`
writes may be DPAPI-wrapped when `USB_MONITOR_DPAPI=1` (Windows user
key; same user can still decrypt). Report exports stay plaintext.
Paths stay under this project:

| Path | Content |
|---|---|
| `data/events/events.json` | newest 5000 events; `dropped_total` counts oldest rows removed by the cap |
| `data/alerts/alerts.json` | newest 2000 emitted alerts; same `dropped_total` counter |
| `data/inventory/devices.json` | observed identities |
| `data/reports/` | exported JSON / CSV / text |
| `logs/usb_monitor.log` | rotating application log |

Suppressed cooldown hits are not written to disk. Event and alert files
drop the oldest rows when the cap is hit and persist how many were
removed (`dropped_total`). Inventory is not capped so first-seen history
remains. Dropped rows are not archived. `create_monitor()` persists;
demos that must not touch `data/` pass `path=None`.

## Presentation

CLI subcommands: `status`, `monitor`, `devices`, `events`, `alerts`,
`report`, `trust`, `untrust`, `gui`. Offline `--demo-*` checks live in
`usb_monitor.demos`; `main.py` only dispatches them.

`report` prints a masked summary. `report --export` writes files under
`data/reports/`. The GUI shows the same records and can export without
opening USB media.

Limitations and SOC caveats: [REVIEW.md](REVIEW.md). Manual hardware
checklist: [HARDWARE.md](HARDWARE.md).
