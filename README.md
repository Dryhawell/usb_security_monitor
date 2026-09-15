# USB Security Monitor

Defensive endpoint-security tool that monitors USB and removable-storage
activity on a local Windows computer you own or are authorized to administer.

This project is intended for:

- cybersecurity portfolio work
- Blue Team / SOC learning
- endpoint security fundamentals
- Windows-focused USB event monitoring

**Current status:** v1.0.0 — planned scope is complete (live watch, inventory,
explainable scoring, local alerts/storage, CLI, reports, GUI, tests, docs,
review). Heuristic scores are **not** a malware verdict. See
[docs/REVIEW.md](docs/REVIEW.md).

## Overview

USB Security Monitor watches for removable-storage connection and
disconnection events, records them locally, maintains a device inventory,
and scores *suspicious characteristics* using explainable rules.

It does **not** determine whether a device is actually malicious. It does
not scan firmware, execute files from USB media, or replace antivirus or
EDR software.

Further reading:

- [Architecture](docs/ARCHITECTURE.md) — pipeline, identity, storage
- [Scoring and alerts](docs/SCORING.md) — rules, bands, cooldown
- [Review](docs/REVIEW.md) — strengths, limits, SOC caveats, test gaps

## Why This Project Exists

Removable media remains a common path for data loss and malware introduction.
Blue Team work often starts with visibility: knowing which devices appeared,
when they appeared, and whether they were seen before. This project teaches
that visibility layer — inventory, first-seen detection, and simple
anomaly signals — without crossing into offensive USB techniques.

## Features

- Detect USB/removable storage connect and disconnect events
- Collect available device metadata (VID/PID, product, drive letter, …)
- Maintain a local device inventory (first seen / last seen / count)
- First-seen vs known-device detection
- Explainable rule-based risk scoring (heuristic, not a malware verdict)
- Sliding-window anomaly signals (rapid reconnect, event flaps, new-device bursts)
- Local session alerts with fingerprint deduplication and cooldown
- Local JSON storage (`events.json`, `alerts.json`, `devices.json`) with a newest-record cap on events and alerts
- CLI subcommands to list inventory, events, and alerts
- Local report export (JSON, CSV, and human-readable text under `data/reports/`)
- Unit tests with a mocked event source (`pytest`, no USB hardware)
- Threading, exception isolation, and graceful shutdown for the live watcher
- Optional local GUI (tkinter) for operators who prefer a window over the CLI

Deferred items (not in v1.0.0): extra rule tests and optional local
JSON encryption. See [docs/REVIEW.md](docs/REVIEW.md).

## Privacy

The application operates **entirely locally**.

It will:

- store events, inventory, alerts, and logs under this project directory
- never upload telemetry
- never contact external servers
- never transmit device information
- never collect unrelated personal data

Local paths:

- `data/events/` — event records (`events.json`, newest 5000 kept)
- `data/inventory/` — observed devices (`devices.json`)
- `data/alerts/` — emitted alerts (`alerts.json`, newest 2000 kept)
- `data/reports/` — exported reports (`usb-report-*.json`, `*.csv`, `*.txt`)
- `logs/usb_monitor.log` — application log

Serial numbers and similar identifiers are treated as sensitive local
device identifiers. Console, logs, and the GUI mask them. Local JSON
stores and JSON/CSV report files keep unmasked values for forensics on
this machine only.

## Responsible Use

This project is intended for defensive monitoring on systems and devices
you own or are authorized to administer. Do not use it to monitor other
people’s computers or devices without authorization.

## Limitations

This tool cannot determine with certainty whether a USB device is malicious.

It does not:

- scan USB firmware
- detect BadUSB attacks reliably
- analyze malicious firmware
- perform antivirus scanning
- inspect every file on removable media
- guarantee device authenticity
- replace endpoint security software

USB hard disks often appear to Windows as `DRIVE_FIXED`. Missing serials
are common on honest devices. First-seen plus a missing serial must not
be treated as CRITICAL.

## Installation

Python 3.11 or newer is required (developed on Windows 11 / Python 3.11.9).

```powershell
cd usb_security_monitor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

The application has no third-party runtime dependencies. `pytest` is
test-only. The GUI uses stdlib `tkinter`.

## Usage

```powershell
python main.py --help
python main.py --version
python main.py status
python main.py monitor --timeout 20
python main.py gui
python main.py devices
python main.py events --limit 20 --type CONNECT
python main.py alerts --severity HIGH
python main.py report
python main.py report --export
python main.py report --export --format json
python main.py trust DEVICE_ID
python main.py untrust DEVICE_ID
```

Legacy flags such as `--status`, `--monitor`, `--devices`, `--trust`,
`--untrust`, and `--gui` still work.

Live monitor and GUI do **not** open or execute files on USB media.
Ctrl+C (CLI) or Stop / close window (GUI) shuts the watcher down.

Offline checks (no USB hardware). `--demo-*` flags are unchanged;
implementations live in `usb_monitor.demos`:

```powershell
python main.py --demo-cli
python main.py --demo-gui
python main.py --demo-reliability
python main.py --demo-report
python main.py --demo-storage
python main.py --demo-alerts
python main.py --demo-risk
python main.py --demo-anomaly
python main.py --demo-inventory
python main.py --demo-normalize
python main.py --demo-metadata
python main.py --demo-models
python main.py --probe-source
python main.py --probe-metadata
python main.py --listen-source --timeout 20
```

## Tests

Tests use `MockEventSource` and never open USB files or talk to
`WM_DEVICECHANGE`.

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

## Architecture

```
Windows Event Source  (or MockEventSource in tests)
        ↓
   USB Monitor
        ↓
 Device Inventory
        ↓
  Risk Analyzer
        ↓
  Alert Manager
     ↓       ↓
Event Store  Report Export (JSON / CSV / text)
                 ↓
            CLI / local GUI
```

Platform-specific monitoring is kept separate from analysis, storage,
and presentation. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

MIT License. See [LICENSE](LICENSE).
