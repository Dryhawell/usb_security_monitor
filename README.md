# USB Security Monitor

Defensive endpoint-security tool that monitors USB and removable-storage
activity on a local Windows computer you own or are authorized to administer.

This project is intended for:

- cybersecurity portfolio work
- Blue Team / SOC learning
- endpoint security fundamentals
- Windows-focused USB event monitoring

**Current status:** Phase 2 — data models (`Device`, `USBEvent`, `Alert`).
Device monitoring, analysis, inventory, and CLI commands are not
implemented yet.

## Overview

USB Security Monitor watches for removable-storage connection and
disconnection events, records them locally, maintains a device inventory,
and scores *suspicious characteristics* using explainable rules.

It does **not** determine whether a device is actually malicious. It does
not scan firmware, execute files from USB media, or replace antivirus or
EDR software.

## Why This Project Exists

Removable media remains a common path for data loss and malware introduction.
Blue Team work often starts with visibility: knowing which devices appeared,
when they appeared, and whether they were seen before. This project teaches
that visibility layer — inventory, first-seen detection, and simple
anomaly signals — without crossing into offensive USB techniques.

## Features (planned)

- Detect USB/removable storage connect and disconnect events
- Collect available device metadata (VID/PID, product, drive letter, …)
- Maintain a local device inventory (first seen / last seen / count)
- First-seen vs known-device detection
- Explainable rule-based risk scoring
- Local alerts with deduplication
- JSON event/inventory storage
- CLI reports (human-readable, JSON, CSV)
- Unit tests with a mocked event source

## Privacy

The application operates **entirely locally**.

It will:

- store events, inventory, alerts, and logs under this project directory
- never upload telemetry
- never contact external servers
- never transmit device information
- never collect unrelated personal data

Planned local paths:

- `data/events/` — event records
- `data/inventory/` — observed devices
- `data/reports/` — exported reports
- `logs/usb_monitor.log` — application log

Serial numbers and similar identifiers are treated as sensitive local
device identifiers and are masked in default log output.

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

## Installation

Python 3.12 or newer is required.

```powershell
cd usb_security_monitor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Phase 1 has no third-party runtime dependencies.

## Usage

```powershell
python main.py --help
python main.py
python main.py --version
python main.py --verbose
python main.py --demo-models
```

## Architecture (target)

```
Windows Event Source
        ↓
   USB Monitor
        ↓
 Device Inventory
        ↓
  Risk Analyzer
        ↓
  Alert Manager
     ↓       ↓
Event Store  CLI / (later) GUI
```

Platform-specific monitoring is kept separate from analysis, storage,
and presentation. Those layers are added in later phases.

## License

MIT License. See [LICENSE](LICENSE).
