# Manual hardware checks

Live `WM_DEVICECHANGE` and SetupAPI lookups need a Windows machine and
physical media. pytest never talks to USB hardware. This checklist is
the operator substitute.

Use only a computer you own or are authorized to administer, and only a
USB storage device you are authorized to plug in. Do not open or execute
files on the media. Do not treat HIGH/CRITICAL or `SUSPICIOUS_DEVICE` as
a malware verdict. This is not a pentest, BadUSB lab, or firmware test.

## Ground rules

- Standard user is enough. Do not disable antivirus, UAC, or Windows
  Defender for these checks.
- Unknown or untrusted sticks are out of scope. Do not “test malware”
  with this tool.
- Console, logs, and the GUI mask serials. Local JSON under `data/`
  keeps unmasked identifiers for forensics on this endpoint unless
  `USB_MONITOR_DPAPI=1` is set. Report exports stay plaintext.
- USB hard disks often appear as `DRIVE_FIXED` (`removable=False`).
  That is expected, not a failed check.

## No stick required

```powershell
python main.py status
python main.py --probe-source
```

`status` should show live monitoring as supported on Windows.
`--probe-source` starts and stops the hidden-window source without
waiting for a device. If that fails, do not continue to listen/monitor.

## One authorized storage stick

Keep Explorer closed on the volume. The monitor does not open files;
you should not either.

### Raw notifications

```powershell
python main.py --listen-source --timeout 20
```

Plug the stick once. Expect several RAW lines (USB interface, disk,
volume). Serials in the path should be masked. Ctrl+C is safe.

### Coalesced CONNECT / DISCONNECT

```powershell
python main.py monitor --timeout 30
```

1. Plug once. Expect **one** CONNECT (not one event per raw line).
2. Unplug. Expect DISCONNECT.
3. Plug again. Expect CONNECT for a known identity (`KNOWN_DEVICE` in
   inventory status), not a second first-seen of the same serial.
4. Ctrl+C stops the watcher.

Then:

```powershell
python main.py devices
python main.py events --limit 10
python main.py alerts --limit 10
```

The listing must mask serials. `data/events/events.json` and
`data/inventory/devices.json` may still contain the unmasked serial on
disk.

### Metadata without opening files

With the stick still mounted:

```powershell
python main.py --probe-metadata
```

This reads volume information Windows already exposed (drive type,
filesystem, capacity). It does not enumerate or execute files.

### GUI

```powershell
python main.py gui
```

Start, plug/unplug the same authorized stick, confirm the row masks the
serial, Stop, close the window. Do not use Start as a way to browse the
stick.

## Optional observations

These are product limits, not failed checks:

| Observation | What it means |
|---|---|
| No drive letter | Interface-only / composite device. Absence of a volume is not malice or safety. |
| Missing serial | Common on honest devices. First-seen + missing serial must not be CRITICAL. |
| `removable=False` on a USB disk | Windows often reports USB HDD as fixed. |
| Two authorized sticks, same VID:PID, different serials, plugged in the same quiet window | Two CONNECT events if both USB paths expose a serial. Volume-only sticks with no serial can still merge. |
| `python main.py trust DEVICE_ID` then replug | CONNECT still appears. Trust only lowers the heuristic. |

## Out of scope

Do not use this checklist to:

- scan or execute files on the stick
- prove firmware authenticity or BadUSB
- block, eject, or contain a device
- test on someone else’s computer or with someone else’s media

Automated coverage remains `python -m pytest` with `MockEventSource`.
Scoring bands: [SCORING.md](SCORING.md). Limits: [REVIEW.md](REVIEW.md).
