# Phase 18 review

Defensive Blue Team / code-quality review of USB Security Monitor as of
`feat/project-docs` (GUI + docs stack). This is not a malware-detection
claim or a pentest. Phase 19 stamped this tree as **v1.0.0** without
merging the stacked PRs into `main`.

Scope: local endpoint USB/removable-storage visibility. The tool must
not exploit devices, execute USB contents, hide itself, or send
telemetry.

## Architecture strengths

- **Layering.** Detection (`EventSource`), coalescing (`EventNormalizer`),
  inventory, explainable scoring, alerts, JSON storage, and
  CLI/GUI/reports stay separate. Analysis cannot invent VID/PID/serial.
- **Event-based Windows source.** `WM_DEVICECHANGE` via a hidden
  top-level window (message-only windows miss broadcasts). Stdlib
  `ctypes` only; no WMI poll loop and no pywin32.
- **Honest identity.** Prefer `VID:PID:SERIAL`; never fabricate
  manufacturer or serial. Volume label is not OEM. Trust does not hide
  CONNECT/DISCONNECT.
- **Operator-safe output.** Console, logs, and GUI mask serials.
  JSON/CSV on disk stay local forensics, not telemetry.
- **Failure isolation.** `USBMonitor.run()` / `_queue_event` catch
  metadata, store, and callback errors so one bad notification should
  not kill the watcher. `stop()` is idempotent. WndProc must not leak
  Python exceptions into `user32`.
- **Test seam.** `MockEventSource` plus `feed`/`replay`/`FakeClock`
  cover coalescing, first-seen, scoring bands, cooldown, storage, and
  GUI construction without USB hardware.

## Limitations (product)

These are by design, not bugs:

- Heuristic scores are **not** a malware verdict and not CVSS.
- No firmware / BadUSB / HID-as-keyboard authenticity check.
- No antivirus scan and no inspection of files on the stick.
- USB hard disks often appear as `DRIVE_FIXED` (`removable=False`).
- First-seen + missing serial must not be treated as CRITICAL.
- Live watching is Windows-only. Models, storage, reports, and tests
  still run elsewhere.
- Anomaly windows are **session memory**; they reset when the process
  exits.
- Cooldown-suppressed alerts are not written to disk.

## Residual risks / SOC caveats

| Caveat | Why it matters |
|---|---|
| Visibility ≠ containment | The tool records plug/unplug. It does not block, eject, or scan the device. |
| HID / composite devices | A BadUSB keyboard may show as a USB interface with no volume. Absence of a drive letter is not proof of malice or safety. |
| Same VID:PID in 0.5s | USB paths with different instance/serial segments stay separate. Disk/volume follow-ups without a serial still merge into the open burst. Two sticks that expose no serial can still merge. |
| Dropped raw events | The Windows source queue is bounded (1024). When full, a raw event is logged and dropped. |
| Capped JSON history | `events.json` keeps the newest 5000 records; `alerts.json` keeps 2000. Older rows are dropped, not archived. Inventory stays uncapped. |
| Local plaintext identifiers | By default `devices.json` / `events.json` / JSON-CSV reports store unmasked serials. Writes apply an owner-only ACL. Set `USB_MONITOR_DPAPI=1` to wrap new store JSON with the current Windows user DPAPI key; reports stay plaintext. Anyone who can run as this user can still decrypt. |
| Trust is an operator flag | `TRUSTED_DEVICE` (−10) lowers the heuristic. It is not an allowlist and not a safety guarantee. |
| GUI worker vs Windows thread | Tk is main-thread; monitor worker is daemon; Windows pump is non-daemon. A hung `GetMessageW` can delay process exit after Stop. |
| Stacked PRs vs `main` | v1.0.0 is on `main`. Later hardening lands as ordinary PRs against `main`. |
| No remote SOC integration | There is no syslog/SIEM shipper. That is correct for “local only”; an analyst must copy reports by hand. |

Do not treat HIGH/CRITICAL or `SUSPICIOUS_DEVICE` as “this stick is
malware.” They mean stacked observed characteristics.

## Test coverage

`python -m pytest` currently has **64** tests. They are hardware-free
and that is appropriate.

Covered well:

- Mock source contract
- USB+disk+volume coalescing and disk-only drop
- Two same-VID:PID USB paths with different serials stay separate
- First-seen vs known
- First-seen + missing serial is not CRITICAL
- Rapid reconnect, alert cooldown, severity escalation
- Identity change (`IDENTITY_INCONSISTENCY`) and trusted −10 mitigation
- Corrupt JSON recovery, report mask vs JSON serial
- Event/alert store newest-record cap
- Poll/metadata/store isolation, idempotent stop
- GUI row masking and window construct/destroy
- `--demo-*` flags still dispatch through `main.py`
- Owner-only ACL after atomic JSON/report writes
- Optional DPAPI wrapping of store JSON (`USB_MONITOR_DPAPI=1`)
- Raw Windows source queue drops when full (bounded, logged)
- GUI Start/Stop/export with a mocked source (no USB hardware)
- Offline `--demo-*` bodies return OK without USB hardware

Gaps (honest, not a failing grade):

- No live `WM_DEVICECHANGE` / SetupAPI integration test in pytest
  (needs Windows and authorized hardware). Follow
  [HARDWARE.md](HARDWARE.md): `--probe-source`, `--monitor`, `gui`.

## Follow-ups

### Phase 19 (v1.0.0) — done

- `__version__` is `1.0.0`; README status marks the planned scope complete.
- Malware-disclaimer language remains on CLI, GUI, reports, and README.
- Stacked PRs later merged to `main` (v1.0.0).
- Event/alert store record cap is post-1.0 hardening (newest 5000
  events / 2000 alerts). Coalescing uses instance/serial when both
  sides of a match expose one.
- Offline `--demo-*` implementations live in `usb_monitor.demos`.
- JSON/report writes apply an owner-only ACL (still plaintext, still
  local).
- Rule tests cover manufacturer identity change and trusted −10.
- Manual hardware checklist lives in `docs/HARDWARE.md` (authorized
  sticks only; pytest stays mock-only).
- Optional DPAPI for store JSON (`USB_MONITOR_DPAPI=1`; reports stay
  plaintext; still no telemetry).
- Raw event queue drop when full is covered without starting the live
  watcher.
- GUI Start/Stop/export is driven with MockEventSource (no USB media).
- Offline `--demo-*` flags run as pytest (still no USB hardware;
  `--demo-gui` is covered by the GUI window tests).

### Later (not v1.0 blockers)

- None currently tracked. Further work is ordinary product follow-up.

## Verdict

The tree is a coherent **local USB visibility** portfolio piece: layered,
explainable, and explicit about what it cannot do. v1.0.0 is a version
and documentation stamp of this stacked tree. It is **not** an EDR,
antivirus, or BadUSB detector.
