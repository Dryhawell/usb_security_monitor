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
| Same VID:PID in 0.5s | Coalescing matches action + VID/PID (+ drive letter). Two sticks that share a VID:PID in the quiet window can merge; the first instance/serial wins. |
| Dropped raw events | The Windows source queue is bounded (1024). When full, a raw event is logged and dropped. |
| Capped JSON history | `events.json` keeps the newest 5000 records; `alerts.json` keeps 2000. Older rows are dropped, not archived. Inventory stays uncapped. |
| Local plaintext identifiers | `devices.json` / `events.json` / JSON-CSV reports store unmasked serials. Anyone with the user profile can read them. |
| Trust is an operator flag | `TRUSTED_DEVICE` (−10) lowers the heuristic. It is not an allowlist and not a safety guarantee. |
| GUI worker vs Windows thread | Tk is main-thread; monitor worker is daemon; Windows pump is non-daemon. A hung `GetMessageW` can delay process exit after Stop. |
| Stacked PRs vs `main` | v1.0.0 is on `main`. Later hardening lands as ordinary PRs against `main`. |
| No remote SOC integration | There is no syslog/SIEM shipper. That is correct for “local only”; an analyst must copy reports by hand. |

Do not treat HIGH/CRITICAL or `SUSPICIOUS_DEVICE` as “this stick is
malware.” They mean stacked observed characteristics.

## Test coverage

`python -m pytest` currently has **31** tests. They are hardware-free
and that is appropriate.

Covered well:

- Mock source contract
- USB+disk+volume coalescing and disk-only drop
- First-seen vs known
- First-seen + missing serial is not CRITICAL
- Rapid reconnect, alert cooldown, severity escalation
- Corrupt JSON recovery, report mask vs JSON serial
- Event/alert store newest-record cap
- Poll/metadata/store isolation, idempotent stop
- GUI row masking and window construct/destroy

Gaps (honest, not a failing grade):

- No live `WM_DEVICECHANGE` / SetupAPI integration test (needs Windows
  and authorized hardware; keep it manual: `--probe-source`,
  `--monitor`, `gui`).
- No test that two same-VID:PID bursts in the quiet window stay
  distinct.
- No test for identity-change (`IDENTITY_INCONSISTENCY`) or trusted
  −10 mitigation.
- No test that the raw queue drops when full.
- `main.py` demos are not pytest; they are operator checks.
- GUI Start/Stop/export paths are not driven end-to-end (would need a
  longer Tk loop).

## Follow-ups

### Phase 19 (v1.0.0) — done

- `__version__` is `1.0.0`; README status marks the planned scope complete.
- Malware-disclaimer language remains on CLI, GUI, reports, and README.
- Stacked PRs later merged to `main` (v1.0.0).
- Event/alert store record cap is post-1.0 hardening (newest 5000
  events / 2000 alerts). Coalescing-key rewrite stays deferred.

### Later (not v1.0 blockers)

- Split `main.py` demos out of the entry point.
- Optional coalescing key that includes instance/serial when present.
- Optional local encryption or tighter ACLs for JSON (still no
  telemetry).
- Broader rule unit tests (identity change, trusted mitigation).
- Manual hardware test notes in docs (authorized sticks only).

## Verdict

The tree is a coherent **local USB visibility** portfolio piece: layered,
explainable, and explicit about what it cannot do. v1.0.0 is a version
and documentation stamp of this stacked tree. It is **not** an EDR,
antivirus, or BadUSB detector.
