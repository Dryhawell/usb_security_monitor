# Scoring and alerts

Scores are an internal heuristic, not a malware verdict and not CVSS.
First-seen plus a missing serial must not reach CRITICAL by themselves.

## Risk bands

| Score | Band |
|---|---|
| 0–20 | LOW |
| 21–50 | MEDIUM |
| 51–75 | HIGH |
| 76–100 | CRITICAL |

HIGH/CRITICAL also emit a `SUSPICIOUS_DEVICE` event. That still means
"stacked observed characteristics", not confirmed malware.

## Rules

CONNECT events are scored. DISCONNECT is recorded for anomaly windows
only.

| Rule ID | Score | Meaning |
|---|---|---|
| `FIRST_SEEN_DEVICE` | +15 | Identity was not in local inventory |
| `UNKNOWN_MANUFACTURER` | +10 | OS did not expose a manufacturer |
| `MISSING_SERIAL` | +8 | No serial/instance id |
| `WEAK_IDENTITY` | +10 | Drive letter or VID:PID only |
| `GENERIC_OR_SUSPICIOUS_NAME` | +8 | Generic/suspicious name pattern |
| `DEVICE_TYPE_MISMATCH` | +12 | Type vs storage attributes disagree |
| `IDENTITY_INCONSISTENCY` | +30 | Known identity changed manufacturer/serial/VID/PID |
| `UNEXPECTED_REMOVABLE` | +12 | Known non-removable became removable |
| `RAPID_RECONNECT` | +10 | Same identity, 3 CONNECTs / 15s |
| `REPEATED_EVENTS` | +8 | 4 CONNECT/DISCONNECT / 20s |
| `MULTIPLE_NEW_DEVICES` | +20 | 3 first-seen identities / 60s |
| `TRUSTED_DEVICE` | −10 | Operator trusted flag (not a safety guarantee) |

Anomaly windows live in session memory and use event timestamps so
demos can replay a timeline without sleeping.

## Alerts

One candidate per CONNECT, in this priority:

1. CRITICAL / HIGH / identity change → `device|suspicious`
2. Multiple new devices → `host|multiple_new`
3. MEDIUM score → `device|elevated`
4. Rapid reconnect / flap → `device|flap`
5. First-seen → `device|first_seen`

The same fingerprint is suppressed for 60 seconds unless severity
escalates. Suppressed hits are not stored. Trust does not hide
CONNECT/DISCONNECT; it only reduces heuristic weight.
