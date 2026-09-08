"""In-memory USB alerts with fingerprint dedup and cooldown.

Alerts are a Blue Team convenience, not a malware verdict. Identical
warnings for the same fingerprint are suppressed for a cooldown window
so a flapping device cannot flood the operator. Emitted alerts may be
appended to a local AlertStore; suppressed warnings are not written.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

from usb_monitor.analysis.risk_engine import RiskAssessment
from usb_monitor.models.alert import Alert
from usb_monitor.models.enums import RiskLevel, Severity
from usb_monitor.models.event import USBEvent
from usb_monitor.storage.alert_store import AlertStore
from usb_monitor.utils.logger import get_logger
from usb_monitor.utils.time import ensure_utc

DEFAULT_COOLDOWN_SECONDS = 60.0

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_HEURISTIC_NOTE = "Heuristic finding; not a malware confirmation."


@dataclass(frozen=True)
class AlertDecision:
    """Outcome of evaluating one CONNECT assessment."""

    alert: Alert | None = None
    fingerprint: str = ""
    suppressed: bool = False


@dataclass
class _CooldownEntry:
    timestamp: datetime
    severity: Severity
    alert_id: str
    suppressed: int = 0


@dataclass
class AlertStats:
    emitted: int
    suppressed: int
    cooldown_seconds: float


class AlertManager:
    """Turn CONNECT assessments into de-duplicated session alerts."""

    def __init__(
        self,
        cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS,
        *,
        store: AlertStore | None = None,
    ) -> None:
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must be >= 0")
        self._cooldown = float(cooldown_seconds)
        self._store = store
        self._lock = threading.Lock()
        self._last: dict[str, _CooldownEntry] = {}
        self._emitted: list[Alert] = []
        self._suppressed_total = 0
        self._log = get_logger("alerts")

    @property
    def cooldown_seconds(self) -> float:
        return self._cooldown

    def stats(self) -> AlertStats:
        with self._lock:
            return AlertStats(
                emitted=len(self._emitted),
                suppressed=self._suppressed_total,
                cooldown_seconds=self._cooldown,
            )

    def list_alerts(self) -> list[Alert]:
        with self._lock:
            return list(self._emitted)

    def consider(self, event: USBEvent, assessment: RiskAssessment) -> AlertDecision:
        """Return an alert, a suppression, or a no-op for this CONNECT."""
        candidate = _build_candidate(event, assessment)
        if candidate is None:
            return AlertDecision()
        fingerprint, severity, title, description = candidate
        when = ensure_utc(event.timestamp)
        with self._lock:
            previous = self._last.get(fingerprint)
            if previous is not None and _in_cooldown(previous.timestamp, when, self._cooldown):
                if _SEVERITY_RANK[severity] > _SEVERITY_RANK[previous.severity]:
                    alert = _make_alert(event, assessment, severity, title, description)
                    self._last[fingerprint] = _CooldownEntry(
                        timestamp=when,
                        severity=severity,
                        alert_id=alert.alert_id,
                    )
                    self._remember(alert)
                    self._log.info(
                        "Alert escalated %s %s %s",
                        severity.value,
                        title,
                        event.safe_device_id,
                    )
                    return AlertDecision(alert=alert, fingerprint=fingerprint)
                previous.suppressed += 1
                self._suppressed_total += 1
                self._log.debug(
                    "Alert suppressed (%s) fingerprint=%s device=%s",
                    previous.suppressed,
                    fingerprint.split("|", 1)[0],
                    event.safe_device_id,
                )
                return AlertDecision(fingerprint=fingerprint, suppressed=True)
            alert = _make_alert(event, assessment, severity, title, description)
            self._last[fingerprint] = _CooldownEntry(
                timestamp=when,
                severity=severity,
                alert_id=alert.alert_id,
            )
            self._remember(alert)
            self._log.info("Alert %s %s %s", severity.value, title, event.safe_device_id)
            return AlertDecision(alert=alert, fingerprint=fingerprint)

    def _remember(self, alert: Alert) -> None:
        self._emitted.append(alert)
        if self._store is not None:
            self._store.append(alert)


def attach_decision(event: USBEvent, decision: AlertDecision) -> None:
    """Record emit/suppress metadata on an event without exposing raw serials twice."""
    if decision.alert is not None:
        event.details["alert"] = {
            "alert_id": decision.alert.alert_id,
            "severity": decision.alert.severity.value,
            "title": decision.alert.title,
            "fingerprint": decision.fingerprint,
            "malware_verdict": False,
        }
        event.details.pop("alert_suppressed", None)
        return
    if decision.suppressed:
        event.details["alert_suppressed"] = {
            "fingerprint": decision.fingerprint,
            "reason": "Same warning is inside the cooldown window.",
        }


def format_alert(alert: Alert) -> str:
    """Human-readable alert block for console output."""
    reasons = alert.reasons or ["No rule text was attached."]
    rec = alert.recommendation or "Review the device in person if the context is unusual."
    lines = [
        f"[{alert.display_timestamp}] ALERT {alert.severity.value}",
        f"  {alert.title}",
        f"  Device: {alert.safe_device_id}",
        f"  {alert.description}",
        "  Reasons:",
        *[f"    - {item}" for item in reasons],
        f"  Recommendation: {rec}",
        f"  {_HEURISTIC_NOTE}",
        "--------------------------------",
    ]
    return "\n".join(lines)


def _in_cooldown(previous: datetime, now: datetime, window: float) -> bool:
    if window == 0:
        return False
    return now < previous + timedelta(seconds=window)


def _build_candidate(
    event: USBEvent, assessment: RiskAssessment
) -> tuple[str, Severity, str, str] | None:
    rule_ids = {match.rule.rule_id for match in assessment.matches}
    device_key = event.device_id or "unknown"
    if assessment.level is RiskLevel.CRITICAL:
        return (
            f"{device_key}|suspicious",
            Severity.CRITICAL,
            "Suspicious USB characteristics",
            "The heuristic score reached CRITICAL. This is not a malware confirmation.",
        )
    if assessment.level is RiskLevel.HIGH or "IDENTITY_INCONSISTENCY" in rule_ids:
        return (
            f"{device_key}|suspicious",
            Severity.HIGH,
            "Suspicious USB characteristics",
            "Stacked characteristics or an identity change reached HIGH. This is not a malware confirmation.",
        )
    if "MULTIPLE_NEW_DEVICES" in rule_ids:
        return (
            "host|multiple_new",
            Severity.MEDIUM,
            "Multiple new USB devices",
            "Several first-seen identities appeared on this endpoint in a short window.",
        )
    if assessment.level is RiskLevel.MEDIUM:
        return (
            f"{device_key}|elevated",
            Severity.MEDIUM,
            "Elevated USB risk",
            "Explainable rules produced a MEDIUM heuristic score. This is not a malware confirmation.",
        )
    if "RAPID_RECONNECT" in rule_ids or "REPEATED_EVENTS" in rule_ids:
        return (
            f"{device_key}|flap",
            Severity.LOW,
            "USB reconnect anomaly",
            "The same identity reconnected or flapped inside the anomaly window.",
        )
    if "FIRST_SEEN_DEVICE" in rule_ids:
        return (
            f"{device_key}|first_seen",
            Severity.INFO,
            "New USB device observed",
            "This identity was not in the local inventory. Verify that it belongs to an authorized user.",
        )
    return None


def _make_alert(
    event: USBEvent,
    assessment: RiskAssessment,
    severity: Severity,
    title: str,
    description: str,
) -> Alert:
    recommendations = assessment.recommendations
    return Alert(
        severity=severity,
        title=title,
        description=description,
        timestamp=event.timestamp,
        device_id=event.device_id,
        event_id=event.event_id,
        reasons=list(assessment.reasons),
        recommendation=(recommendations[0] if recommendations else None),
    )
