"""Explainable risk rules for USB Security Monitor.

Scores are an internal heuristic, not a malware verdict and not a
standardized CVSS-style rating. Unknown manufacturer and missing serial
are weak signals; they never justify CRITICAL by themselves.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from usb_monitor.models.device import Device
from usb_monitor.models.enums import DeviceType, Severity
from usb_monitor.models.event import USBEvent

_GENERIC_NAME_RE = re.compile(
    r"(generic|unknown|www\.|https?://|usb\s*(mass\s*)?storage|usb\s*device|"
    r"compatible usb|vid_0000|test\s*device)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Rule:
    """One scoring rule. ``score`` may be negative (mitigation)."""

    rule_id: str
    name: str
    description: str
    score: int
    severity: Severity
    recommendation: str


@dataclass(frozen=True)
class AnalysisContext:
    """Facts available to rules. Analysis must not invent missing fields."""

    event: USBEvent
    device: Device | None = None
    is_first_seen: bool = False
    previous: Device | None = None


@dataclass(frozen=True)
class RuleMatch:
    """A rule that fired, with evidence safe for logs (no raw serials)."""

    rule: Rule
    evidence: str


RuleChecker = Callable[[AnalysisContext], RuleMatch | None]

RULE_FIRST_SEEN = Rule(
    rule_id="FIRST_SEEN_DEVICE",
    name="First-seen device",
    description="This identity is not in the local endpoint inventory.",
    score=15,
    severity=Severity.LOW,
    recommendation="Verify that the device belongs to an authorized user before trusting it.",
)
RULE_UNKNOWN_MANUFACTURER = Rule(
    rule_id="UNKNOWN_MANUFACTURER",
    name="Unknown manufacturer",
    description="The OS did not expose a manufacturer string.",
    score=10,
    severity=Severity.INFO,
    recommendation="Treat missing OEM data as incomplete telemetry, not proof of malware.",
)
RULE_MISSING_SERIAL = Rule(
    rule_id="MISSING_SERIAL",
    name="Missing serial number",
    description="No serial/instance identifier was available for this connection.",
    score=8,
    severity=Severity.INFO,
    recommendation="Many honest devices omit serials; use this only as a weak identity signal.",
)
RULE_WEAK_IDENTITY = Rule(
    rule_id="WEAK_IDENTITY",
    name="Weak device identity",
    description="Identity is only a drive letter or VID/PID without a serial.",
    score=10,
    severity=Severity.LOW,
    recommendation="A later connection with a serial may be a different physical device.",
)
RULE_GENERIC_NAME = Rule(
    rule_id="GENERIC_OR_SUSPICIOUS_NAME",
    name="Generic or suspicious naming",
    description="Manufacturer or product name matches a generic/suspicious pattern.",
    score=8,
    severity=Severity.LOW,
    recommendation="Generic USB names are common; confirm the physical device if the context is unusual.",
)
RULE_TYPE_MISMATCH = Rule(
    rule_id="DEVICE_TYPE_MISMATCH",
    name="Device type mismatch",
    description="Classification does not match attached storage attributes.",
    score=12,
    severity=Severity.LOW,
    recommendation="Review whether this is a composite device or incomplete classification.",
)
RULE_IDENTITY_CHANGE = Rule(
    rule_id="IDENTITY_INCONSISTENCY",
    name="Device identity changed",
    description="A known identity presented a different manufacturer, serial, or VID/PID.",
    score=30,
    severity=Severity.HIGH,
    recommendation="Investigate whether the same ID now refers to a different device. This is not a malware confirmation.",
)
RULE_REMOVABLE_CHANGED = Rule(
    rule_id="UNEXPECTED_REMOVABLE",
    name="Removable status changed",
    description="A known device switched from non-removable to removable in OS telemetry.",
    score=12,
    severity=Severity.LOW,
    recommendation="USB hard disks often report as fixed; a sudden change is worth a visual check.",
)
RULE_TRUSTED = Rule(
    rule_id="TRUSTED_DEVICE",
    name="Trusted device",
    description="An operator marked this identity trusted. Trust is not a safety guarantee.",
    score=-10,
    severity=Severity.INFO,
    recommendation="Keep CONNECT logging enabled; trusted status only reduces some heuristic weight.",
)

RULES: tuple[Rule, ...] = (
    RULE_FIRST_SEEN,
    RULE_UNKNOWN_MANUFACTURER,
    RULE_MISSING_SERIAL,
    RULE_WEAK_IDENTITY,
    RULE_GENERIC_NAME,
    RULE_TYPE_MISMATCH,
    RULE_IDENTITY_CHANGE,
    RULE_REMOVABLE_CHANGED,
    RULE_TRUSTED,
)


def check_first_seen(context: AnalysisContext) -> RuleMatch | None:
    if not context.is_first_seen:
        return None
    return RuleMatch(RULE_FIRST_SEEN, "Identity was not present in the local inventory.")


def check_unknown_manufacturer(context: AnalysisContext) -> RuleMatch | None:
    if context.event.manufacturer:
        return None
    return RuleMatch(RULE_UNKNOWN_MANUFACTURER, "Manufacturer field is empty (OS did not expose it).")


def check_missing_serial(context: AnalysisContext) -> RuleMatch | None:
    if context.event.serial_number:
        return None
    return RuleMatch(RULE_MISSING_SERIAL, "Serial/instance identifier is empty.")


def check_weak_identity(context: AnalysisContext) -> RuleMatch | None:
    device_id = context.event.device_id or ""
    if device_id.startswith("volume:"):
        return RuleMatch(RULE_WEAK_IDENTITY, "Identity is a drive letter (volume:X:), which can be reused.")
    if context.event.vendor_id and context.event.product_id and not context.event.serial_number:
        return RuleMatch(RULE_WEAK_IDENTITY, "Identity is VID:PID only; two sticks can share that pair.")
    return None


def check_generic_name(context: AnalysisContext) -> RuleMatch | None:
    text = " ".join(
        part for part in (context.event.manufacturer, context.event.device_name) if part
    )
    if not text or _GENERIC_NAME_RE.search(text) is None:
        return None
    return RuleMatch(RULE_GENERIC_NAME, "Name matched a generic/suspicious pattern.")


def check_type_mismatch(context: AnalysisContext) -> RuleMatch | None:
    event = context.event
    if event.device_type is DeviceType.USB_DEVICE and event.drive_letter:
        return RuleMatch(
            RULE_TYPE_MISMATCH,
            "Type is USB_DEVICE but a drive letter is present.",
        )
    if event.device_type is DeviceType.REMOVABLE_MEDIA and event.vendor_id and event.product_id:
        return RuleMatch(
            RULE_TYPE_MISMATCH,
            "Type is REMOVABLE_MEDIA while USB VID/PID is present (possible incomplete USB classification).",
        )
    return None


def check_identity_change(context: AnalysisContext) -> RuleMatch | None:
    previous = context.previous
    event = context.event
    if previous is None:
        return None
    changes: list[str] = []
    if previous.manufacturer and event.manufacturer and previous.manufacturer.lower() != event.manufacturer.lower():
        changes.append("manufacturer")
    if previous.serial_number and event.serial_number and previous.serial_number != event.serial_number:
        changes.append("serial")
    if previous.vendor_id and event.vendor_id and previous.vendor_id != event.vendor_id:
        changes.append("vendor_id")
    if previous.product_id and event.product_id and previous.product_id != event.product_id:
        changes.append("product_id")
    if not changes:
        return None
    return RuleMatch(RULE_IDENTITY_CHANGE, "Changed fields: " + ", ".join(changes) + ".")


def check_removable_changed(context: AnalysisContext) -> RuleMatch | None:
    previous = context.previous
    event = context.event
    if previous is None or previous.removable is not False or event.removable is not True:
        return None
    return RuleMatch(RULE_REMOVABLE_CHANGED, "OS now reports removable=True for a previously non-removable identity.")


def check_trusted(context: AnalysisContext) -> RuleMatch | None:
    if context.device is None or not context.device.trusted:
        return None
    return RuleMatch(RULE_TRUSTED, "Operator trusted flag is set; events are still recorded.")


CHECKERS: tuple[RuleChecker, ...] = (
    check_first_seen,
    check_unknown_manufacturer,
    check_missing_serial,
    check_weak_identity,
    check_generic_name,
    check_type_mismatch,
    check_identity_change,
    check_removable_changed,
    check_trusted,
)
