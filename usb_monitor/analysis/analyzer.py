"""Apply risk assessments to USB events and inventory records.

Detection stays in the monitor. This module only scores characteristics
that were already observed.
"""

from __future__ import annotations

from usb_monitor.analysis.risk_engine import RiskAssessment, evaluate_risk
from usb_monitor.analysis.rules import AnalysisContext
from usb_monitor.inventory import Observation
from usb_monitor.models.enums import EventType, RiskLevel
from usb_monitor.models.event import USBEvent


class Analyzer:
    """Evaluate CONNECT events against the rule catalog."""

    def analyze(
        self,
        event: USBEvent,
        observation: Observation | None = None,
    ) -> RiskAssessment | None:
        """Score a CONNECT. DISCONNECT is ignored (no extra characteristics)."""
        if event.event_type is not EventType.CONNECT:
            return None
        is_first_seen = False
        device = None
        previous = None
        if observation is not None:
            is_first_seen = observation.is_first_seen
            device = observation.device
            previous = observation.previous
        else:
            inventory = event.details.get("inventory") if isinstance(event.details, dict) else None
            if isinstance(inventory, dict):
                is_first_seen = bool(inventory.get("is_first_seen"))
        context = AnalysisContext(
            event=event,
            device=device,
            is_first_seen=is_first_seen,
            previous=previous,
        )
        return evaluate_risk(context)


def apply_assessment(event: USBEvent, assessment: RiskAssessment) -> USBEvent:
    """Attach score, band, and explainable matches to an event."""
    event.risk_score = assessment.score
    event.risk_level = assessment.level
    event.details["risk"] = assessment.to_dict()
    return event


def should_emit_suspicious(assessment: RiskAssessment) -> bool:
    """HIGH/CRITICAL only when the clamped heuristic lands in those bands."""
    return assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
