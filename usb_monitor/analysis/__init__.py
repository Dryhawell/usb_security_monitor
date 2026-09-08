"""Rule-based analysis: characteristics in, explainable heuristic out."""

from usb_monitor.analysis.analyzer import Analyzer, apply_assessment, should_emit_suspicious
from usb_monitor.analysis.anomaly import AnomalySnapshot, AnomalyTracker
from usb_monitor.analysis.risk_engine import RiskAssessment, evaluate_risk
from usb_monitor.analysis.rules import RULES, AnalysisContext, Rule, RuleMatch

__all__ = [
    "Analyzer",
    "AnalysisContext",
    "AnomalySnapshot",
    "AnomalyTracker",
    "RiskAssessment",
    "Rule",
    "RuleMatch",
    "RULES",
    "apply_assessment",
    "evaluate_risk",
    "should_emit_suspicious",
]
