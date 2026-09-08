"""Sum triggered rule scores into a clamped 0-100 heuristic.

The result is not a determination that a device is malicious.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from usb_monitor.analysis.rules import (
    CHECKERS,
    AnalysisContext,
    RuleMatch,
)
from usb_monitor.models.enums import RiskLevel, clamp_risk_score, risk_level_from_score


@dataclass(frozen=True)
class RiskAssessment:
    """Explainable score produced from triggered rules only."""

    score: int
    level: RiskLevel
    matches: tuple[RuleMatch, ...]

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(f"{match.rule.rule_id} ({match.rule.score:+d}): {match.evidence}" for match in self.matches)

    @property
    def recommendations(self) -> tuple[str, ...]:
        seen: list[str] = []
        for match in self.matches:
            text = match.rule.recommendation
            if text not in seen:
                seen.append(text)
        return tuple(seen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value,
            "heuristic": True,
            "malware_verdict": False,
            "matches": [
                {
                    "rule_id": match.rule.rule_id,
                    "name": match.rule.name,
                    "score": match.rule.score,
                    "severity": match.rule.severity.value,
                    "evidence": match.evidence,
                    "recommendation": match.rule.recommendation,
                }
                for match in self.matches
            ],
        }


def evaluate_risk(context: AnalysisContext) -> RiskAssessment:
    """Run all rules and clamp the total to 0-100."""
    matches = tuple(match for checker in CHECKERS if (match := checker(context)) is not None)
    total = clamp_risk_score(sum(match.rule.score for match in matches))
    return RiskAssessment(score=total, level=risk_level_from_score(total), matches=matches)
