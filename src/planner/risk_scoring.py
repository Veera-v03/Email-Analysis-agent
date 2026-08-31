"""Configurable, explainable weighted risk scoring over canonical evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.models.evidence import Evidence, EvidenceSeverity

DEFAULT_WEIGHTS: dict[str, float] = {
    "authentication": 20.0,
    "url": 18.0,
    "impersonation": 18.0,
    "social_engineering": 18.0,
    "attachment": 15.0,
    "threat_intelligence": 15.0,
    "campaign": 12.0,
    "sender": 10.0,
    "ocr": 8.0,
    "qr": 8.0,
    "historical": 8.0,
    "general": 5.0,
}
_SEVERITY_MULTIPLIER = {
    EvidenceSeverity.INFO: 0.0,
    EvidenceSeverity.LOW: 0.25,
    EvidenceSeverity.MEDIUM: 0.5,
    EvidenceSeverity.HIGH: 0.8,
    EvidenceSeverity.CRITICAL: 1.0,
}


@dataclass(frozen=True)
class RiskScore:
    """Bounded risk score and auditable contribution breakdown."""

    score: float
    confidence: float
    risk_level: str
    reasons: tuple[str, ...]
    breakdown: tuple[dict[str, Any], ...]


class RiskScoringEngine:
    """Calculate weighted, bounded scores without mutating evidence or state."""

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self._weights = {**DEFAULT_WEIGHTS, **(weights or {})}
        if any(weight < 0 for weight in self._weights.values()):
            raise ValueError("Risk weights must be non-negative.")

    def score(self, evidence: tuple[Evidence, ...]) -> RiskScore:
        """Score evidence once per factor, retaining every contributing reason."""
        contributions: list[dict[str, Any]] = []
        seen_factors: set[str] = set()
        for item in evidence:
            factor = self._factor(item)
            if factor in seen_factors:
                continue
            multiplier = _SEVERITY_MULTIPLIER[item.severity]
            if multiplier <= 0:
                continue
            weight = self._weights.get(factor, self._weights["general"])
            points = round(weight * multiplier, 2)
            seen_factors.add(factor)
            contributions.append(
                {
                    "factor": factor,
                    "points": points,
                    "weight": weight,
                    "evidence_id": item.evidence_id,
                    "reason": item.description,
                }
            )
        total = min(100.0, round(sum(item["points"] for item in contributions), 2))
        confidence = min(0.99, round(0.5 + min(len(contributions), 5) * 0.1, 2))
        risk_level = (
            "critical"
            if total >= 75
            else "high"
            if total >= 50
            else "medium"
            if total >= 25
            else "low"
        )
        return RiskScore(
            score=total,
            confidence=confidence,
            risk_level=risk_level,
            reasons=tuple(item["reason"] for item in contributions),
            breakdown=tuple(contributions),
        )

    @staticmethod
    def _factor(item: Evidence) -> str:
        category = item.category.casefold()
        if any(token in category for token in ("spf", "dkim", "dmarc", "auth")):
            return "authentication"
        if "impersonation" in category or "brand" in category:
            return "impersonation"
        if "social_engineering" in category or "behavior" in category:
            return "social_engineering"
        if "threat_intelligence" in category:
            return "threat_intelligence"
        if "campaign" in category:
            return "campaign"
        if "historical" in category:
            return "historical"
        if "attachment" in category:
            return "attachment"
        if "sender" in category or "domain" in category:
            return "sender"
        if "ocr" in category:
            return "ocr"
        if "qr" in category:
            return "qr"
        if "url" in category:
            return "url"
        return "general"
