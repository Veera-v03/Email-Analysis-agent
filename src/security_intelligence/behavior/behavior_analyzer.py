"""Behavioral Analysis Service analyzing text for social engineering, urgency, and BEC indicators."""

from __future__ import annotations

from typing import Any


class BehaviorAnalyzer:
    """Linguistic and pattern scanner identifying social engineering and phishing tactics."""

    URGENCY_KEYWORDS = {
        "urgent",
        "immediate",
        "action required",
        "suspended",
        "disable",
        "unauthorized",
        "expire",
        "within 24 hours",
        "due now",
    }

    BEC_KEYWORDS = {
        "wire transfer",
        "ceo",
        "payment request",
        "bank details",
        "routing number",
        "direct deposit",
        "gift card",
        "invoice payment",
    }

    HARVEST_KEYWORDS = {
        "reset password",
        "verify account",
        "security alert",
        "login request",
        "confirm identity",
        "update credentials",
        "sign in attempt",
    }

    INVOICE_KEYWORDS = {
        "invoice due",
        "overdue",
        "billing receipt",
        "amount due",
        "payment invoice",
        "purchase order",
    }

    def analyze_text(self, text: str) -> dict[str, Any]:
        """Parse text content for behavioral indicators, tactics, and risk scores."""
        text_lower = text.lower()
        tactics = []
        indicators = []
        score = 0.0

        # 1. Urgency Detection
        urg_matches = [w for w in self.URGENCY_KEYWORDS if w in text_lower]
        if urg_matches:
            tactics.append("urgency_manipulation")
            indicators.extend(urg_matches)
            score += 2.5

        # 2. Business Email Compromise (BEC)
        bec_matches = [w for w in self.BEC_KEYWORDS if w in text_lower]
        if bec_matches:
            tactics.append("bec_impersonation")
            indicators.extend(bec_matches)
            score += 3.5

        # 3. Credential Harvesting
        har_matches = [w for w in self.HARVEST_KEYWORDS if w in text_lower]
        if har_matches:
            tactics.append("credential_harvesting")
            indicators.extend(har_matches)
            score += 3.0

        # 4. Invoice Fraud
        inv_matches = [w for w in self.INVOICE_KEYWORDS if w in text_lower]
        if inv_matches:
            tactics.append("financial_fraud")
            indicators.extend(inv_matches)
            score += 2.0

        # Normalize score to 1.0 maximum
        norm_score = round(min(score / 10.0, 1.0), 2)

        return {
            "behavior_risk_score": norm_score,
            "detected_tactics": list(set(tactics)),
            "risk_indicators": list(set(indicators)),
            "social_engineering_detected": len(tactics) > 0,
        }
