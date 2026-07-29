"""Reasoning layer for evidence correlation and threat interpretation."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.models.agent import AgentState
from src.models.evidence import EvidenceSeverity


class ReasoningOutput(BaseModel):
    """Structured reasoning outcome summarizing classification, risk, and action."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    summary: str = Field(..., description="Summary of the reasoning verdict.")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score for this verdict."
    )
    risk_level: str = Field(
        ..., description="Calculated risk: low, medium, high, critical."
    )
    evidence_correlation: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    recommended_action: str = Field(..., description="Recommended mitigation action.")
    security_explanation: str = Field(
        ..., description="Human-friendly security explanation."
    )
    analyst_notes: str = Field(..., description="Detailed notes for security analysts.")


class ReasoningEngine:
    """Processes accumulated evidence to calculate risk, confidence, and recommended action."""

    def __init__(self, memory_retrieval: Any | None = None) -> None:
        self.memory_retrieval = memory_retrieval

    def reason(
        self,
        state: AgentState,
        memory_retrieval: Any | None = None,
    ) -> ReasoningOutput:
        """Analyze accumulated evidence and produce structured reasoning output."""
        retriever = memory_retrieval or self.memory_retrieval
        evidences = state.evidence.items

        # 1. Inspect evidence items and correlate them
        correlations: list[dict[str, Any]] = []
        has_spf_fail = False
        has_dkim_fail = False
        has_dmarc_fail = False
        has_malicious_url = False
        has_suspicious_attachment = False
        has_sender_anomaly = False

        for ev in evidences:
            desc_lower = ev.description.lower()
            cat_lower = ev.category.lower()
            title_lower = ev.title.lower()

            # Correlate auth failures
            if "spf" in cat_lower or "spf" in title_lower:
                if "fail" in desc_lower or ev.severity in (
                    EvidenceSeverity.HIGH,
                    EvidenceSeverity.CRITICAL,
                ):
                    has_spf_fail = True
                    correlations.append(
                        {
                            "indicator": "SPF Authentication Failure",
                            "evidence_id": ev.evidence_id,
                            "detail": ev.description,
                        }
                    )

            if "dkim" in cat_lower or "dkim" in title_lower:
                if "fail" in desc_lower or ev.severity in (
                    EvidenceSeverity.HIGH,
                    EvidenceSeverity.CRITICAL,
                ):
                    has_dkim_fail = True
                    correlations.append(
                        {
                            "indicator": "DKIM Authentication Failure",
                            "evidence_id": ev.evidence_id,
                            "detail": ev.description,
                        }
                    )

            if "dmarc" in cat_lower or "dmarc" in title_lower:
                if "fail" in desc_lower or ev.severity in (
                    EvidenceSeverity.HIGH,
                    EvidenceSeverity.CRITICAL,
                ):
                    has_dmarc_fail = True
                    correlations.append(
                        {
                            "indicator": "DMARC Authentication Failure",
                            "evidence_id": ev.evidence_id,
                            "detail": ev.description,
                        }
                    )

            # Correlate URL anomalies
            if "url" in cat_lower or "url" in title_lower or "domain" in cat_lower:
                if (
                    ev.severity in (EvidenceSeverity.HIGH, EvidenceSeverity.CRITICAL)
                    or "suspicious" in desc_lower
                    or "malicious" in desc_lower
                    or "shortener" in desc_lower
                ):
                    has_malicious_url = True
                    correlations.append(
                        {
                            "indicator": "Suspicious URL/Domain",
                            "evidence_id": ev.evidence_id,
                            "detail": ev.description,
                        }
                    )

            # Correlate Attachment anomalies
            if (
                "attachment" in cat_lower
                or "attachment" in title_lower
                or "signature" in cat_lower
            ):
                if (
                    ev.severity in (EvidenceSeverity.HIGH, EvidenceSeverity.CRITICAL)
                    or "executable" in desc_lower
                    or "zip" in desc_lower
                    or "double extension" in desc_lower
                ):
                    has_suspicious_attachment = True
                    correlations.append(
                        {
                            "indicator": "Suspicious Attachment",
                            "evidence_id": ev.evidence_id,
                            "detail": ev.description,
                        }
                    )

            # Correlate Sender anomalies
            if (
                "sender" in cat_lower
                or "sender" in title_lower
                or "relationship" in cat_lower
            ):
                if (
                    ev.severity
                    in (
                        EvidenceSeverity.MEDIUM,
                        EvidenceSeverity.HIGH,
                        EvidenceSeverity.CRITICAL,
                    )
                    or "mismatch" in desc_lower
                    or "spoof" in desc_lower
                    or "display name" in desc_lower
                ):
                    has_sender_anomaly = True
                    correlations.append(
                        {
                            "indicator": "Sender Mismatch/Anomaly",
                            "evidence_id": ev.evidence_id,
                            "detail": ev.description,
                        }
                    )

        # Phase 9 Advanced Security Intelligence checks
        from src.security_intelligence.behavior.behavior_analyzer import (
            BehaviorAnalyzer,
        )
        from src.security_intelligence.brand.brand_service import BrandService

        has_impersonation = False
        has_social_eng = False

        if state.parsed_email:
            brand_service = BrandService()
            display_name = state.parsed_email.header.subject
            sender_email = state.parsed_email.header.sender
            brand_res = brand_service.analyze_sender(display_name, sender_email)
            if brand_res.get("impersonation_detected"):
                has_impersonation = True
                correlations.append(
                    {
                        "indicator": "Brand Impersonation Detected",
                        "evidence_id": f"brand_{brand_res.get('matched_brand')}",
                        "detail": brand_res.get("reason"),
                    }
                )

            behavior_analyzer = BehaviorAnalyzer()
            behav_res = behavior_analyzer.analyze_text(
                state.parsed_email.body_text or ""
            )
            if behav_res.get("social_engineering_detected"):
                has_social_eng = True
                for tactic in behav_res.get("detected_tactics", []):
                    correlations.append(
                        {
                            "indicator": f"Social Engineering ({tactic})",
                            "evidence_id": f"behav_{tactic}",
                            "detail": f"Matched risk indicators: {', '.join(behav_res.get('risk_indicators', []))}",
                        }
                    )

        # 2. Risk Level calculation
        # Low: no high/critical evidence, and normal authentication
        # Medium: some sender anomalies or minor URL indicators
        # High: spf/dkim fail + sender mismatch, or suspicious attachments
        # Critical: critical severity evidence or multiple strong indicators (e.g. SPF failure + malicious URL + attachment)

        critical_count = sum(
            1 for ev in evidences if ev.severity == EvidenceSeverity.CRITICAL
        )
        high_count = sum(1 for ev in evidences if ev.severity == EvidenceSeverity.HIGH)
        medium_count = sum(
            1 for ev in evidences if ev.severity == EvidenceSeverity.MEDIUM
        )

        has_attachments = bool(state.parsed_email and state.parsed_email.attachments)

        if (
            critical_count > 0
            or (high_count >= 2)
            or (has_spf_fail and has_malicious_url and has_suspicious_attachment)
            or (has_impersonation and has_social_eng)
        ):
            risk_level = "critical"
            summary = "Critical security threat detected. High likelihood of active phishing, BEC or malware campaign."
            if has_attachments:
                recommended_action = "Block email delivery, quarantine attachment, and flag sender domain."
            else:
                recommended_action = "Block email delivery, flag sender domain, and restrict sender IP access."
            confidence = 0.95 if critical_count > 0 else 0.88
        elif (
            high_count > 0
            or (has_spf_fail and has_malicious_url)
            or (has_suspicious_attachment)
            or has_impersonation
            or has_social_eng
        ):
            risk_level = "high"
            summary = "High risk security indicators observed. Potential phishing or impersonation attempt."
            recommended_action = (
                "Quarantine email for analyst review and display warning badge."
            )
            confidence = 0.85
        elif medium_count > 0 or has_sender_anomaly or has_spf_fail or has_dkim_fail:
            risk_level = "medium"
            summary = "Moderate risk indicators observed. Minor sender validation issues or unverified URLs."
            recommended_action = "Deliver with external warning banner and safety tips."
            confidence = 0.75
        else:
            risk_level = "low"
            summary = "No significant risk indicators observed. Email authentication checks passed."
            recommended_action = "Deliver normally to inbox."
            confidence = 0.90

        # Adjust confidence based on correlation density
        if len(correlations) > 1:
            confidence = min(0.99, confidence + (len(correlations) * 0.02))

        # 3. Explanations and notes
        explanation_parts = []
        if has_spf_fail or has_dkim_fail or has_dmarc_fail:
            explanation_parts.append("email authentication failures (SPF/DKIM/DMARC)")
        if has_malicious_url:
            explanation_parts.append(
                "suspicious hyperlinks/URLs matching phishing profiles"
            )
        if has_suspicious_attachment:
            explanation_parts.append(
                "potentially dangerous attachment types or metadata structures"
            )
        if has_sender_anomaly:
            explanation_parts.append(
                "inconsistencies in the sender headers or display names"
            )
        if has_impersonation:
            explanation_parts.append("brand impersonation indicators")
        if has_social_eng:
            explanation_parts.append("social engineering or urgent language tactics")

        if explanation_parts:
            security_explanation = (
                f"This email was classified as {risk_level} risk because of: "
                + ", ".join(explanation_parts)
                + "."
            )
        else:
            if risk_level == "low":
                security_explanation = "This email was classified as low risk because all core integrity and safety checks passed successfully."
            else:
                security_explanation = f"This email was classified as {risk_level} risk based on automated threat assessment."

        analyst_notes_lines = [
            f"Verdict: {risk_level.upper()} RISK (Confidence: {confidence * 100:.1f}%)",
            f"Total evidence items analyzed: {len(evidences)}",
            f"Correlated indicators: {len(correlations)}",
        ]
        for corr in correlations:
            analyst_notes_lines.append(f"- {corr['indicator']}: {corr['detail']}")

        analyst_notes = "\n".join(analyst_notes_lines)

        return ReasoningOutput(
            summary=summary,
            confidence=confidence,
            risk_level=risk_level,
            evidence_correlation=tuple(correlations),
            recommended_action=recommended_action,
            security_explanation=security_explanation,
            analyst_notes=analyst_notes,
        )
