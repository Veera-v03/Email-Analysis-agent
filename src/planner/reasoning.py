"""Reasoning layer for evidence correlation and threat interpretation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.models.agent import AgentState
from src.models.evidence import Evidence, EvidenceSeverity
from src.planner.risk_scoring import RiskScoringEngine

HISTORICAL_SIMILARITY_THRESHOLD = 0.80
HISTORICAL_CONFIDENCE_INCREMENT = 0.03
MAX_HISTORICAL_CONFIDENCE_INCREMENT = 0.09


@dataclass(frozen=True)
class HistoricalReasoningContext:
    """Structured, deterministic influence from retrieved investigations."""

    correlations: tuple[dict[str, Any], ...] = ()
    explanation_parts: tuple[str, ...] = ()
    investigation_ids: tuple[str, ...] = ()
    confidence_adjustment: float = 0.0
    has_campaign_match: bool = False


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
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    score_breakdown: tuple[dict[str, Any], ...] = Field(default_factory=tuple)


class ReasoningEngine:
    """Processes accumulated evidence to calculate risk, confidence, and recommended action."""

    def __init__(
        self,
        memory_retrieval: Any | None = None,
        risk_scoring: RiskScoringEngine | None = None,
    ) -> None:
        self.memory_retrieval = memory_retrieval
        self._risk_scoring = risk_scoring or RiskScoringEngine()

    @staticmethod
    def _historical_context(
        state: AgentState,
        retriever: Any | None,
    ) -> HistoricalReasoningContext:
        """Retrieve and normalize high-similarity historical investigations.

        Only investigations with a similarity score of at least 0.80 can affect
        the result. Each supporting phishing investigation adds 0.03 confidence,
        capped at 0.09. Conflicting high-similarity outcomes suppress the
        adjustment so historical data never inflates confidence ambiguously.
        """
        if retriever is None or state.parsed_email is None:
            return HistoricalReasoningContext()

        email = state.parsed_email
        matches = retriever.find_similar_investigations(
            subject=email.header.subject,
            sender=email.header.sender,
            body_summary=email.body_text[:2000],
        )
        high_similarity_matches = sorted(
            (
                match
                for match in matches
                if float(match.similarity_score) >= HISTORICAL_SIMILARITY_THRESHOLD
            ),
            key=lambda match: (-float(match.similarity_score), str(match.memory_id)),
        )
        if not high_similarity_matches:
            return HistoricalReasoningContext()

        supporting_matches: list[Any] = []
        conflicting_matches: list[Any] = []
        correlations: list[dict[str, Any]] = []
        sender = email.header.sender.casefold()
        sender_domain = sender.rsplit("@", 1)[-1] if "@" in sender else ""
        current_urls = tuple(
            match.casefold()
            for match in re.findall(r"https?://[^\s<>()]+", email.body_text)
        )
        attachment_names = tuple(
            attachment.filename.casefold() for attachment in email.attachments
        )

        for match in high_similarity_matches:
            record = match.record
            classification = str(getattr(record, "classification", "")).casefold()
            risk_level = str(getattr(record, "risk_level", "")).casefold()
            is_phishing = risk_level in {"high", "critical"} or any(
                label in classification
                for label in ("phishing", "bec", "malware", "scam")
            )
            is_conflicting = risk_level == "low" or classification in {
                "safe",
                "benign",
                "legitimate",
                "clean",
            }
            historical_sender = str(getattr(record, "sender", "")).casefold()
            historical_text = " ".join(
                (
                    historical_sender,
                    str(getattr(record, "subject", "")).casefold(),
                    str(getattr(record, "summary", "")).casefold(),
                )
            )
            shared_indicators: list[str] = []
            if historical_sender == sender:
                shared_indicators.append("sender")
            elif sender_domain and historical_sender.endswith(f"@{sender_domain}"):
                shared_indicators.append("sender domain")
            if any(url in historical_text for url in current_urls):
                shared_indicators.append("URL")
            if any(name in historical_text for name in attachment_names):
                shared_indicators.append("attachment filename")

            detail = (
                f"Historical investigation {match.memory_id} matched at "
                f"{float(match.similarity_score):.2f} similarity "
                f"(classification: {classification or 'unknown'}, "
                f"risk: {risk_level or 'unknown'})."
            )
            correlations.append(
                {
                    "indicator": "Historical Investigation Match",
                    "evidence_id": match.memory_id,
                    "detail": detail,
                    "similarity_score": float(match.similarity_score),
                    "shared_indicators": tuple(shared_indicators),
                }
            )
            if is_phishing:
                supporting_matches.append(match)
            elif is_conflicting:
                conflicting_matches.append(match)

        supporting_ids = tuple(str(match.memory_id) for match in supporting_matches)
        conflicting_ids = tuple(str(match.memory_id) for match in conflicting_matches)
        has_conflict = bool(supporting_ids and conflicting_ids)
        campaign_match = len(supporting_ids) >= 2 and not has_conflict
        explanation_parts: list[str] = []

        if has_conflict:
            correlations.append(
                {
                    "indicator": "Conflicting Historical Investigation Matches",
                    "evidence_id": ",".join((*supporting_ids, *conflicting_ids)),
                    "detail": (
                        "High-similarity historical investigations include both "
                        "phishing and low-risk outcomes; no historical confidence "
                        "adjustment was applied."
                    ),
                }
            )
            explanation_parts.append(
                "conflicting high-similarity historical investigation outcomes"
            )
            confidence_adjustment = 0.0
        elif supporting_ids:
            confidence_adjustment = min(
                MAX_HISTORICAL_CONFIDENCE_INCREMENT,
                len(supporting_ids) * HISTORICAL_CONFIDENCE_INCREMENT,
            )
            explanation_parts.append(
                "high-similarity historical phishing investigation matches"
            )
        else:
            confidence_adjustment = 0.0

        if campaign_match:
            correlations.append(
                {
                    "indicator": "Historical Phishing Campaign Correlation",
                    "evidence_id": ",".join(supporting_ids),
                    "detail": (
                        "Multiple high-similarity historical phishing investigations "
                        f"matched: {', '.join(supporting_ids)}."
                    ),
                }
            )
            explanation_parts.append("a repeated historical phishing campaign")

        return HistoricalReasoningContext(
            correlations=tuple(correlations),
            explanation_parts=tuple(explanation_parts),
            investigation_ids=supporting_ids,
            confidence_adjustment=confidence_adjustment,
            has_campaign_match=campaign_match,
        )

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
        has_threat_intelligence_match = False
        has_campaign_correlation = False

        for ev in evidences:
            desc_lower = ev.description.lower()
            cat_lower = ev.category.lower()
            title_lower = ev.title.lower()

            if "threat_intelligence" in cat_lower and ev.metadata.get("malicious"):
                has_threat_intelligence_match = True
                correlations.append(
                    {
                        "indicator": "External Threat Intelligence Match",
                        "evidence_id": ev.evidence_id,
                        "detail": ev.description,
                    }
                )
            if "campaign_correlation" in cat_lower:
                has_campaign_correlation = True
                correlations.append(
                    {
                        "indicator": "Campaign Correlation",
                        "evidence_id": ev.evidence_id,
                        "detail": ev.description,
                    }
                )

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
        synthesized_evidences: list[Evidence] = []

        if state.parsed_email:
            brand_service = BrandService()
            display_name = state.parsed_email.header.subject
            sender_email = state.parsed_email.header.sender
            brand_res = brand_service.analyze_sender(display_name, sender_email)
            if brand_res.get("impersonation_detected"):
                has_impersonation = True
                matched_brand = str(brand_res.get("matched_brand", "Unknown"))
                reason_detail = str(
                    brand_res.get("reason", "Brand impersonation detected.")
                )
                ev_id = f"ev_brand_{matched_brand.lower().replace(' ', '_')}"
                correlations.append(
                    {
                        "indicator": "Brand Impersonation Detected",
                        "evidence_id": ev_id,
                        "detail": reason_detail,
                    }
                )
                synthesized_evidences.append(
                    Evidence(
                        evidence_id=ev_id,
                        evidence_type="brand_impersonation",
                        category="sender.impersonation",
                        title=f"Brand Impersonation ({matched_brand})",
                        description=reason_detail,
                        severity=(
                            EvidenceSeverity.CRITICAL
                            if brand_res.get("confidence", 0.9) >= 0.8
                            else EvidenceSeverity.HIGH
                        ),
                        source="security_intelligence.brand",
                        confidence=brand_res.get("confidence", 0.9),
                        metadata={"brand": matched_brand},
                    )
                )

            behavior_analyzer = BehaviorAnalyzer()
            behav_res = behavior_analyzer.analyze_text(
                state.parsed_email.body_text or ""
            )
            if behav_res.get("social_engineering_detected"):
                has_social_eng = True
                tactics = behav_res.get("detected_tactics", [])
                risk_indicators = behav_res.get("risk_indicators", [])
                for tactic in tactics:
                    ev_id = f"ev_behav_{tactic}"
                    correlations.append(
                        {
                            "indicator": f"Social Engineering ({tactic})",
                            "evidence_id": ev_id,
                            "detail": f"Matched risk indicators: {', '.join(risk_indicators)}",
                        }
                    )
                    tactic_sev = (
                        EvidenceSeverity.CRITICAL
                        if tactic in {"credential_harvesting", "urgency_manipulation"}
                        else EvidenceSeverity.HIGH
                    )
                    synthesized_evidences.append(
                        Evidence(
                            evidence_id=ev_id,
                            evidence_type=f"social_engineering.{tactic}",
                            category="behavior.social_engineering",
                            title=f"Social Engineering ({tactic.replace('_', ' ').title()})",
                            description=f"Behavioral threat detection matched risk indicators: {', '.join(risk_indicators)}",
                            severity=tactic_sev,
                            source="security_intelligence.behavior",
                            confidence=0.85,
                            metadata={"tactic": tactic, "indicators": risk_indicators},
                        )
                    )

        historical_context = self._historical_context(state, retriever)
        current_correlation_count = len(correlations)
        correlations.extend(historical_context.correlations)

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
            or has_threat_intelligence_match
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
        if current_correlation_count > 1:
            confidence = min(0.99, confidence + (current_correlation_count * 0.02))

        if historical_context.has_campaign_match and risk_level == "low":
            risk_level = "medium"
            summary = (
                "Moderate risk indicators observed. Multiple high-similarity "
                "historical phishing investigations indicate a possible campaign."
            )
            recommended_action = (
                "Quarantine email for analyst review and display warning badge."
            )
            confidence = 0.75

        if historical_context.confidence_adjustment:
            confidence = min(
                0.99,
                confidence + historical_context.confidence_adjustment,
            )
        if historical_context.investigation_ids:
            recommended_action += (
                " Review matching historical investigations: "
                + ", ".join(historical_context.investigation_ids)
                + "."
            )

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
        explanation_parts.extend(historical_context.explanation_parts)
        if has_threat_intelligence_match:
            explanation_parts.append("external threat-intelligence provider matches")
        if has_campaign_correlation:
            explanation_parts.append("tenant campaign correlation evidence")

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
        all_scoring_evidences = tuple(evidences) + tuple(synthesized_evidences)
        weighted_score = self._risk_scoring.score(all_scoring_evidences)

        return ReasoningOutput(
            summary=summary,
            confidence=confidence,
            risk_level=risk_level,
            evidence_correlation=tuple(correlations),
            recommended_action=recommended_action,
            security_explanation=security_explanation,
            analyst_notes=analyst_notes,
            risk_score=weighted_score.score,
            score_breakdown=weighted_score.breakdown,
        )
