"""Confidence Fusion Engine deriving assessment confidence from evidence, agreement, and completeness."""

from __future__ import annotations

from src.authentication.models import AuthenticationVerification
from src.parsing.models import ParsedEmail
from src.risk.models import ConfidenceScoreDetailsDTO, RiskEvidenceDTO
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.transmission.models import TransmissionAnalysis


class ConfidenceFusionEngine:
    """Derives overall assessment confidence from evidence quality, provider agreement, and feature completeness."""

    def fuse_confidence(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis,
        auth: AuthenticationVerification,
        intel: ThreatIntelEnrichmentResult,
        evidence_list: list[RiskEvidenceDTO],
    ) -> ConfidenceScoreDetailsDTO:
        """Calculate multi-dimensional confidence fusion metrics."""
        # 1. Feature Completeness (presence of valid data across Modules 6-9)
        completeness = 1.0
        if not parsed.message_id or not parsed.sender.address:
            completeness -= 0.1
        if transmission.header_integrity_score < 0.3:
            completeness -= 0.1
        if auth.spf.result == "UNKNOWN":
            completeness -= 0.1

        feature_completeness = max(0.5, completeness)

        # 2. Evidence Quality (based on weights and confidence of triggered risk evidence)
        if evidence_list:
            avg_evidence_conf = sum(e.confidence for e in evidence_list) / len(
                evidence_list
            )
            evidence_quality = max(0.6, avg_evidence_conf)
        else:
            evidence_quality = 1.0

        # 3. Provider Agreement (threat intel feed consensus)
        if intel.matched_feeds:
            provider_agreement = min(1.0, 0.7 + (len(intel.matched_feeds) * 0.1))
        else:
            provider_agreement = 1.0

        # Overall Fused Confidence
        overall_confidence = min(
            1.0,
            (
                feature_completeness * 0.4
                + evidence_quality * 0.4
                + provider_agreement * 0.2
            ),
        )

        return ConfidenceScoreDetailsDTO(
            overall_confidence=round(overall_confidence, 2),
            feature_completeness=round(feature_completeness, 2),
            evidence_quality=round(evidence_quality, 2),
            provider_agreement=round(provider_agreement, 2),
        )
