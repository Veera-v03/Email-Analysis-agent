"""Risk Feature Registry composing feature extractors across modules and supporting future providers."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from src.authentication.models import AuthenticationVerification
from src.parsing.models import ParsedEmail
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.transmission.models import TransmissionAnalysis


@runtime_checkable
class FeatureExtractorProvider(Protocol):
    """Protocol interface for module-specific feature extractors (Parsing, Transmission, Auth, Intel, OCR, LLM)."""

    @property
    def provider_name(self) -> str: ...

    def extract_features(
        self,
        parsed: ParsedEmail | None = None,
        transmission: TransmissionAnalysis | None = None,
        auth: AuthenticationVerification | None = None,
        intel: ThreatIntelEnrichmentResult | None = None,
    ) -> dict[str, Any]: ...


class ParsingFeatureExtractor(FeatureExtractorProvider):
    """Feature extractor for Module 6 ParsedEmail."""

    @property
    def provider_name(self) -> str:
        return "parsing"

    def extract_features(
        self,
        parsed: ParsedEmail | None = None,
        transmission: TransmissionAnalysis | None = None,
        auth: AuthenticationVerification | None = None,
        intel: ThreatIntelEnrichmentResult | None = None,
    ) -> dict[str, Any]:
        if not parsed:
            return {}
        return {
            "has_attachments": len(parsed.attachments) > 0,
            "attachment_count": len(parsed.attachments),
            "recipient_count": len(parsed.recipients_to) + len(parsed.recipients_cc),
            "subject_length": len(parsed.subject),
        }


class TransmissionFeatureExtractor(FeatureExtractorProvider):
    """Feature extractor for Module 7 TransmissionAnalysis."""

    @property
    def provider_name(self) -> str:
        return "transmission"

    def extract_features(
        self,
        parsed: ParsedEmail | None = None,
        transmission: TransmissionAnalysis | None = None,
        auth: AuthenticationVerification | None = None,
        intel: ThreatIntelEnrichmentResult | None = None,
    ) -> dict[str, Any]:
        if not transmission:
            return {}
        return {
            "is_display_name_spoofed": transmission.sender_identity.is_display_name_spoofed,
            "is_reply_to_mismatched": transmission.sender_identity.is_reply_to_mismatched,
            "is_reply_to_free_webmail": transmission.sender_identity.is_reply_to_free_webmail,
            "is_return_path_mismatched": transmission.sender_identity.is_return_path_mismatched,
            "is_thread_hijack_suspect": transmission.is_thread_hijack_suspect,
            "header_integrity_score": transmission.header_integrity_score,
            "sender_authenticity_score": transmission.sender_authenticity_score,
        }


class AuthenticationFeatureExtractor(FeatureExtractorProvider):
    """Feature extractor for Module 8 AuthenticationVerification."""

    @property
    def provider_name(self) -> str:
        return "authentication"

    def extract_features(
        self,
        parsed: ParsedEmail | None = None,
        transmission: TransmissionAnalysis | None = None,
        auth: AuthenticationVerification | None = None,
        intel: ThreatIntelEnrichmentResult | None = None,
    ) -> dict[str, Any]:
        if not auth:
            return {}
        return {
            "spf_result": auth.spf.result,
            "dkim_result": auth.dkim_overall_result,
            "dmarc_result": auth.dmarc.result,
            "auth_pass_summary": auth.auth_pass_summary,
            "auth_risk_impact": auth.auth_risk_score_impact,
        }


class ThreatIntelFeatureExtractor(FeatureExtractorProvider):
    """Feature extractor for Module 9 ThreatIntelEnrichmentResult."""

    @property
    def provider_name(self) -> str:
        return "threat_intel"

    def extract_features(
        self,
        parsed: ParsedEmail | None = None,
        transmission: TransmissionAnalysis | None = None,
        auth: AuthenticationVerification | None = None,
        intel: ThreatIntelEnrichmentResult | None = None,
    ) -> dict[str, Any]:
        if not intel:
            return {}
        return {
            "malicious_ioc_count": intel.malicious_ioc_count,
            "intel_confidence": intel.overall_confidence.confidence,
            "matched_feeds": intel.matched_feeds,
            "intel_risk_impact": intel.intel_risk_score_impact,
        }


class RiskFeatureRegistry:
    """Registry composing feature extractors from upstream modules and future providers."""

    def __init__(self) -> None:
        self._providers: dict[str, FeatureExtractorProvider] = {}
        # Register default extractors for Modules 6-9
        self.register(ParsingFeatureExtractor())
        self.register(TransmissionFeatureExtractor())
        self.register(AuthenticationFeatureExtractor())
        self.register(ThreatIntelFeatureExtractor())

    def register(self, provider: FeatureExtractorProvider) -> None:
        """Register a feature extractor provider."""
        self._providers[provider.provider_name.lower()] = provider

    def extract_all_features(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis,
        auth: AuthenticationVerification,
        intel: ThreatIntelEnrichmentResult,
    ) -> dict[str, Any]:
        """Extract and aggregate feature dictionary across all registered providers."""
        aggregated: dict[str, Any] = {}
        for provider in self._providers.values():
            extracted = provider.extract_features(
                parsed=parsed, transmission=transmission, auth=auth, intel=intel
            )
            aggregated.update(extracted)
        return aggregated
