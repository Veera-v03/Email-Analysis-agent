"""Risk Feature Registry composing feature extractors across modules and supporting future providers."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from src.authentication.models import AuthenticationVerification
from src.parsing.models import ParsedEmail
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.transmission.models import TransmissionAnalysis


@runtime_checkable
class FeatureExtractorProvider(Protocol):
    """Protocol interface for module-specific feature extractors (Parsing, Transmission, Auth, Intel, Content, OCR, LLM)."""

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


class ContentFeatureExtractor(FeatureExtractorProvider):
    """Feature extractor for Module 14 Content & Media Intelligence."""

    @property
    def provider_name(self) -> str:
        return "content_intelligence"

    def extract_features(
        self,
        parsed: ParsedEmail | None = None,
        transmission: TransmissionAnalysis | None = None,
        auth: AuthenticationVerification | None = None,
        intel: ThreatIntelEnrichmentResult | None = None,
    ) -> dict[str, Any]:
        if not parsed:
            return {}
        body_lower = (parsed.body_plain or "").lower() + (
            parsed.body_html or ""
        ).lower()
        return {
            "has_hidden_text": "display:none" in body_lower
            or "font-size:0px" in body_lower,
            "external_form_actions": "<form" in body_lower and "action=" in body_lower,
            "urgency_score": 0.85
            if any(
                w in body_lower
                for w in ["urgent", "within 24 hours", "immediate action"]
            )
            else 0.0,
            "financial_coercion_score": 0.90
            if any(
                w in body_lower
                for w in ["wire transfer", "payment invoice", "bank details"]
            )
            else 0.0,
            "primary_intent": "PAYMENT_REQUEST"
            if "wire transfer" in body_lower
            else (
                "CREDENTIAL_UPDATE" if "reset password" in body_lower else "LEGITIMATE"
            ),
        }


class URLFeatureExtractor(FeatureExtractorProvider):
    """Feature extractor for Module 15 URL & Sandbox Intelligence."""

    @property
    def provider_name(self) -> str:
        return "url_intelligence"

    def extract_features(
        self,
        parsed: ParsedEmail | None = None,
        transmission: TransmissionAnalysis | None = None,
        auth: AuthenticationVerification | None = None,
        intel: ThreatIntelEnrichmentResult | None = None,
    ) -> dict[str, Any]:
        if not parsed:
            return {}
        has_mismatched = any(u.is_mismatched for u in parsed.urls)
        has_shortened = any(u.is_shortened for u in parsed.urls)
        return {
            "has_mismatched_urls": has_mismatched,
            "has_shortened_urls": has_shortened,
            "extracted_urls_count": len(parsed.urls),
            "ssrf_violation_detected": False,
        }


class CorrelationFeatureExtractor(FeatureExtractorProvider):
    """Feature extractor for Module 16 Threat Correlation & Campaign Intelligence."""

    @property
    def provider_name(self) -> str:
        return "threat_correlation"

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
            "campaign_detected": False,
            "campaign_score": 0.0,
            "mitre_technique_count": 0,
            "historical_matches_count": 0,
        }


class RiskFeatureRegistry:
    """Registry composing feature extractors from upstream modules and future providers."""

    def __init__(self) -> None:
        self._providers: dict[str, FeatureExtractorProvider] = {}
        # Register default extractors for Modules 6-9, 14, 15, and 16
        self.register(ParsingFeatureExtractor())
        self.register(TransmissionFeatureExtractor())
        self.register(AuthenticationFeatureExtractor())
        self.register(ThreatIntelFeatureExtractor())
        self.register(ContentFeatureExtractor())
        self.register(URLFeatureExtractor())
        self.register(CorrelationFeatureExtractor())

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
