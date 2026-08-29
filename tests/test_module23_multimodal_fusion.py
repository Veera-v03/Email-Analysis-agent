"""Targeted unit and integration tests for Module 23 (Phase 1: DTO Contracts & Multimodal Signal Normalization Layer)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from src.authentication.models import (
    ARCChainResultDTO,
    AuthenticationVerification,
    DKIMSignatureResultDTO,
    DMARCResultDTO,
    SPFResultDTO,
)
from src.content_intelligence.models import (
    ContentAnalysisResult,
    ContentIntentAnalysisDTO,
    ContentMediaEvidenceDTO,
    DOMContentSignalsDTO,
    MediaStatus,
)
from src.parsing.models import (
    HeaderAddressDTO,
    ParsedEmail,
)
from src.risk.calibrator import RiskScoreCalibrator
from src.risk.engine import RiskAssessmentEngine
from src.risk.fusion_models import (
    EvidenceStatus,
    MultimodalFeatureVectorDTO,
    NormalizedSignalDTO,
    SignalDomain,
)
from src.risk.models import RiskAssessment, RiskPolicyConfig
from src.risk.multimodal_fuser import MultimodalSignalFuser
from src.risk.pipeline import RiskAssessmentPipeline
from src.risk.profiles import (
    InMemoryTenantRiskProfileProvider,
    TenantRiskProfile,
    TenantRiskSensitivity,
)
from src.risk.strategies.deterministic import DeterministicWeightedScoringStrategy
from src.security_intelligence.threat_intel.framework import ThreatIntelObservation
from src.threat_correlation.models import (
    IOCRelationshipGraphDTO,
    ThreatCorrelationResult,
)
from src.threat_intel.models import (
    ConfidenceScoreDTO,
    IOCTargetDetailDTO,
    ThreatIntelEnrichmentResult,
)
from src.transmission.models import (
    SenderIdentityAnalysisDTO,
    TransmissionAnalysis,
)


# Helper builders for minimal valid test DTOs
def _build_minimal_parsed_email(tenant_id=None, message_id="msg_test_001") -> ParsedEmail:
    t_id = tenant_id or uuid4()
    return ParsedEmail(
        parsed_id=uuid4(),
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=t_id,
        message_id=message_id,
        internet_message_id="<msg001@example.com>",
        sender=HeaderAddressDTO(address="sender@example.com", name="Sender Name"),
        recipients_to=[HeaderAddressDTO(address="user@company.com", name="User")],
        subject="Important Security Update",
        raw_headers={"From": ["sender@example.com"]},
    )


def _build_minimal_transmission(parsed: ParsedEmail) -> TransmissionAnalysis:
    return TransmissionAnalysis(
        analysis_id=uuid4(),
        parsed_id=parsed.parsed_id,
        raw_email_id=parsed.raw_email_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        internet_message_id=parsed.internet_message_id,
        sender_identity=SenderIdentityAnalysisDTO(
            from_address=parsed.sender.address,
            from_domain="example.com",
            from_display_name=parsed.sender.name,
            is_display_name_spoofed=False,
            is_reply_to_mismatched=False,
        ),
        header_integrity_score=1.0,
    )


def _build_minimal_auth(parsed: ParsedEmail) -> AuthenticationVerification:
    return AuthenticationVerification(
        verification_id=uuid4(),
        parsed_id=parsed.parsed_id,
        transmission_id=uuid4(),
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        internet_message_id=parsed.internet_message_id,
        spf=SPFResultDTO(result="PASS", domain="example.com"),
        dmarc=DMARCResultDTO(result="PASS", domain="example.com", policy="reject"),
        dkim_signatures=[DKIMSignatureResultDTO(selector="s1", domain="example.com", result="PASS")],
        dkim_overall_result="PASS",
        arc=ARCChainResultDTO(chain_valid=True, instance_count=1),
    )


def _build_minimal_intel(parsed: ParsedEmail) -> ThreatIntelEnrichmentResult:
    return ThreatIntelEnrichmentResult(
        enrichment_id=uuid4(),
        parsed_id=parsed.parsed_id,
        transmission_id=uuid4(),
        auth_verification_id=uuid4(),
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        malicious_ioc_count=0,
        overall_confidence=ConfidenceScoreDTO(confidence=0.9),
    )


# ===========================================================================
# 1. DTO and Enum Validation Tests
# ===========================================================================
def test_signal_domain_enum_values() -> None:
    expected_domains = {
        "authentication",
        "transmission",
        "threat_intel",
        "content_intelligence",
        "media_intelligence",
        "url_intelligence",
        "threat_correlation",
    }
    assert {d.value for d in SignalDomain} == expected_domains


def test_evidence_status_enum_values() -> None:
    expected_statuses = {
        "EVALUATED_POSITIVE",
        "EVALUATED_NEGATIVE",
        "SKIPPED",
        "UNAVAILABLE",
        "ERROR",
    }
    assert {s.value for s in EvidenceStatus} == expected_statuses


def test_normalized_signal_dto_validation() -> None:
    signal = NormalizedSignalDTO(
        domain=SignalDomain.AUTHENTICATION,
        signal_name="dmarc_result",
        raw_value="FAIL",
        normalized_score=1.0,
        confidence=0.95,
        weight=1.5,
        status=EvidenceStatus.EVALUATED_POSITIVE,
        explanation="DMARC validation failed",
    )
    assert signal.domain == SignalDomain.AUTHENTICATION
    assert signal.normalized_score == 1.0
    assert signal.confidence == 0.95
    assert signal.status == EvidenceStatus.EVALUATED_POSITIVE


def test_multimodal_feature_vector_dto_validation() -> None:
    t_id = uuid4()
    vec = MultimodalFeatureVectorDTO(
        tenant_id=t_id,
        message_id="msg_001",
        domain_subscores={"authentication": 0.8},
        signals=[],
        completeness_ratio=0.75,
        total_evaluated_signals=15,
    )
    assert vec.tenant_id == t_id
    assert vec.message_id == "msg_001"
    assert vec.domain_subscores["authentication"] == 0.8
    assert vec.completeness_ratio == 0.75


# ===========================================================================
# 2. Authentication Domain Normalization Tests
# ===========================================================================
def test_authentication_normalization_pass() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    result = fuser.fuse_signals(parsed, trans, auth, intel)
    auth_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.AUTHENTICATION}

    assert auth_signals["dmarc_result"].normalized_score == 0.0
    assert auth_signals["dmarc_result"].status == EvidenceStatus.EVALUATED_NEGATIVE
    assert auth_signals["spf_result"].normalized_score == 0.0
    assert auth_signals["dkim_result"].normalized_score == 0.0
    assert auth_signals["arc_chain_valid"].normalized_score == 0.0


def test_authentication_normalization_fail() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = AuthenticationVerification(
        verification_id=uuid4(),
        parsed_id=parsed.parsed_id,
        transmission_id=uuid4(),
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        internet_message_id=parsed.internet_message_id,
        spf=SPFResultDTO(result="FAIL", domain="example.com"),
        dmarc=DMARCResultDTO(result="FAIL", domain="example.com", policy="reject"),
        dkim_signatures=[DKIMSignatureResultDTO(selector="s1", domain="example.com", result="FAIL")],
        dkim_overall_result="FAIL",
        arc=ARCChainResultDTO(chain_valid=False, instance_count=2),
    )
    intel = _build_minimal_intel(parsed)

    result = fuser.fuse_signals(parsed, trans, auth, intel)
    auth_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.AUTHENTICATION}

    assert auth_signals["dmarc_result"].normalized_score == 1.0
    assert auth_signals["dmarc_result"].status == EvidenceStatus.EVALUATED_POSITIVE
    assert auth_signals["spf_result"].normalized_score == 0.9
    assert auth_signals["dkim_result"].normalized_score == 0.8
    assert auth_signals["arc_chain_valid"].normalized_score == 0.7


# ===========================================================================
# 3. Transmission Domain Normalization Tests
# ===========================================================================
def test_transmission_normalization_threat_detected() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = TransmissionAnalysis(
        analysis_id=uuid4(),
        parsed_id=parsed.parsed_id,
        raw_email_id=parsed.raw_email_id,
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        internet_message_id=parsed.internet_message_id,
        sender_identity=SenderIdentityAnalysisDTO(
            from_address=parsed.sender.address,
            from_domain="example.com",
            from_display_name="CEO Name",
            is_display_name_spoofed=True,
            is_reply_to_mismatched=True,
            reply_to_address="attacker@phish.com",
        ),
        is_thread_hijack_suspect=True,
        header_integrity_score=0.20,
    )
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    result = fuser.fuse_signals(parsed, trans, auth, intel)
    trans_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.TRANSMISSION}

    assert trans_signals["is_display_name_spoofed"].normalized_score == 1.0
    assert trans_signals["is_display_name_spoofed"].status == EvidenceStatus.EVALUATED_POSITIVE
    assert trans_signals["is_reply_to_mismatched"].normalized_score == 0.9
    assert trans_signals["is_thread_hijack_suspect"].normalized_score == 0.85
    assert trans_signals["header_integrity_score"].normalized_score == pytest.approx(0.80)


# ===========================================================================
# 4. Threat Intel Domain Normalization Tests
# ===========================================================================
def test_threat_intel_normalization_ioc_and_whois() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)

    obs = ThreatIntelObservation(
        provider_name="whois",
        target="phishing.com",
        target_type="domain",
        malicious=True,
        confidence=0.9,
        metadata={"domain_age_days": 3},
    )
    target = IOCTargetDetailDTO(
        target="phishing.com",
        target_type="domain",
        is_malicious=True,
        confidence=ConfidenceScoreDTO(confidence=0.9),
        observations=[obs],
    )
    intel = ThreatIntelEnrichmentResult(
        enrichment_id=uuid4(),
        parsed_id=parsed.parsed_id,
        transmission_id=uuid4(),
        auth_verification_id=uuid4(),
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        malicious_ioc_count=2,
        matched_feeds=["GoogleSafeBrowsing", "PhishTank"],
        enriched_targets=[target],
        overall_confidence=ConfidenceScoreDTO(confidence=0.9),
    )

    result = fuser.fuse_signals(parsed, trans, auth, intel)
    intel_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.THREAT_INTEL}

    assert intel_signals["malicious_ioc_count"].normalized_score == 1.0  # 2 * 0.5 = 1.0
    assert intel_signals["malicious_ioc_count"].status == EvidenceStatus.EVALUATED_POSITIVE
    assert intel_signals["whois_age_days"].normalized_score == 0.90
    assert intel_signals["whois_age_days"].status == EvidenceStatus.EVALUATED_POSITIVE


# ===========================================================================
# 5. Content Domain Normalization Tests
# ===========================================================================
def test_content_normalization_urgency_coercion_and_hidden_dom() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    content_res = ContentAnalysisResult(
        analysis_id=uuid4(),
        parsed_id=parsed.parsed_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        dom_signals=DOMContentSignalsDTO(has_hidden_text=True, script_tag_count=1),
        intent_analysis=ContentIntentAnalysisDTO(
            primary_intent="PAYMENT_REQUEST",
            urgency_detected=True,
            urgency_score=0.85,
            financial_coercion_detected=True,
            financial_coercion_score=0.90,
        ),
        media_evidence=ContentMediaEvidenceDTO(),
    )

    result = fuser.fuse_signals(parsed, trans, auth, intel, content_res=content_res)
    content_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.CONTENT}

    assert content_signals["urgency_score"].normalized_score == 0.85
    assert content_signals["financial_coercion_score"].normalized_score == 0.90
    assert content_signals["has_hidden_dom_text"].normalized_score == 0.80
    assert content_signals["tracking_beacons"].normalized_score == 0.30


# ===========================================================================
# 6. Media (OCR & QR) Domain Normalization Tests
# ===========================================================================
def test_media_normalization_ocr_and_qr() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    content_res = ContentAnalysisResult(
        analysis_id=uuid4(),
        parsed_id=parsed.parsed_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        dom_signals=DOMContentSignalsDTO(),
        intent_analysis=ContentIntentAnalysisDTO(),
        media_evidence=ContentMediaEvidenceDTO(
            ocr_status=MediaStatus.SUCCESS,
            ocr_extracted_text="URGENT INVOICE DUE: wire $5000 immediately to routing 12345",
            ocr_confidence=0.95,
            qr_status=MediaStatus.SUCCESS,
            qr_detected=True,
            qr_extracted_urls=["https://phishing-portal.com/login"],
        ),
    )

    result = fuser.fuse_signals(parsed, trans, auth, intel, content_res=content_res)
    media_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.MEDIA}

    assert media_signals["ocr_phishing_detected"].normalized_score == pytest.approx(0.855, rel=1e-2)  # 0.95 * 0.90
    assert media_signals["ocr_phishing_detected"].status == EvidenceStatus.EVALUATED_POSITIVE
    assert media_signals["qr_malicious_destination"].normalized_score == 1.0
    assert media_signals["qr_malicious_destination"].status == EvidenceStatus.EVALUATED_POSITIVE


# ===========================================================================
# 7. URL Domain Normalization Tests
# ===========================================================================
class MockURLRedirectChain:
    def __init__(self, total_hops: int = 4) -> None:
        self.total_hops = total_hops


class MockURLSandboxResult:
    def __init__(self, has_credential_inputs: bool = True) -> None:
        self.has_credential_inputs = has_credential_inputs


class MockURLAnalysisResult:
    def __init__(self, has_cred=True, hops=4, ssrf=False) -> None:
        self.sandbox_result = MockURLSandboxResult(has_credential_inputs=has_cred)
        self.redirect_chain = MockURLRedirectChain(total_hops=hops)
        self.ssrf_violation_detected = ssrf


def test_url_normalization_credential_form_redirects_and_ssrf() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)
    url_res = MockURLAnalysisResult(has_cred=True, hops=4, ssrf=True)

    result = fuser.fuse_signals(parsed, trans, auth, intel, url_res=url_res)
    url_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.URL}

    assert url_signals["has_credential_form"].normalized_score == 1.0
    assert url_signals["has_credential_form"].status == EvidenceStatus.EVALUATED_POSITIVE
    assert url_signals["redirect_depth"].normalized_score == 1.0  # 4 * 0.25 = 1.0
    assert url_signals["ssrf_violation"].normalized_score == 1.0


# ===========================================================================
# 8. Threat Correlation Domain Normalization Tests
# ===========================================================================
def test_correlation_normalization_campaign_and_similarity() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    correlation_res = ThreatCorrelationResult(
        correlation_id=uuid4(),
        parsed_id=parsed.parsed_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        relationship_graph=IOCRelationshipGraphDTO(),
        campaign_detected=True,
        campaign_id="CAMP-2026-08",
        campaign_score=8.5,
    )

    result = fuser.fuse_signals(parsed, trans, auth, intel, correlation_res=correlation_res)
    corr_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.CORRELATION}

    assert corr_signals["campaign_detected"].normalized_score == 0.85
    assert corr_signals["campaign_detected"].status == EvidenceStatus.EVALUATED_POSITIVE
    assert corr_signals["historical_similarity_score"].normalized_score == pytest.approx(0.85)


# ===========================================================================
# 9. Missing Optional DTOs and Resilience Tests
# ===========================================================================
def test_missing_optional_dtos_resilience() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    # All optional DTOs are None
    result = fuser.fuse_signals(
        parsed, trans, auth, intel, content_res=None, url_res=None, correlation_res=None
    )

    assert result.tenant_id == parsed.tenant_id
    assert len(result.signals) > 0

    skipped_domains = {s.domain for s in result.signals if s.status == EvidenceStatus.SKIPPED}
    assert SignalDomain.CONTENT in skipped_domains
    assert SignalDomain.MEDIA in skipped_domains
    assert SignalDomain.URL in skipped_domains
    assert SignalDomain.CORRELATION in skipped_domains

    # Completeness ratio reflects missing domains
    assert result.completeness_ratio < 1.0


# ===========================================================================
# 10. Evidence Status Semantics (SKIPPED, UNAVAILABLE, ERROR)
# ===========================================================================
def test_evidence_status_distinctions() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    content_res = ContentAnalysisResult(
        analysis_id=uuid4(),
        parsed_id=parsed.parsed_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        dom_signals=DOMContentSignalsDTO(),
        intent_analysis=ContentIntentAnalysisDTO(),
        media_evidence=ContentMediaEvidenceDTO(
            ocr_status=MediaStatus.UNAVAILABLE,
            qr_status=MediaStatus.FAILED,
        ),
    )

    result = fuser.fuse_signals(parsed, trans, auth, intel, content_res=content_res)
    media_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.MEDIA}

    assert media_signals["ocr_phishing_detected"].status == EvidenceStatus.UNAVAILABLE
    assert media_signals["ocr_phishing_detected"].normalized_score == 0.0
    assert media_signals["ocr_phishing_detected"].weight == 0.0

    assert media_signals["qr_malicious_destination"].status == EvidenceStatus.ERROR
    assert media_signals["qr_malicious_destination"].normalized_score == 0.0
    assert media_signals["qr_malicious_destination"].weight == 0.0


# ===========================================================================
# 11. Invariant & Security Verification Tests
# ===========================================================================
def test_normalized_score_and_confidence_bounds() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    result = fuser.fuse_signals(parsed, trans, auth, intel)

    for signal in result.signals:
        assert 0.0 <= signal.normalized_score <= 1.0, f"Score out of bounds for {signal.signal_name}"
        assert 0.0 <= signal.confidence <= 1.0, f"Confidence out of bounds for {signal.signal_name}"
        assert signal.weight >= 0.0

    for domain_name, subscore in result.domain_subscores.items():
        assert 0.0 <= subscore <= 1.0, f"Domain subscore out of bounds for {domain_name}"


def test_deterministic_reproducibility() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    res1 = fuser.fuse_signals(parsed, trans, auth, intel)
    res2 = fuser.fuse_signals(parsed, trans, auth, intel)

    assert len(res1.signals) == len(res2.signals)
    assert res1.domain_subscores == res2.domain_subscores
    assert res1.completeness_ratio == res2.completeness_ratio
    for s1, s2 in zip(res1.signals, res2.signals, strict=False):
        assert s1.signal_name == s2.signal_name
        assert s1.normalized_score == s2.normalized_score
        assert s1.status == s2.status


def test_tenant_isolation_preserved() -> None:
    fuser = MultimodalSignalFuser()
    t1 = uuid4()
    t2 = uuid4()

    p1 = _build_minimal_parsed_email(tenant_id=t1)
    p2 = _build_minimal_parsed_email(tenant_id=t2)

    res1 = fuser.fuse_signals(p1, _build_minimal_transmission(p1), _build_minimal_auth(p1), _build_minimal_intel(p1))
    res2 = fuser.fuse_signals(p2, _build_minimal_transmission(p2), _build_minimal_auth(p2), _build_minimal_intel(p2))

    assert res1.tenant_id == t1
    assert res2.tenant_id == t2
    assert res1.tenant_id != res2.tenant_id


def test_no_secret_leakage_in_provenance_explanation() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    content_res = ContentAnalysisResult(
        analysis_id=uuid4(),
        parsed_id=parsed.parsed_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        dom_signals=DOMContentSignalsDTO(),
        intent_analysis=ContentIntentAnalysisDTO(),
        media_evidence=ContentMediaEvidenceDTO(
            ocr_status=MediaStatus.SUCCESS,
            ocr_extracted_text="Password: SuperSecretToken12345 Bearer eyJhbGciOiJIUzI1NiJ9.test",
            ocr_confidence=0.95,
        ),
    )

    result = fuser.fuse_signals(parsed, trans, auth, intel, content_res=content_res)

    for signal in result.signals:
        raw_repr = str(signal.raw_value)
        exp_repr = signal.explanation
        assert "SuperSecretToken12345" not in exp_repr
        assert "eyJhbGciOiJIUzI1NiJ9" not in exp_repr
        assert "SuperSecretToken12345" not in raw_repr


def test_all_seven_domains_combined() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)

    obs = ThreatIntelObservation(
        provider_name="whois",
        target="example.com",
        target_type="domain",
        malicious=False,
        confidence=0.9,
        metadata={"domain_age_days": 120},
    )
    target = IOCTargetDetailDTO(
        target="example.com",
        target_type="domain",
        is_malicious=False,
        confidence=ConfidenceScoreDTO(confidence=0.9),
        observations=[obs],
    )
    intel = ThreatIntelEnrichmentResult(
        enrichment_id=uuid4(),
        parsed_id=parsed.parsed_id,
        transmission_id=uuid4(),
        auth_verification_id=uuid4(),
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        malicious_ioc_count=1,
        matched_feeds=["GoogleSafeBrowsing"],
        enriched_targets=[target],
        overall_confidence=ConfidenceScoreDTO(confidence=0.9),
    )

    content_res = ContentAnalysisResult(
        analysis_id=uuid4(),
        parsed_id=parsed.parsed_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        dom_signals=DOMContentSignalsDTO(),
        intent_analysis=ContentIntentAnalysisDTO(urgency_score=0.9),
        media_evidence=ContentMediaEvidenceDTO(
            ocr_status=MediaStatus.SUCCESS,
            ocr_extracted_text="invoice payment",
            ocr_confidence=0.9,
            qr_status=MediaStatus.SUCCESS,
            qr_detected=True,
            qr_extracted_urls=["https://example.com/login"],
        ),
    )
    url_res = MockURLAnalysisResult(has_cred=True, hops=3, ssrf=False)
    correlation_res = ThreatCorrelationResult(
        correlation_id=uuid4(),
        parsed_id=parsed.parsed_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        relationship_graph=IOCRelationshipGraphDTO(),
        campaign_detected=True,
        campaign_score=7.0,
    )

    result = fuser.fuse_signals(
        parsed, trans, auth, intel,
        content_res=content_res,
        url_res=url_res,
        correlation_res=correlation_res,
    )

    assert result.completeness_ratio == 1.0
    assert len(result.domain_subscores) == 7
    for domain in SignalDomain:
        assert domain.value in result.domain_subscores
        assert result.domain_subscores[domain.value] >= 0.0


# ===========================================================================
# 12. Additional Boundary & Specific Signal Tests
# ===========================================================================
def test_authentication_neutral_and_softfail_values() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = AuthenticationVerification(
        verification_id=uuid4(),
        parsed_id=parsed.parsed_id,
        transmission_id=uuid4(),
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        internet_message_id=parsed.internet_message_id,
        spf=SPFResultDTO(result="SOFTFAIL", domain="example.com", client_ip="192.0.2.1"),
        dmarc=DMARCResultDTO(result="NONE", domain="example.com"),
        dkim_signatures=[],
        dkim_overall_result="NONE",
        arc=ARCChainResultDTO(chain_valid=False, instance_count=0),
    )
    intel = _build_minimal_intel(parsed)

    result = fuser.fuse_signals(parsed, trans, auth, intel)
    auth_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.AUTHENTICATION}

    assert auth_signals["spf_result"].normalized_score == 0.60
    assert auth_signals["spf_result"].status == EvidenceStatus.EVALUATED_POSITIVE
    assert auth_signals["dmarc_result"].normalized_score == 0.20
    assert auth_signals["dkim_result"].normalized_score == 0.20
    assert auth_signals["arc_chain_valid"].normalized_score == 0.0


def test_threat_intel_medium_age_domain() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)

    obs = ThreatIntelObservation(
        provider_name="whois",
        target="example.com",
        target_type="domain",
        malicious=False,
        confidence=0.9,
        metadata={"domain_age_days": 20},  # < 30 days -> 0.60
    )
    target = IOCTargetDetailDTO(
        target="example.com",
        target_type="domain",
        is_malicious=False,
        confidence=ConfidenceScoreDTO(confidence=0.9),
        observations=[obs],
    )
    intel = ThreatIntelEnrichmentResult(
        enrichment_id=uuid4(),
        parsed_id=parsed.parsed_id,
        transmission_id=uuid4(),
        auth_verification_id=uuid4(),
        account_id=parsed.account_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        malicious_ioc_count=0,
        enriched_targets=[target],
        overall_confidence=ConfidenceScoreDTO(confidence=0.9),
    )

    result = fuser.fuse_signals(parsed, trans, auth, intel)
    intel_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.THREAT_INTEL}

    assert intel_signals["whois_age_days"].normalized_score == 0.60
    assert intel_signals["whois_age_days"].status == EvidenceStatus.EVALUATED_POSITIVE


def test_content_benign_evaluation() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    content_res = ContentAnalysisResult(
        analysis_id=uuid4(),
        parsed_id=parsed.parsed_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        dom_signals=DOMContentSignalsDTO(has_hidden_text=False, script_tag_count=0),
        intent_analysis=ContentIntentAnalysisDTO(
            primary_intent="LEGITIMATE",
            urgency_detected=False,
            urgency_score=0.05,
            financial_coercion_detected=False,
            financial_coercion_score=0.0,
        ),
        media_evidence=ContentMediaEvidenceDTO(),
    )

    result = fuser.fuse_signals(parsed, trans, auth, intel, content_res=content_res)
    content_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.CONTENT}

    assert content_signals["urgency_score"].status == EvidenceStatus.EVALUATED_NEGATIVE
    assert content_signals["financial_coercion_score"].status == EvidenceStatus.EVALUATED_NEGATIVE
    assert content_signals["has_hidden_dom_text"].status == EvidenceStatus.EVALUATED_NEGATIVE
    assert content_signals["tracking_beacons"].status == EvidenceStatus.EVALUATED_NEGATIVE


def test_url_single_hop_benign() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)
    url_res = MockURLAnalysisResult(has_cred=False, hops=1, ssrf=False)

    result = fuser.fuse_signals(parsed, trans, auth, intel, url_res=url_res)
    url_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.URL}

    assert url_signals["has_credential_form"].normalized_score == 0.0
    assert url_signals["redirect_depth"].normalized_score == 0.0
    assert url_signals["ssrf_violation"].normalized_score == 0.0


def test_media_ocr_success_benign_text() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    content_res = ContentAnalysisResult(
        analysis_id=uuid4(),
        parsed_id=parsed.parsed_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        dom_signals=DOMContentSignalsDTO(),
        intent_analysis=ContentIntentAnalysisDTO(),
        media_evidence=ContentMediaEvidenceDTO(
            ocr_status=MediaStatus.SUCCESS,
            ocr_extracted_text="Company annual picnic schedule and meeting agenda.",
            ocr_confidence=0.92,
        ),
    )

    result = fuser.fuse_signals(parsed, trans, auth, intel, content_res=content_res)
    media_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.MEDIA}

    assert media_signals["ocr_phishing_detected"].normalized_score == 0.0
    assert media_signals["ocr_phishing_detected"].status == EvidenceStatus.EVALUATED_NEGATIVE


def test_correlation_negative_benign() -> None:
    fuser = MultimodalSignalFuser()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    correlation_res = ThreatCorrelationResult(
        correlation_id=uuid4(),
        parsed_id=parsed.parsed_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        relationship_graph=IOCRelationshipGraphDTO(),
        campaign_detected=False,
        campaign_score=1.0,
    )

    result = fuser.fuse_signals(parsed, trans, auth, intel, correlation_res=correlation_res)
    corr_signals = {s.signal_name: s for s in result.signals if s.domain == SignalDomain.CORRELATION}

    assert corr_signals["campaign_detected"].normalized_score == 0.0
    assert corr_signals["campaign_detected"].status == EvidenceStatus.EVALUATED_NEGATIVE
    assert corr_signals["historical_similarity_score"].normalized_score == pytest.approx(0.10)
    assert corr_signals["historical_similarity_score"].status == EvidenceStatus.EVALUATED_NEGATIVE


# ===========================================================================
# 13. Phase 2: Multimodal Scoring & Domain Ceiling Tests
# ===========================================================================
def test_multimodal_scoring_authentication_ceiling() -> None:
    strategy = DeterministicWeightedScoringStrategy()
    t_id = uuid4()
    # Create vector with all authentication failures: DMARC(30) + SPF(15) + DKIM(15) + ARC(10) = 70 pts
    signals = [
        NormalizedSignalDTO(
            domain=SignalDomain.AUTHENTICATION,
            signal_name="dmarc_result",
            raw_value="FAIL",
            normalized_score=1.0,
            confidence=1.0,
            status=EvidenceStatus.EVALUATED_POSITIVE,
        ),
        NormalizedSignalDTO(
            domain=SignalDomain.AUTHENTICATION,
            signal_name="spf_result",
            raw_value="FAIL",
            normalized_score=1.0,
            confidence=1.0,
            status=EvidenceStatus.EVALUATED_POSITIVE,
        ),
        NormalizedSignalDTO(
            domain=SignalDomain.AUTHENTICATION,
            signal_name="dkim_result",
            raw_value="FAIL",
            normalized_score=1.0,
            confidence=1.0,
            status=EvidenceStatus.EVALUATED_POSITIVE,
        ),
        NormalizedSignalDTO(
            domain=SignalDomain.AUTHENTICATION,
            signal_name="arc_chain_valid",
            raw_value=False,
            normalized_score=1.0,
            confidence=1.0,
            status=EvidenceStatus.EVALUATED_POSITIVE,
        ),
    ]
    vec = MultimodalFeatureVectorDTO(
        tenant_id=t_id,
        message_id="msg_auth_ceil",
        signals=signals,
    )

    score, evidence, categories = strategy.calculate_score(vec)
    # Auth domain ceiling is 30
    assert score == 30
    assert len(evidence) == 4


def test_multimodal_scoring_transmission_ceiling() -> None:
    strategy = DeterministicWeightedScoringStrategy()
    t_id = uuid4()
    # Transmission signals: Display spoof(40) + ReplyTo(25) + Thread hijack(25) + Integrity(15) = 105 pts
    signals = [
        NormalizedSignalDTO(
            domain=SignalDomain.TRANSMISSION,
            signal_name="is_display_name_spoofed",
            raw_value=True,
            normalized_score=1.0,
            confidence=1.0,
            status=EvidenceStatus.EVALUATED_POSITIVE,
        ),
        NormalizedSignalDTO(
            domain=SignalDomain.TRANSMISSION,
            signal_name="is_reply_to_mismatched",
            raw_value=True,
            normalized_score=1.0,
            confidence=1.0,
            status=EvidenceStatus.EVALUATED_POSITIVE,
        ),
        NormalizedSignalDTO(
            domain=SignalDomain.TRANSMISSION,
            signal_name="is_thread_hijack_suspect",
            raw_value=True,
            normalized_score=1.0,
            confidence=1.0,
            status=EvidenceStatus.EVALUATED_POSITIVE,
        ),
    ]
    vec = MultimodalFeatureVectorDTO(
        tenant_id=t_id,
        message_id="msg_trans_ceil",
        signals=signals,
    )

    score, evidence, categories = strategy.calculate_score(vec)
    # Transmission ceiling is 40
    assert score == 40
    assert "BEC" in categories
    assert "CREDENTIAL_HARVESTING" in categories


def test_multimodal_scoring_all_domain_ceilings_bounded_to_100() -> None:
    strategy = DeterministicWeightedScoringStrategy()
    t_id = uuid4()
    # Populate all 7 domains with high threat indicators
    signals = [
        NormalizedSignalDTO(domain=SignalDomain.AUTHENTICATION, signal_name="dmarc_result", raw_value="FAIL", normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
        NormalizedSignalDTO(domain=SignalDomain.TRANSMISSION, signal_name="is_display_name_spoofed", raw_value=True, normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
        NormalizedSignalDTO(domain=SignalDomain.THREAT_INTEL, signal_name="malicious_ioc_count", raw_value=3, normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
        NormalizedSignalDTO(domain=SignalDomain.CONTENT, signal_name="has_hidden_dom_text", raw_value=True, normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
        NormalizedSignalDTO(domain=SignalDomain.MEDIA, signal_name="qr_malicious_destination", raw_value=True, normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
        NormalizedSignalDTO(domain=SignalDomain.URL, signal_name="ssrf_violation", raw_value=True, normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
        NormalizedSignalDTO(domain=SignalDomain.CORRELATION, signal_name="campaign_detected", raw_value=True, normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
    ]
    vec = MultimodalFeatureVectorDTO(
        tenant_id=t_id,
        message_id="msg_all_ceil",
        signals=signals,
    )

    score, evidence, categories = strategy.calculate_score(vec)
    # Sum of max domains (30 + 40 + 35 + 15 + 25 + 35 + 20 = 200) capped at 100
    assert score == 100
    assert len(evidence) == 7


# ===========================================================================
# 14. Phase 2: Anti-Double-Counting Rule Tests
# ===========================================================================
def test_anti_double_counting_rule_a_dmarc_and_spf() -> None:
    strategy = DeterministicWeightedScoringStrategy()
    t_id = uuid4()
    # DMARC fail (30) + SPF fail (15 * 0.50 = 7.5 -> 8)
    signals = [
        NormalizedSignalDTO(domain=SignalDomain.AUTHENTICATION, signal_name="dmarc_result", raw_value="FAIL", normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
        NormalizedSignalDTO(domain=SignalDomain.AUTHENTICATION, signal_name="spf_result", raw_value="FAIL", normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
    ]
    vec = MultimodalFeatureVectorDTO(tenant_id=t_id, message_id="msg_rule_a", signals=signals)
    score, evidence, _ = strategy.calculate_score(vec)

    # DMARC (30) + SPF scaled (7.5 -> 8) = 38 -> capped by Auth ceiling of 30
    assert score == 30
    # Provenance preserves both signals with individual contributions
    ev_dict = {e.feature_name: e.applied_weight for e in evidence}
    assert ev_dict["dmarc_result"] == 30
    assert ev_dict["spf_result"] == 8  # 15 * 0.5 = 7.5 -> 8


def test_anti_double_counting_rule_b_ioc_and_sandbox_cred_form() -> None:
    strategy = DeterministicWeightedScoringStrategy()
    t_id = uuid4()
    # Threat Intel IOC (35) + URL Sandbox Cred Form (30 * 0.50 = 15)
    signals = [
        NormalizedSignalDTO(domain=SignalDomain.THREAT_INTEL, signal_name="malicious_ioc_count", raw_value=2, normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
        NormalizedSignalDTO(domain=SignalDomain.URL, signal_name="has_credential_form", raw_value=True, normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
    ]
    vec = MultimodalFeatureVectorDTO(tenant_id=t_id, message_id="msg_rule_b", signals=signals)
    score, evidence, categories = strategy.calculate_score(vec)

    assert score == 35 + 15  # Threat Intel: 35 (max 35), URL: 15 (max 35) = 50
    ev_dict = {e.feature_name: e.applied_weight for e in evidence}
    assert ev_dict["malicious_ioc_count"] == 35
    assert ev_dict["has_credential_form"] == 15  # Scaled by 0.50 as corroborating


def test_anti_double_counting_rule_c_executive_spoof_and_bec_linguistics() -> None:
    strategy = DeterministicWeightedScoringStrategy()
    t_id = uuid4()
    # Transmission display spoof (40) + Content financial coercion (20 * 0.50 = 10)
    signals = [
        NormalizedSignalDTO(domain=SignalDomain.TRANSMISSION, signal_name="is_display_name_spoofed", raw_value=True, normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
        NormalizedSignalDTO(domain=SignalDomain.CONTENT, signal_name="financial_coercion_score", raw_value=1.0, normalized_score=1.0, confidence=1.0, status=EvidenceStatus.EVALUATED_POSITIVE),
    ]
    vec = MultimodalFeatureVectorDTO(tenant_id=t_id, message_id="msg_rule_c", signals=signals)
    score, evidence, categories = strategy.calculate_score(vec)

    assert score == 40 + 10  # Transmission: 40, Content: 10 = 50
    assert "BEC" in categories
    ev_dict = {e.feature_name: e.applied_weight for e in evidence}
    assert ev_dict["is_display_name_spoofed"] == 40
    assert ev_dict["financial_coercion_score"] == 10


def test_confidence_scaling_effect_on_contribution() -> None:
    strategy = DeterministicWeightedScoringStrategy()
    t_id = uuid4()
    # Threat Intel IOC with low confidence (0.40)
    signals = [
        NormalizedSignalDTO(domain=SignalDomain.THREAT_INTEL, signal_name="malicious_ioc_count", raw_value=1, normalized_score=1.0, confidence=0.40, status=EvidenceStatus.EVALUATED_POSITIVE),
    ]
    vec = MultimodalFeatureVectorDTO(tenant_id=t_id, message_id="msg_conf", signals=signals)
    score, evidence, _ = strategy.calculate_score(vec)

    # 35 base * 1.0 score * 0.40 conf = 14 pts
    assert score == 14
    assert evidence[0].applied_weight == 14


def test_zero_signal_behavior() -> None:
    strategy = DeterministicWeightedScoringStrategy()
    t_id = uuid4()
    signals = [
        NormalizedSignalDTO(domain=SignalDomain.AUTHENTICATION, signal_name="dmarc_result", raw_value="PASS", normalized_score=0.0, confidence=1.0, status=EvidenceStatus.EVALUATED_NEGATIVE),
        NormalizedSignalDTO(domain=SignalDomain.TRANSMISSION, signal_name="is_display_name_spoofed", raw_value=False, normalized_score=0.0, confidence=1.0, status=EvidenceStatus.EVALUATED_NEGATIVE),
    ]
    vec = MultimodalFeatureVectorDTO(tenant_id=t_id, message_id="msg_clean", signals=signals)
    score, evidence, categories = strategy.calculate_score(vec)

    assert score == 0
    assert len(evidence) == 0
    assert len(categories) == 0


def test_legacy_scoring_backward_compatibility() -> None:
    strategy = DeterministicWeightedScoringStrategy()
    cfg = RiskPolicyConfig()
    legacy_features = {
        "is_display_name_spoofed": True,
        "malicious_ioc_count": 1,
        "dmarc_result": "FAIL",
    }
    score, evidence, categories = strategy.calculate_score(legacy_features, cfg)
    # Legacy: 40 + 35 + 30 = 105 -> capped at 100
    assert score == 100
    assert len(evidence) == 3


# ===========================================================================
# 15. Phase 2: RiskScoreCalibrator Tests
# ===========================================================================
def test_calibrator_boundary_score_0() -> None:
    calibrator = RiskScoreCalibrator()
    prob = calibrator.calibrate(0)
    # S = 0 -> P <= 0.02
    assert 0.0 <= prob <= 0.02
    assert prob == pytest.approx(0.018, abs=0.005)


def test_calibrator_midpoint_score_50() -> None:
    calibrator = RiskScoreCalibrator()
    prob = calibrator.calibrate(50)
    # S = 50 -> P == 0.50
    assert prob == 0.50


def test_calibrator_boundary_score_100() -> None:
    calibrator = RiskScoreCalibrator()
    prob = calibrator.calibrate(100)
    # S = 100 -> P >= 0.98
    assert 0.98 <= prob <= 1.0
    assert prob == pytest.approx(0.982, abs=0.005)


def test_calibrator_monotonic_increasing_0_to_100() -> None:
    calibrator = RiskScoreCalibrator()
    prev_prob = -1.0
    for s in range(101):
        p = calibrator.calibrate(s)
        assert 0.0 <= p <= 1.0
        assert p >= prev_prob, f"Monotonicity violated at score {s}: {p} < {prev_prob}"
        prev_prob = p


def test_calibrator_invalid_scores_raise_value_error() -> None:
    calibrator = RiskScoreCalibrator()
    with pytest.raises(ValueError, match=r"Risk score must be in range \[0, 100\]"):
        calibrator.calibrate(-1)

    with pytest.raises(ValueError, match=r"Risk score must be in range \[0, 100\]"):
        calibrator.calibrate(101)


def test_calibrator_batch_conversion() -> None:
    calibrator = RiskScoreCalibrator()
    scores = [0, 25, 50, 75, 100]
    probs = calibrator.calibrate_batch(scores)
    assert len(probs) == 5
    assert probs[0] <= 0.02
    assert probs[2] == 0.50
    assert probs[4] >= 0.98


# ===========================================================================
# 16. Phase 3: Tenant Risk Profile & Policy Tests
# ===========================================================================
def test_tenant_profile_presets_and_thresholds() -> None:
    t_id = uuid4()
    p_agg = TenantRiskProfile.create_aggressive(t_id)
    p_bal = TenantRiskProfile.create_balanced(t_id)
    p_per = TenantRiskProfile.create_permissive(t_id)

    assert p_agg.sensitivity == TenantRiskSensitivity.AGGRESSIVE
    assert p_agg.threshold_clean_max == 19
    assert p_agg.threshold_suspicious_max == 49

    assert p_bal.sensitivity == TenantRiskSensitivity.BALANCED
    assert p_bal.threshold_clean_max == 29
    assert p_bal.threshold_suspicious_max == 69

    assert p_per.sensitivity == TenantRiskSensitivity.PERMISSIVE
    assert p_per.threshold_clean_max == 39
    assert p_per.threshold_suspicious_max == 79


def test_tenant_profile_provider_fallback_to_balanced() -> None:
    provider = InMemoryTenantRiskProfileProvider()
    t_unknown = uuid4()
    prof = provider.get_profile(t_unknown)
    assert prof.tenant_id == t_unknown
    assert prof.sensitivity == TenantRiskSensitivity.BALANCED


def test_same_evidence_different_tenant_policy_verdict() -> None:
    """CRITICAL TEST: Same evidence yields identical risk_score and calibrated_probability, but distinct tenant policy verdicts."""
    t_agg = uuid4()
    t_bal = uuid4()

    p_agg = TenantRiskProfile.create_aggressive(t_agg)
    p_bal = TenantRiskProfile.create_balanced(t_bal)

    provider = InMemoryTenantRiskProfileProvider()
    provider.set_profile(p_agg)
    provider.set_profile(p_bal)

    pipeline = RiskAssessmentPipeline(profile_provider=provider)

    # Build identical evidence resulting in intermediate score (e.g. 55 pts: Threat Intel 35 + Media OCR 20 = 55 pts)
    p1 = _build_minimal_parsed_email(tenant_id=t_agg)
    t1 = _build_minimal_transmission(p1)
    a1 = _build_minimal_auth(p1)
    i1 = ThreatIntelEnrichmentResult(
        enrichment_id=uuid4(),
        parsed_id=p1.parsed_id,
        transmission_id=t1.analysis_id,
        auth_verification_id=a1.verification_id,
        account_id=p1.account_id,
        tenant_id=p1.tenant_id,
        message_id=p1.message_id,
        malicious_ioc_count=3,
        overall_confidence=ConfidenceScoreDTO(confidence=1.0),
    )

    content_res = ContentAnalysisResult(
        analysis_id=uuid4(),
        parsed_id=p1.parsed_id,
        tenant_id=p1.tenant_id,
        message_id=p1.message_id,
        dom_signals=DOMContentSignalsDTO(),
        intent_analysis=ContentIntentAnalysisDTO(),
        media_evidence=ContentMediaEvidenceDTO(
            ocr_status=MediaStatus.SUCCESS,
            ocr_extracted_text="URGENT: Please verify your bank account login credentials immediately.",
            ocr_confidence=1.0,
        ),
    )

    # Threat Intel IOC hit (35 pts) + Media OCR phishing detected (20 pts) = 55 pts
    # For Tenant Aggressive (threshold_suspicious_max = 49 -> Score 55 is MALICIOUS)
    res_agg = pipeline.assess_risk(
        parsed=p1, transmission=t1, auth=a1, intel=i1, content_res=content_res
    )

    # Evaluate for Tenant Balanced (threshold_suspicious_max = 69 -> Score 55 is SUSPICIOUS)
    p2 = _build_minimal_parsed_email(tenant_id=t_bal)
    t2 = _build_minimal_transmission(p2)
    a2 = _build_minimal_auth(p2)
    i2 = ThreatIntelEnrichmentResult(
        enrichment_id=uuid4(),
        parsed_id=p2.parsed_id,
        transmission_id=t2.analysis_id,
        auth_verification_id=a2.verification_id,
        account_id=p2.account_id,
        tenant_id=p2.tenant_id,
        message_id=p2.message_id,
        malicious_ioc_count=3,
        overall_confidence=ConfidenceScoreDTO(confidence=1.0),
    )

    res_bal = pipeline.assess_risk(
        parsed=p2, transmission=t2, auth=a2, intel=i2, content_res=content_res
    )

    # 1. Deterministic score must be IDENTICAL (53 pts)
    assert res_agg.risk_score == res_bal.risk_score
    assert res_agg.risk_score == 53
    # 2. Calibrated probability must be IDENTICAL
    assert res_agg.calibrated_probability == res_bal.calibrated_probability
    # 3. Policy Verdicts must DIFFER according to tenant policy
    from src.common.constants import ActionTaken, Verdict
    assert res_agg.verdict == Verdict.MALICIOUS
    assert res_agg.recommended_action == ActionTaken.QUARANTINED
    assert res_agg.tenant_profile == "AGGRESSIVE"

    assert res_bal.verdict == Verdict.SUSPICIOUS
    assert res_bal.recommended_action == ActionTaken.BANNER_INJECTED
    assert res_bal.tenant_profile == "BALANCED"


# ===========================================================================
# 17. Phase 3: Pipeline & Engine End-to-End Multimodal Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_engine_multimodal_execution_and_event_publishing() -> None:
    events_published = []

    class MockEventPublisher:
        async def publish(self, event) -> None:
            events_published.append(event)

    publisher = MockEventPublisher()
    engine = RiskAssessmentEngine(event_publisher=publisher)

    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    content_res = ContentAnalysisResult(
        analysis_id=uuid4(),
        parsed_id=parsed.parsed_id,
        tenant_id=parsed.tenant_id,
        message_id=parsed.message_id,
        dom_signals=DOMContentSignalsDTO(has_hidden_text=True),
        intent_analysis=ContentIntentAnalysisDTO(urgency_score=0.95),
        media_evidence=ContentMediaEvidenceDTO(),
    )

    assessment = await engine.assess_risk(
        parsed=parsed,
        transmission=trans,
        auth=auth,
        intel=intel,
        content_res=content_res,
    )

    assert isinstance(assessment, RiskAssessment)
    assert assessment.risk_score > 0
    assert 0.0 <= assessment.calibrated_probability <= 1.0
    assert assessment.tenant_profile == "BALANCED"

    # Verify RiskScoredEvent was published
    assert len(events_published) == 1
    event = events_published[0]
    assert event.risk_score == assessment.risk_score
    assert event.verdict == assessment.verdict


@pytest.mark.asyncio
async def test_orchestrator_stage4_multimodal_signal_propagation() -> None:
    from src.database.models import RawEmail
    from src.orchestrator.orchestrator import EmailSecurityPipelineOrchestrator

    orchestrator = EmailSecurityPipelineOrchestrator()
    t_id = uuid4()
    raw_email = RawEmail(
        id=uuid4(),
        account_id=uuid4(),
        tenant_id=t_id,
        message_id="msg_orch_001",
        internet_message_id="<msg_orch_001@example.com>",
        raw_eml_data=b"From: sender@example.com\r\nTo: user@company.com\r\nSubject: Test Email\r\n\r\nHello World",
        raw_size_bytes=80,
    )

    result = await orchestrator.execute_pipeline(raw_email)
    assert result is not None
    assert result.risk_assessment is not None
    assert 0 <= result.risk_assessment.risk_score <= 100
    assert 0.0 <= result.risk_assessment.calibrated_probability <= 1.0
    assert result.risk_assessment.tenant_profile == "BALANCED"


@pytest.mark.asyncio
async def test_ai_decision_engine_compatibility_with_multimodal_risk() -> None:
    from src.ai_decision.engine import AIDecisionEngine

    ai_engine = AIDecisionEngine()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    pipeline = RiskAssessmentPipeline()
    assessment = pipeline.assess_risk(parsed, trans, auth, intel)

    decision_plan = await ai_engine.generate_decision_plan(assessment)
    assert decision_plan is not None
    assert decision_plan.assessment_id == assessment.assessment_id
    assert decision_plan.tenant_id == assessment.tenant_id
    assert len(decision_plan.recommended_actions) >= 1


@pytest.mark.asyncio
async def test_remediation_engine_compatibility_with_multimodal_risk() -> None:
    from src.ai_decision.models import DecisionPlan
    from src.remediation.engine import RemediationEngine

    remediation = RemediationEngine()
    parsed = _build_minimal_parsed_email()
    trans = _build_minimal_transmission(parsed)
    auth = _build_minimal_auth(parsed)
    intel = _build_minimal_intel(parsed)

    pipeline = RiskAssessmentPipeline()
    assessment = pipeline.assess_risk(parsed, trans, auth, intel)

    plan = DecisionPlan(
        assessment_id=assessment.assessment_id,
        tenant_id=assessment.tenant_id,
        message_id=assessment.message_id,
        executive_summary="Executive summary test",
        technical_summary="Technical summary test",
        analyst_explanation="Explanation test",
        attack_summary="Attack summary test",
        business_impact="Low impact test",
        recommended_actions=["QUARANTINE_MESSAGE"],
        risk_confidence=1.0,
        ai_decision_confidence=1.0,
    )

    remediation_res = await remediation.execute_remediation(
        tenant_id=assessment.tenant_id,
        incident_id=assessment.parsed_id,
        assessment=assessment,
        decision_plan=plan,
        requested_action=assessment.recommended_action,
        is_dry_run=True,
    )

    assert remediation_res is not None
    assert remediation_res.is_dry_run is True
