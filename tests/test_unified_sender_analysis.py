"""Unit tests for the unified Phase 3 sender analysis result contract."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.models.authentication import (
    AuthenticationAnalysisResult,
    AuthenticationMechanism,
    AuthenticationMechanismResult,
    AuthenticationStatus,
)
from src.models.display_name import DisplayNameAnalysisResult
from src.models.domain import DomainParseResult
from src.models.domain_features import DomainFeatureResult
from src.models.email_normalization import NormalizedEmailAddress
from src.models.evidence import Evidence, EvidenceCollection, EvidenceSeverity
from src.models.sender import (
    ParsedEmailAddress,
)
from src.models.sender import (
    SenderAnalysisResult as AddressAnalysisResult,
)
from src.models.sender_analysis import (
    NormalizedAddressEvidence,
    SenderAnalysisMetadata,
    SenderAnalysisResult,
    SenderDomainEvidence,
    SenderIdentity,
    SenderMetadataEntry,
)
from src.models.sender_consistency import (
    SenderHeaderComparisonResult,
    SenderHeaderName,
)
from src.models.sender_relationship import SenderRelationshipGraph


def _address(email: str, display_name: str | None = None) -> ParsedEmailAddress:
    """Create valid parsed address evidence for unified-result tests."""
    username, domain = email.split("@")
    return ParsedEmailAddress(
        raw_value=email,
        display_name=display_name,
        email=email,
        username=username,
        domain=domain,
        is_syntactically_valid=True,
    )


def _authentication_result() -> AuthenticationAnalysisResult:
    """Create a complete normalized authentication fixture."""
    def mechanism_result(
        mechanism: AuthenticationMechanism,
    ) -> AuthenticationMechanismResult:
        return AuthenticationMechanismResult(
            mechanism=mechanism,
            status=AuthenticationStatus.UNKNOWN,
        )

    return AuthenticationAnalysisResult(
        spf=mechanism_result(AuthenticationMechanism.SPF),
        dkim=mechanism_result(AuthenticationMechanism.DKIM),
        dmarc=mechanism_result(AuthenticationMechanism.DMARC),
        arc=mechanism_result(AuthenticationMechanism.ARC),
    )


def _display_name_result() -> DisplayNameAnalysisResult:
    """Create a minimal deterministic display-name analysis fixture."""
    return DisplayNameAnalysisResult(
        raw_value="Account Security",
        normalized_value="Account Security",
        is_empty=False,
        uppercase_character_count=2,
        alphabetic_character_count=15,
        uppercase_ratio=2 / 15,
        is_suspiciously_capitalized=False,
        punctuation_count=0,
        has_excessive_punctuation=False,
    )


def test_unified_result_composes_all_previous_analyzer_outputs() -> None:
    """The result contract holds address, domain, auth, and evidence outputs."""
    from_address = _address("notice@example.com", "Account Security")
    addresses = AddressAnalysisResult(from_addresses=(from_address,))
    parsed_domain = DomainParseResult(
        raw_value="example.com",
        normalized_domain="example.com",
        root_domain="example.com",
        second_level_domain="example",
        tld="com",
        is_valid=True,
        has_known_public_suffix=True,
    )
    features = DomainFeatureResult(
        analyzed_domain="example.com",
        is_valid_domain=True,
        length=11,
        entropy=3.0,
        hyphen_count=0,
        digit_count=0,
        contains_unicode=False,
        contains_punycode=False,
        has_repeated_characters=False,
        maximum_repeated_character_count=1,
        has_uncommon_tld=False,
    )
    result = SenderAnalysisResult(
        sender=SenderIdentity(from_address=from_address),
        addresses=addresses,
        normalized_addresses=(
            NormalizedAddressEvidence(
                source_header=SenderHeaderName.FROM,
                normalized_address=NormalizedEmailAddress(
                    raw_value="Notice@Example.COM",
                    canonical_email="notice@example.com",
                    username="notice",
                    domain="example.com",
                    is_valid=True,
                ),
            ),
        ),
        domains=(
            SenderDomainEvidence(
                source_header=SenderHeaderName.FROM,
                parsed_domain=parsed_domain,
                features=features,
            ),
        ),
        authentication=_authentication_result(),
        consistency=SenderHeaderComparisonResult(),
        display_name=_display_name_result(),
        relationships=SenderRelationshipGraph(),
        evidence=EvidenceCollection(
            items=(
                Evidence(
                    evidence_id="evidence:001",
                    evidence_type="domain.feature",
                    title="Domain feature observed",
                    description="A deterministic domain feature was collected.",
                    severity=EvidenceSeverity.INFO,
                    source="domain_feature_analyzer",
                ),
            )
        ),
        metadata=SenderAnalysisMetadata(
            analysis_id="analysis-001",
            producer="sender-intelligence",
            entries=(SenderMetadataEntry(key="tenant", value="example"),),
        ),
    )

    assert result.sender.from_address == from_address
    assert result.addresses.from_addresses == (from_address,)
    assert result.domains[0].features == features
    assert result.authentication is not None
    assert result.consistency is not None
    assert result.display_name is not None
    assert result.relationships is not None
    assert result.evidence.items[0].source == "domain_feature_analyzer"
    assert result.metadata.entries[0].key == "tenant"


def test_unified_result_is_frozen_and_rejects_unknown_fields() -> None:
    """The composition boundary is immutable and has a strict schema."""
    address = _address("sender@example.com")
    result = SenderAnalysisResult(
        sender=SenderIdentity(from_address=address),
        addresses=AddressAnalysisResult(from_addresses=(address,)),
    )

    with pytest.raises(ValidationError):
        result.sender = SenderIdentity()
    with pytest.raises(ValidationError):
        SenderAnalysisResult(
            sender=SenderIdentity(),
            addresses=AddressAnalysisResult(),
            unexpected_field=True,
        )


def test_unified_result_contains_no_risk_or_probability_fields() -> None:
    """Phase 3 composition remains independent from later scoring concerns."""
    result = SenderAnalysisResult(
        sender=SenderIdentity(),
        addresses=AddressAnalysisResult(),
    )

    serialized = result.model_dump()
    assert "risk_score" not in serialized
    assert "phishing_probability" not in serialized
