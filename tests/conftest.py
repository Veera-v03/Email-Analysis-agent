"""Shared pytest fixtures for Phase 3 Milestone 3.12 test suite."""

from __future__ import annotations

import pytest

from src.analyzers.sender.authentication import (
    DeterministicAuthenticationHeaderInterpreter,
)
from src.analyzers.sender.display_name import DeterministicDisplayNameAnalyzer
from src.analyzers.sender.domain import PublicSuffixDomainParser
from src.analyzers.sender.domain_features import DeterministicDomainFeatureAnalyzer
from src.analyzers.sender.engine import SenderIntelligenceEngine
from src.analyzers.sender.extractor import RfcAddressParser, StructuredSenderExtractor
from src.analyzers.sender.header_comparison import DeterministicSenderHeaderComparator
from src.analyzers.sender.normalization import CanonicalEmailAddressNormalizer
from src.analyzers.sender.relationships import DeterministicSenderRelationshipBuilder
from src.models.display_name import DisplayNameAnalysisPolicy, DisplayNameLexicon
from src.models.domain_features import DomainFeatureLexicon
from src.models.email import EmailHeader, EmailInput
from src.models.sender import ParsedEmailAddress

# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------


def make_address(
    email: str,
    display_name: str | None = None,
    *,
    valid: bool = True,
) -> ParsedEmailAddress:
    """Create a ParsedEmailAddress for use in tests."""
    if valid:
        username, domain = email.split("@", 1)
        return ParsedEmailAddress(
            raw_value=email,
            display_name=display_name,
            email=email,
            username=username,
            domain=domain,
            is_syntactically_valid=True,
        )
    return ParsedEmailAddress(raw_value=email, is_syntactically_valid=False)


def make_email_input(
    sender: str = "sender@example.com",
    recipients: list[str] | None = None,
    reply_to: str | None = None,
    message_id: str = "<test@example.com>",
    subject: str = "Test subject",
    sent_at: str = "2026-01-01T00:00:00Z",
    body_text: str = "Test body.",
) -> EmailInput:
    """Create a minimal EmailInput for engine integration tests."""
    return EmailInput(
        header=EmailHeader(
            message_id=message_id,
            sender=sender,
            recipients=recipients or ["recipient@example.net"],
            subject=subject,
            sent_at=sent_at,
            reply_to=reply_to,
        ),
        body_text=body_text,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def parser() -> RfcAddressParser:
    return RfcAddressParser()


@pytest.fixture
def extractor() -> StructuredSenderExtractor:
    return StructuredSenderExtractor()


@pytest.fixture
def normalizer() -> CanonicalEmailAddressNormalizer:
    return CanonicalEmailAddressNormalizer()


@pytest.fixture
def domain_parser() -> PublicSuffixDomainParser:
    return PublicSuffixDomainParser()


@pytest.fixture
def feature_analyzer() -> DeterministicDomainFeatureAnalyzer:
    return DeterministicDomainFeatureAnalyzer(
        DomainFeatureLexicon(
            suspicious_keywords=("secure", "verify", "login", "update"),
            brand_keywords=("paypal", "microsoft", "amazon", "google"),
            common_tlds=("com", "org", "net", "edu", "gov", "co.uk"),
        )
    )


@pytest.fixture
def display_name_analyzer() -> DeterministicDisplayNameAnalyzer:
    return DeterministicDisplayNameAnalyzer(
        lexicon=DisplayNameLexicon(
            organization_names=("Microsoft", "PayPal", "Amazon", "Google"),
            security_keywords=("security", "verify", "alert"),
            urgency_words=("urgent", "immediate", "action required"),
            billing_words=("invoice", "payment", "billing"),
            support_words=("support", "helpdesk"),
            administrator_names=("administrator", "admin", "it department"),
        ),
        policy=DisplayNameAnalysisPolicy(
            minimum_alphabetic_characters=4,
            uppercase_ratio_threshold=0.75,
            excessive_punctuation_threshold=3,
        ),
    )


@pytest.fixture
def comparator() -> DeterministicSenderHeaderComparator:
    return DeterministicSenderHeaderComparator()


@pytest.fixture
def auth_interpreter() -> DeterministicAuthenticationHeaderInterpreter:
    return DeterministicAuthenticationHeaderInterpreter()


@pytest.fixture
def relationship_builder() -> DeterministicSenderRelationshipBuilder:
    return DeterministicSenderRelationshipBuilder()


@pytest.fixture
def engine() -> SenderIntelligenceEngine:
    return SenderIntelligenceEngine()
