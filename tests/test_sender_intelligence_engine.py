"""Integration tests for the Phase 3 sender intelligence engine."""

from __future__ import annotations

from src.analyzers.sender.display_name import DeterministicDisplayNameAnalyzer
from src.analyzers.sender.domain_features import DeterministicDomainFeatureAnalyzer
from src.analyzers.sender.engine import SenderIntelligenceEngine
from src.models.authentication import AuthenticationStatus
from src.models.display_name import DisplayNameLexicon
from src.models.domain_features import DomainFeatureLexicon
from src.models.email import EmailHeader, EmailInput


def _email_input() -> EmailInput:
    """Create a Phase 2 input fixture for Phase 3 integration testing."""
    return EmailInput(
        header=EmailHeader(
            message_id="<integration-001@example.com>",
            sender="Microsoft Security <Notice@Example.COM>",
            recipients=["recipient@example.net"],
            subject="Account notice",
            sent_at="2026-07-28T10:00:00+05:30",
            reply_to="Help Desk <help@example.com>",
        ),
        body_text="Validated body content.",
    )


def test_engine_composes_phase_three_outputs_from_email_input() -> None:
    """The engine runs all Phase 3 components without accessing raw email data."""
    engine = SenderIntelligenceEngine(
        domain_feature_analyzer=DeterministicDomainFeatureAnalyzer(
            DomainFeatureLexicon(common_tlds=("com",))
        ),
        display_name_analyzer=DeterministicDisplayNameAnalyzer(
            DisplayNameLexicon(
                organization_names=("Microsoft",),
                security_keywords=("Security",),
            )
        ),
    )

    result = engine.analyze(_email_input())

    assert result.sender.from_address is not None
    assert result.sender.from_address.email == "Notice@Example.COM"
    assert len(result.normalized_addresses) == 2
    assert len(result.domains) == 2
    assert result.authentication is not None
    assert result.authentication.spf.status is AuthenticationStatus.UNKNOWN
    assert result.consistency is not None
    assert result.display_name is not None
    assert result.display_name.organization_names == ("microsoft",)
    assert result.relationships is not None
    assert result.relationships.nodes
    assert result.metadata.analysis_id == "<integration-001@example.com>"


def test_engine_emits_independent_stage_evidence_without_a_risk_score() -> None:
    """Every integrated stage contributes evidence without calculating risk."""
    result = SenderIntelligenceEngine().analyze(_email_input())

    sources = {item.source for item in result.evidence.items}
    assert {
        "sender_extractor",
        "email_address_normalizer",
        "domain_feature_analyzer",
        "display_name_analyzer",
        "sender_header_comparator",
        "authentication_header_interpreter",
        "sender_relationship_builder",
        "sender_intelligence_engine",
    }.issubset(sources)
    assert "risk_score" not in result.model_dump()
    assert "phishing_probability" not in result.model_dump()
