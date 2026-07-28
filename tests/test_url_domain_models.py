"""Regression tests for Milestone 4.10 URL domain models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.models.url import (
    ExtractedUrl,
    FinalUrlIntelligence,
    HtmlContext,
    ParsedUrlComponents,
    RedirectMechanism,
    RedirectResult,
    ReputationResult,
    UrlEvidence,
    UrlExtractionSource,
)


def test_url_evidence_model_is_immutable_and_strict() -> None:
    evidence = UrlEvidence(source="unicode", detail="mixed scripts", observed=True)

    assert evidence.source == "unicode"
    assert evidence.observed is True


def test_html_context_model_validates_optional_fields() -> None:
    context = HtmlContext(tag="a", attribute="href", snippet='<a href="#">link</a>')

    assert context.tag == "a"
    assert context.attribute == "href"


def test_redirect_result_model_uses_enum_values() -> None:
    result = RedirectResult(
        mechanism=RedirectMechanism.HTTP,
        detected=True,
        target="https://example.com",
        detail="http redirect",
    )

    assert result.mechanism is RedirectMechanism.HTTP
    assert result.target == "https://example.com"


def test_reputation_result_model_is_validated() -> None:
    result = ReputationResult(provider_name="virustotal", queried=True, available=False)

    assert result.provider_name == "virustotal"
    assert result.queried is True


def test_final_url_intelligence_aggregates_domain_models() -> None:
    intelligence = FinalUrlIntelligence(
        extracted=ExtractedUrl(
            raw_value="https://example.com",
            source=UrlExtractionSource.BODY_TEXT,
            position=0,
        ),
        components=ParsedUrlComponents(
            scheme="https", host="example.com", is_parseable=True
        ),
        html_context=HtmlContext(tag="a", attribute="href"),
        redirect_result=RedirectResult(
            mechanism=RedirectMechanism.HTML, detected=False, detail="none"
        ),
        reputation_result=ReputationResult(
            provider_name="urlhaus", queried=False, available=False
        ),
        evidence=(UrlEvidence(source="shortener", detail="bit.ly", observed=True),),
    )

    assert intelligence.extracted.raw_value == "https://example.com"
    assert intelligence.html_context is not None
    assert intelligence.redirect_result is not None
    assert intelligence.reputation_result is not None


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        UrlEvidence(source="x", detail="y", observed=True, extra="bad")  # type: ignore[call-arg]
