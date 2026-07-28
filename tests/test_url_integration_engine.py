"""Integration tests for the Phase 4 URL intelligence pipeline."""

from __future__ import annotations

from src.analyzers.url.engine import UrlIntelligenceEngine
from src.models.email import EmailAttachment, EmailHeader, EmailInput
from src.models.url import FinalUrlIntelligence


def test_url_intelligence_engine_integrates_all_phase_4_components() -> None:
    email = EmailInput(
        header=EmailHeader(
            message_id="<msg-001>",
            sender="sender@example.com",
            recipients=["user@example.com"],
            subject="Check this link",
            sent_at="2026-01-01T00:00:00Z",
        ),
        body_text='<a href="https://bit.ly/abc?x=1">click here</a>',
        attachments=[
            EmailAttachment(
                filename="note.txt", content_type="text/plain", size_bytes=12
            )
        ],
    )

    engine = UrlIntelligenceEngine()
    results = engine.analyze(email)

    assert len(results) == 1
    first = results[0]
    assert isinstance(first, FinalUrlIntelligence)
    assert first.extracted.raw_value == "https://bit.ly/abc?x=1"
    assert first.normalized is not None
    assert first.normalized.is_valid is True
    assert first.components.is_parseable is True
    assert first.host.host_type.value in {
        "domain",
        "ipv4",
        "ipv6",
        "localhost",
        "empty",
        "invalid",
    }
    assert first.structural_features is not None
    assert first.unicode_analysis is not None
    assert first.shortener.is_shortened is True
    assert first.shortener.matched_shortener_host == "bit.ly"
    assert first.suspicious_patterns
    assert first.html_context is not None
    assert first.redirect_result is not None
    assert first.reputation_result is not None
    assert first.evidence


def test_url_intelligence_engine_returns_empty_result_for_email_without_urls() -> None:
    email = EmailInput(
        header=EmailHeader(
            message_id="<msg-002>",
            sender="sender@example.com",
            recipients=["user@example.com"],
            subject="No links here",
            sent_at="2026-01-01T00:00:00Z",
        ),
        body_text="This email contains no URLs.",
    )

    engine = UrlIntelligenceEngine()
    assert engine.analyze(email) == ()
