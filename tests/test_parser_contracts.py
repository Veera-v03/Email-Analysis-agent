"""Unit tests for parser pipeline contracts."""

from __future__ import annotations

import pytest

from src.parsers import (
    EmailLoader,
    EmailParser,
    EmailSourceKind,
    LoadedEmail,
    ParserError,
    ParsingStage,
    RawEmail,
)


def test_raw_email_preserves_declared_source_metadata() -> None:
    """A raw-email value object retains its payload and declared source kind."""
    raw_email = RawEmail(
        payload=b"From: sender@example.com\r\n\r\nMessage",
        source_kind=EmailSourceKind.EML,
        source_name="message.eml",
    )

    assert raw_email.source_kind is EmailSourceKind.EML
    assert raw_email.source_name == "message.eml"


def test_raw_email_rejects_overlong_source_name() -> None:
    """Diagnostic metadata has an explicit bounded size."""
    with pytest.raises(ValueError, match="must not exceed"):
        RawEmail(
            payload="{}",
            source_kind=EmailSourceKind.JSON,
            source_name="x" * 1_025,
        )


def test_contract_protocols_are_runtime_checkable() -> None:
    """Loader and parser contracts support runtime dependency verification."""

    class ExampleLoader:
        """Minimal structural implementation used only for protocol verification."""

        def load(self, raw_email: RawEmail) -> LoadedEmail:
            """Return canonical content for the contract test."""
            return LoadedEmail(
                content=b"",
                source_kind=raw_email.source_kind,
                source_name=raw_email.source_name,
            )

    class ExampleParser:
        """Minimal structural implementation used only for protocol verification."""

        def parse(self, loaded_email: LoadedEmail) -> object:
            """Return a sentinel; structural protocol checks inspect the method."""
            return loaded_email

    assert isinstance(ExampleLoader(), EmailLoader)
    assert isinstance(ExampleParser(), EmailParser)


def test_parser_error_never_embeds_message_content() -> None:
    """Parser errors retain only operational context and their message."""
    error = ParserError(
        stage=ParsingStage.HEADER,
        message="Unable to decode header.",
        source_name="inbound-001.eml",
    )

    assert error.stage is ParsingStage.HEADER
    assert error.source_name == "inbound-001.eml"
    assert str(error) == "Unable to decode header."
