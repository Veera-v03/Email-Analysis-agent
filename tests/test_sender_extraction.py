"""Unit tests for Phase 3 sender extraction."""

from __future__ import annotations

from email.message import Message

import pytest

from src.analyzers.sender import (
    MappingHeaderProvider,
    MessageHeaderProvider,
    RfcAddressParser,
    StructuredSenderExtractor,
)


def test_extracts_all_required_header_fields() -> None:
    """Every supported address-bearing header is extracted independently."""
    headers = MappingHeaderProvider(
        {
            "From": "Security Team <security@example.com>",
            "Sender": "mailer@example.com",
            "Reply-To": "help@example.org",
            "Return-Path": "<bounces@example.net>",
            "To": "Alex <alex@example.net>, Bea <bea@example.net>",
            "Cc": "cc@example.net",
            "Bcc": "bcc@example.net",
            "Delivered-To": "inbox@example.net",
        }
    )

    result = StructuredSenderExtractor().extract(headers)

    assert result.from_addresses[0].display_name == "Security Team"
    assert result.from_addresses[0].username == "security"
    assert result.from_addresses[0].domain == "example.com"
    assert result.sender_addresses[0].email == "mailer@example.com"
    assert result.reply_to_addresses[0].email == "help@example.org"
    assert result.return_path_addresses[0].email == "bounces@example.net"
    assert [item.email for item in result.to_addresses] == [
        "alex@example.net",
        "bea@example.net",
    ]
    assert result.cc_addresses[0].email == "cc@example.net"
    assert result.bcc_addresses[0].email == "bcc@example.net"
    assert result.delivered_to_addresses[0].email == "inbox@example.net"


def test_missing_headers_produce_empty_address_collections() -> None:
    """Absent headers are represented without raising exceptions."""
    result = StructuredSenderExtractor().extract(MappingHeaderProvider({}))

    assert result.from_addresses == ()
    assert result.to_addresses == ()
    assert result.reply_to_addresses == ()


def test_malformed_address_is_retained_as_invalid_evidence() -> None:
    """Malformed data remains observable and does not stop extraction."""
    result = StructuredSenderExtractor().extract(
        MappingHeaderProvider({"From": "not a valid mailbox"})
    )

    # getaddresses splits on whitespace tokens; at least one invalid address is produced
    assert len(result.from_addresses) >= 1
    assert all(not addr.is_syntactically_valid for addr in result.from_addresses)
    assert all(addr.email is None for addr in result.from_addresses)
    assert all(addr.username is None for addr in result.from_addresses)
    assert all(addr.domain is None for addr in result.from_addresses)


def test_oversized_malformed_header_is_safely_bounded() -> None:
    """Malformed evidence is bounded before constructing the strict model."""
    result = StructuredSenderExtractor().extract(
        MappingHeaderProvider({"From": "x" * 10_000})
    )

    assert len(result.from_addresses[0].raw_value) == 8_192
    assert result.from_addresses[0].is_syntactically_valid is False


def test_encoded_display_name_is_decoded() -> None:
    """RFC encoded words are decoded before address evidence is created."""
    addresses = RfcAddressParser().parse(
        ("=?utf-8?b?Sm9zw6kgU2lsdmE=?= <jose@example.com>",)
    )

    assert addresses[0].display_name == "José Silva"
    assert addresses[0].email == "jose@example.com"


def test_message_adapter_preserves_repeated_header_values() -> None:
    """The standard-library message adapter supports repeated header fields."""
    # Use the base Message class which allows repeated headers
    message = Message()
    message["X-Recipient"] = "first@example.com"
    message["X-Recipient"] = "second@example.com"

    provider = MessageHeaderProvider(message)
    values = provider.get_all("X-Recipient")

    assert values == ("first@example.com", "second@example.com")


def test_mapping_provider_rejects_non_text_header_values() -> None:
    """The mapping adapter rejects invalid integration data at its boundary."""
    with pytest.raises(TypeError, match="must be strings"):
        MappingHeaderProvider({"From": ["sender@example.com", 1]})  # type: ignore[list-item]
