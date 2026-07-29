"""RFC-aware sender and recipient address extraction implementations."""

from __future__ import annotations

from email.header import decode_header
from email.utils import getaddresses

from src.analyzers.sender.contracts import AddressParser, HeaderProvider
from src.models.sender import (
    MAX_DISPLAY_NAME_LENGTH,
    MAX_DOMAIN_LENGTH,
    MAX_EMAIL_ADDRESS_LENGTH,
    MAX_MAILBOX_USERNAME_LENGTH,
    MAX_RAW_ADDRESS_LENGTH,
    ParsedEmailAddress,
    SenderAnalysisResult,
)

ADDRESS_HEADER_NAMES = (
    "From",
    "Sender",
    "Reply-To",
    "Return-Path",
    "To",
    "Cc",
    "Bcc",
    "Delivered-To",
)


class RfcAddressParser:
    """Extract address evidence using Python's RFC-aware standard library."""

    def parse(self, header_values: tuple[str, ...]) -> tuple[ParsedEmailAddress, ...]:
        """Parse all values of one address-bearing message header.

        Malformed values are retained as invalid evidence instead of raising an
        exception or being discarded.
        """
        addresses: list[ParsedEmailAddress] = []
        for header_value in header_values:
            addresses.extend(self._parse_header_value(header_value))
        return tuple(addresses)

    def _parse_header_value(self, header_value: str) -> tuple[ParsedEmailAddress, ...]:
        """Parse a single raw header value with a recovery path for bad syntax."""
        decoded_value = self._decode_value(header_value)
        try:
            parsed_pairs = getaddresses([decoded_value], strict=False)
        except (TypeError, ValueError):
            return (self._malformed_address(header_value),)

        parsed_addresses = tuple(
            self._to_address(display_name, email_address, header_value)
            for display_name, email_address in parsed_pairs
            if display_name or email_address
        )
        if parsed_addresses:
            return parsed_addresses
        return (self._malformed_address(header_value),)

    @staticmethod
    def _decode_value(value: str) -> str:
        """Decode RFC encoded words while preserving recoverable text."""
        decoded_parts: list[str] = []
        try:
            encoded_parts = decode_header(value)
        except (TypeError, ValueError):
            return value

        for part, charset in encoded_parts:
            if isinstance(part, str):
                decoded_parts.append(part)
                continue
            try:
                decoded_parts.append(part.decode(charset or "ascii", errors="replace"))
            except (LookupError, UnicodeError):
                decoded_parts.append(part.decode("utf-8", errors="replace"))
        return "".join(decoded_parts)

    def _to_address(
        self,
        display_name: str,
        email_address: str,
        original_value: str,
    ) -> ParsedEmailAddress:
        """Convert one standard-library parsed pair into an evidence model."""
        normalized_display_name = (
            self._bounded_text(
                display_name.strip(),
                MAX_DISPLAY_NAME_LENGTH,
            )
            or None
        )
        normalized_email = email_address.strip()
        raw_value = self._bounded_text(
            normalized_email or normalized_display_name or original_value.strip(),
            MAX_RAW_ADDRESS_LENGTH,
        )
        username, domain = self._split_mailbox(normalized_email)
        is_valid = username is not None and domain is not None

        return ParsedEmailAddress(
            raw_value=raw_value,
            display_name=normalized_display_name,
            email=normalized_email if is_valid else None,
            username=username,
            domain=domain,
            is_syntactically_valid=is_valid,
        )

    @staticmethod
    def _malformed_address(original_value: str) -> ParsedEmailAddress:
        """Preserve an unparseable address header value as invalid evidence."""
        return ParsedEmailAddress(
            raw_value=RfcAddressParser._bounded_text(
                original_value.strip() or "<empty>",
                MAX_RAW_ADDRESS_LENGTH,
            ),
            is_syntactically_valid=False,
        )

    @staticmethod
    def _split_mailbox(email_address: str) -> tuple[str | None, str | None]:
        """Return mailbox components when the address is minimally well formed."""
        username, separator, domain = email_address.rpartition("@")
        if (
            not separator
            or not username
            or not domain
            or len(email_address) > MAX_EMAIL_ADDRESS_LENGTH
            or len(username) > MAX_MAILBOX_USERNAME_LENGTH
            or len(domain) > MAX_DOMAIN_LENGTH
            or any(character.isspace() for character in email_address)
            or not email_address.isprintable()
        ):
            return None, None
        return username, domain.casefold()

    @staticmethod
    def _bounded_text(value: str, maximum_length: int) -> str:
        """Return text constrained to the output model's storage bound."""
        return value[:maximum_length]


class StructuredSenderExtractor:
    """Collect address evidence for all sender-intelligence header fields."""

    def __init__(self, address_parser: AddressParser | None = None) -> None:
        """Create the extractor with an injectable address-parser dependency."""
        self._address_parser = address_parser or RfcAddressParser()

    def extract(self, headers: HeaderProvider) -> SenderAnalysisResult:
        """Extract structured sender intelligence from supported address headers."""
        extracted = {
            header_name: self._address_parser.parse(headers.get_all(header_name))
            for header_name in ADDRESS_HEADER_NAMES
        }
        return SenderAnalysisResult(
            from_addresses=extracted["From"],
            sender_addresses=extracted["Sender"],
            reply_to_addresses=extracted["Reply-To"],
            return_path_addresses=extracted["Return-Path"],
            to_addresses=extracted["To"],
            cc_addresses=extracted["Cc"],
            bcc_addresses=extracted["Bcc"],
            delivered_to_addresses=extracted["Delivered-To"],
        )
