"""RFC 5322 Header Unfolding, RFC 2047 Encoded-Word Decoding, and Address Parsing."""

from __future__ import annotations

import email.header
from email.message import Message
from email.utils import getaddresses

from src.parsing.models import HeaderAddressDTO


def decode_rfc2047_header(header_val: str | None) -> str:
    """Decode RFC 2047 encoded-word strings (e.g. =?utf-8?B?...?=)."""
    if not header_val:
        return ""

    decoded_parts: list[str] = []
    try:
        parts = email.header.decode_header(header_val)
        for content, encoding in parts:
            if isinstance(content, bytes):
                enc = encoding or "utf-8"
                try:
                    decoded_parts.append(content.decode(enc, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    decoded_parts.append(content.decode("latin1", errors="replace"))
            else:
                decoded_parts.append(str(content))
        return "".join(decoded_parts)
    except Exception:
        return str(header_val)


def parse_address_header(raw_val: str | None) -> HeaderAddressDTO:
    """Parse single address string into HeaderAddressDTO."""
    if not raw_val:
        return HeaderAddressDTO(name="", address="")

    decoded = decode_rfc2047_header(raw_val)
    parsed = getaddresses([decoded])
    if parsed:
        name, addr = parsed[0]
        return HeaderAddressDTO(name=name.strip(), address=addr.strip().lower())
    return HeaderAddressDTO(name="", address=decoded.strip().lower())


def parse_addresses_list(raw_val: str | None) -> list[HeaderAddressDTO]:
    """Parse comma-separated address header string into list of HeaderAddressDTO."""
    if not raw_val:
        return []

    decoded = decode_rfc2047_header(raw_val)
    parsed_pairs = getaddresses([decoded])
    results: list[HeaderAddressDTO] = []
    for name, addr in parsed_pairs:
        if addr:
            results.append(
                HeaderAddressDTO(name=name.strip(), address=addr.strip().lower())
            )
    return results


def extract_raw_headers_map(msg: Message) -> dict[str, list[str]]:
    """Extract raw headers from email Message object as a dictionary mapping header name to list of values."""
    headers_map: dict[str, list[str]] = {}
    for key, value in msg.items():
        name = key.lower()
        decoded_value = decode_rfc2047_header(value)
        if name in headers_map:
            headers_map[name].append(decoded_value)
        else:
            headers_map[name] = [decoded_value]
    return headers_map
