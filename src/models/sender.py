"""Structured sender-intelligence data contracts.

These models retain extracted address evidence only. They intentionally make
no assessment of message safety, sender reputation, or phishing likelihood.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

MAX_RAW_ADDRESS_LENGTH = 8_192
MAX_DISPLAY_NAME_LENGTH = 998
MAX_EMAIL_ADDRESS_LENGTH = 320
MAX_MAILBOX_USERNAME_LENGTH = 64
MAX_DOMAIN_LENGTH = 255


class ParsedEmailAddress(BaseModel):
    """Represent one address value extracted from an RFC message header.

    ``raw_value`` preserves evidence for malformed or partially recoverable
    values. Component fields are populated only when a syntactically usable
    mailbox is available.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    raw_value: StrictStr = Field(min_length=1, max_length=MAX_RAW_ADDRESS_LENGTH)
    display_name: StrictStr | None = Field(
        default=None, max_length=MAX_DISPLAY_NAME_LENGTH
    )
    email: StrictStr | None = Field(default=None, max_length=MAX_EMAIL_ADDRESS_LENGTH)
    username: StrictStr | None = Field(
        default=None,
        max_length=MAX_MAILBOX_USERNAME_LENGTH,
    )
    domain: StrictStr | None = Field(default=None, max_length=MAX_DOMAIN_LENGTH)
    is_syntactically_valid: StrictBool


class SenderAnalysisResult(BaseModel):
    """Contain sender and recipient address evidence from relevant headers."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    from_addresses: tuple[ParsedEmailAddress, ...] = ()
    sender_addresses: tuple[ParsedEmailAddress, ...] = ()
    reply_to_addresses: tuple[ParsedEmailAddress, ...] = ()
    return_path_addresses: tuple[ParsedEmailAddress, ...] = ()
    to_addresses: tuple[ParsedEmailAddress, ...] = ()
    cc_addresses: tuple[ParsedEmailAddress, ...] = ()
    bcc_addresses: tuple[ParsedEmailAddress, ...] = ()
    delivered_to_addresses: tuple[ParsedEmailAddress, ...] = ()
