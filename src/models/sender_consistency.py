"""Structured evidence models for sender-header consistency comparison."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictStr


class SenderHeaderName(StrEnum):
    """Identify sender-related address-bearing email headers."""

    FROM = "from"
    SENDER = "sender"
    REPLY_TO = "reply_to"
    RETURN_PATH = "return_path"


class HeaderComparisonPair(StrEnum):
    """Identify a deterministic comparison between sender-related headers."""

    FROM_TO_SENDER = "from_to_sender"
    FROM_TO_REPLY_TO = "from_to_reply_to"
    FROM_TO_RETURN_PATH = "from_to_return_path"


class HeaderMismatchType(StrEnum):
    """Describe the type of observed header divergence."""

    EMAIL_ADDRESS = "email_address"
    DOMAIN = "domain"


class UnexpectedHeaderCombination(StrEnum):
    """Describe an unusual sender-header arrangement without judging it as unsafe."""

    SENDER_WITHOUT_FROM = "sender_without_from"
    REPLY_TO_WITHOUT_FROM = "reply_to_without_from"
    RETURN_PATH_WITHOUT_FROM = "return_path_without_from"
    MULTIPLE_FROM_WITHOUT_SENDER = "multiple_from_without_sender"
    MULTIPLE_SENDER_VALUES = "multiple_sender_values"
    MULTIPLE_RETURN_PATH_VALUES = "multiple_return_path_values"


class HeaderMismatchEvidence(BaseModel):
    """Preserve divergent valid mailbox and domain sets for one header comparison."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    comparison: HeaderComparisonPair
    mismatch_type: HeaderMismatchType
    left_header: SenderHeaderName
    right_header: SenderHeaderName
    left_values: tuple[StrictStr, ...] = Field(default=())
    right_values: tuple[StrictStr, ...] = Field(default=())


class InvalidHeaderAddressEvidence(BaseModel):
    """Preserve invalid parsed address values for a present sender header."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    header: SenderHeaderName
    raw_values: tuple[StrictStr, ...] = Field(default=())


class SenderHeaderComparisonResult(BaseModel):
    """Contain deterministic sender-header comparison evidence only."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    missing_headers: tuple[SenderHeaderName, ...] = Field(default=())
    invalid_header_addresses: tuple[InvalidHeaderAddressEvidence, ...] = Field(
        default=()
    )
    mismatches: tuple[HeaderMismatchEvidence, ...] = Field(default=())
    unexpected_combinations: tuple[UnexpectedHeaderCombination, ...] = Field(
        default=()
    )
