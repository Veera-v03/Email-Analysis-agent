"""Data contracts for canonical email-address normalization."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

MAX_NORMALIZATION_INPUT_LENGTH = 8_192
MAX_CANONICAL_EMAIL_LENGTH = 320
MAX_CANONICAL_USERNAME_LENGTH = 64
MAX_CANONICAL_DOMAIN_LENGTH = 255


class AddressNormalizationAction(StrEnum):
    """Describe a deterministic formatting repair applied to an address."""

    DISPLAY_WRAPPER_REMOVED = "display_wrapper_removed"
    LEADING_OR_TRAILING_WHITESPACE_REMOVED = "leading_or_trailing_whitespace_removed"
    INTERNAL_WHITESPACE_REMOVED = "internal_whitespace_removed"
    MAILTO_PREFIX_REMOVED = "mailto_prefix_removed"
    REPEATED_AT_SEPARATOR_COLLAPSED = "repeated_at_separator_collapsed"
    REPEATED_DOT_SEPARATOR_COLLAPSED = "repeated_dot_separator_collapsed"
    CASE_NORMALIZED = "case_normalized"
    DOMAIN_IDNA_ENCODED = "domain_idna_encoded"


class NormalizedEmailAddress(BaseModel):
    """Contain original input and its safe canonical mailbox representation."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    raw_value: StrictStr = Field(max_length=MAX_NORMALIZATION_INPUT_LENGTH)
    canonical_email: StrictStr | None = Field(
        default=None,
        max_length=MAX_CANONICAL_EMAIL_LENGTH,
    )
    username: StrictStr | None = Field(
        default=None,
        max_length=MAX_CANONICAL_USERNAME_LENGTH,
    )
    domain: StrictStr | None = Field(
        default=None,
        max_length=MAX_CANONICAL_DOMAIN_LENGTH,
    )
    is_valid: StrictBool
    actions: tuple[AddressNormalizationAction, ...] = ()
