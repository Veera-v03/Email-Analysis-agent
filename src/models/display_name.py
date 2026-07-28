"""Structured display-name analysis data contracts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
)

MAX_DISPLAY_NAME_INPUT_LENGTH = 998
MAX_DISPLAY_NAME_TERM_LENGTH = 128


class ImpersonationIndicator(StrEnum):
    """Describe an observable display-name context relevant to impersonation review."""

    ORGANIZATION_REFERENCE = "organization_reference"
    ADMINISTRATOR_REFERENCE = "administrator_reference"
    ORGANIZATION_SECURITY_CONTEXT = "organization_security_context"
    ORGANIZATION_SUPPORT_CONTEXT = "organization_support_context"


class DisplayNameLexicon(BaseModel):
    """Contain caller-owned terms for deterministic display-name analysis."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    organization_names: tuple[StrictStr, ...] = Field(default=())
    security_keywords: tuple[StrictStr, ...] = Field(default=())
    urgency_words: tuple[StrictStr, ...] = Field(default=())
    billing_words: tuple[StrictStr, ...] = Field(default=())
    support_words: tuple[StrictStr, ...] = Field(default=())
    administrator_names: tuple[StrictStr, ...] = Field(default=())


class DisplayNameAnalysisPolicy(BaseModel):
    """Configure deterministic formatting thresholds for display-name features."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    minimum_alphabetic_characters: StrictInt = Field(default=4, ge=1)
    uppercase_ratio_threshold: StrictFloat = Field(default=0.75, gt=0, le=1)
    excessive_punctuation_threshold: StrictInt = Field(default=3, ge=1)


class DisplayNameAnalysisResult(BaseModel):
    """Contain structured display-name observations without a security verdict."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    raw_value: StrictStr = Field(max_length=MAX_DISPLAY_NAME_INPUT_LENGTH)
    normalized_value: StrictStr = Field(max_length=MAX_DISPLAY_NAME_INPUT_LENGTH)
    is_empty: StrictBool
    organization_names: tuple[StrictStr, ...] = Field(default=())
    security_keywords: tuple[StrictStr, ...] = Field(default=())
    urgency_words: tuple[StrictStr, ...] = Field(default=())
    billing_words: tuple[StrictStr, ...] = Field(default=())
    support_words: tuple[StrictStr, ...] = Field(default=())
    administrator_names: tuple[StrictStr, ...] = Field(default=())
    uppercase_character_count: StrictInt = Field(ge=0)
    alphabetic_character_count: StrictInt = Field(ge=0)
    uppercase_ratio: StrictFloat = Field(ge=0, le=1)
    is_suspiciously_capitalized: StrictBool
    punctuation_count: StrictInt = Field(ge=0)
    has_excessive_punctuation: StrictBool
    impersonation_indicators: tuple[ImpersonationIndicator, ...] = Field(default=())
