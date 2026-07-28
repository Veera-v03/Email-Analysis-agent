"""Deterministic domain feature-analysis data contracts."""

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

MAX_FEATURE_TERM_LENGTH = 128


class TyposquattingIndicator(StrEnum):
    """Describe a deterministic brand-similarity observation."""

    SINGLE_EDIT_DISTANCE = "single_edit_distance"
    HYPHENATED_BRAND = "hyphenated_brand"


class DomainFeatureLexicon(BaseModel):
    """Inject policy-owned terms used for deterministic feature extraction.

    Empty collections are intentional defaults: the feature engine itself owns
    no mutable policy or keyword catalogue.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    suspicious_keywords: tuple[StrictStr, ...] = Field(default=())
    brand_keywords: tuple[StrictStr, ...] = Field(default=())
    common_tlds: tuple[StrictStr, ...] = Field(default=())


class DomainFeatureResult(BaseModel):
    """Contain deterministic, non-reputational domain features."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    analyzed_domain: StrictStr = Field(max_length=253)
    is_valid_domain: StrictBool
    length: StrictInt = Field(ge=0, le=253)
    entropy: StrictFloat = Field(ge=0)
    hyphen_count: StrictInt = Field(ge=0)
    digit_count: StrictInt = Field(ge=0)
    contains_unicode: StrictBool
    contains_punycode: StrictBool
    has_repeated_characters: StrictBool
    maximum_repeated_character_count: StrictInt = Field(ge=0)
    suspicious_keywords: tuple[StrictStr, ...] = Field(default=())
    brand_keywords: tuple[StrictStr, ...] = Field(default=())
    has_uncommon_tld: StrictBool
    typosquatting_indicators: tuple[TyposquattingIndicator, ...] = Field(default=())
