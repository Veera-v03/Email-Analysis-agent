"""Unified immutable result contract for Phase 3 sender intelligence."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StrictStr

from src.models.authentication import AuthenticationAnalysisResult
from src.models.display_name import DisplayNameAnalysisResult
from src.models.domain import DomainParseResult
from src.models.domain_features import DomainFeatureResult
from src.models.email_normalization import NormalizedEmailAddress
from src.models.evidence import EvidenceCollection
from src.models.sender import (
    ParsedEmailAddress,
)
from src.models.sender import (
    SenderAnalysisResult as AddressAnalysisResult,
)
from src.models.sender_consistency import (
    SenderHeaderComparisonResult,
    SenderHeaderName,
)
from src.models.sender_relationship import SenderRelationshipGraph

MAX_METADATA_KEY_LENGTH = 128
MAX_METADATA_TEXT_LENGTH = 256


class SenderIdentity(BaseModel):
    """Contain optional primary identity observations for sender headers."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    from_address: ParsedEmailAddress | None = None
    sender_address: ParsedEmailAddress | None = None
    reply_to_address: ParsedEmailAddress | None = None
    return_path_address: ParsedEmailAddress | None = None


class NormalizedAddressEvidence(BaseModel):
    """Associate a normalized address result with its source header occurrence."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    source_header: SenderHeaderName
    normalized_address: NormalizedEmailAddress


class SenderDomainEvidence(BaseModel):
    """Associate parsed and featured domain evidence with a source header."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    source_header: SenderHeaderName
    parsed_domain: DomainParseResult
    features: DomainFeatureResult | None = None


class SenderMetadataEntry(BaseModel):
    """Represent one immutable JSON-compatible metadata value."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    key: StrictStr = Field(min_length=1, max_length=MAX_METADATA_KEY_LENGTH)
    value: JsonValue


class SenderAnalysisMetadata(BaseModel):
    """Contain immutable operation metadata for a unified sender analysis result."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    analysis_id: StrictStr | None = Field(
        default=None,
        max_length=MAX_METADATA_TEXT_LENGTH,
    )
    producer: StrictStr | None = Field(
        default=None,
        max_length=MAX_METADATA_TEXT_LENGTH,
    )
    entries: tuple[SenderMetadataEntry, ...] = Field(default=())


class SenderAnalysisResult(BaseModel):
    """Compose all Phase 3 sender-intelligence outputs into one immutable result.

    This contract contains extracted and deterministic observations only. It has
    no phishing probability, risk score, reputation, or verdict field.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    sender: SenderIdentity
    addresses: AddressAnalysisResult
    normalized_addresses: tuple[NormalizedAddressEvidence, ...] = Field(default=())
    domains: tuple[SenderDomainEvidence, ...] = Field(default=())
    authentication: AuthenticationAnalysisResult | None = None
    consistency: SenderHeaderComparisonResult | None = None
    display_name: DisplayNameAnalysisResult | None = None
    relationships: SenderRelationshipGraph | None = None
    evidence: EvidenceCollection = Field(default_factory=EvidenceCollection)
    metadata: SenderAnalysisMetadata = Field(default_factory=SenderAnalysisMetadata)
