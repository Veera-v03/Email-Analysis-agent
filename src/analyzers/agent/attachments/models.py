"""Domain models for attachment analysis."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
)

from src.models.agent import ToolEvidence


class ReputationStatus(StrEnum):
    """Represent the output status of an attachment reputation check."""

    UNKNOWN = "unknown"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class AttachmentReputationResult(BaseModel):
    """Result of querying attachment hash reputation."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    sha256: StrictStr = Field(default="", max_length=128)
    status: ReputationStatus = Field(default=ReputationStatus.UNKNOWN)
    threat_name: StrictStr | None = Field(default=None)
    score: StrictFloat | None = Field(default=None, ge=0.0, le=100.0)
    details: dict[str, Any] = Field(default_factory=dict)


class AttachmentPayload(BaseModel):
    """Immutable representation of an email attachment for analysis."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    filename: StrictStr = Field(default="", max_length=1024)
    content_type: StrictStr = Field(default="", max_length=256)
    size_bytes: StrictInt = Field(default=0, ge=0)
    content: bytes = Field(default=b"")
    content_id: StrictStr | None = Field(default=None, max_length=256)


class AttachmentAnalysisResult(BaseModel):
    """Structured analysis outcome for a single email attachment."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    filename: StrictStr
    content_type: StrictStr
    size_bytes: StrictInt
    sha256: StrictStr | None = Field(default=None)
    md5: StrictStr | None = Field(default=None)
    entropy: StrictFloat | None = Field(default=None)
    detected_mime: StrictStr | None = Field(default=None)
    is_mime_mismatch: StrictBool = Field(default=False)
    is_dangerous_extension: StrictBool = Field(default=False)
    is_double_extension: StrictBool = Field(default=False)
    is_archive: StrictBool = Field(default=False)
    is_office_doc: StrictBool = Field(default=False)
    is_pdf: StrictBool = Field(default=False)
    is_executable: StrictBool = Field(default=False)
    has_macros: StrictBool = Field(default=False)
    has_pdf_javascript: StrictBool = Field(default=False)
    evidence: tuple[ToolEvidence, ...] = Field(default_factory=tuple)
