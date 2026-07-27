"""Stable interfaces and value objects for the email parsing pipeline.

The contracts intentionally depend only on the standard library and the
existing normalized application model. Concrete source loaders and MIME
parsers can be introduced independently without changing their consumers.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from src.models import EmailInput


class EmailSourceKind(StrEnum):
    """Represent a raw email representation accepted by the ingestion boundary."""

    JSON = "json"
    EML = "eml"
    MSG = "msg"


class ParsingStage(StrEnum):
    """Identify the pipeline stage at which a recoverable parsing error occurred."""

    LOADING = "loading"
    HEADER = "header"
    BODY = "body"
    ATTACHMENT = "attachment"
    NORMALIZATION = "normalization"


RawPayload = bytes | str | Mapping[str, object]


@dataclass(frozen=True, slots=True)
class RawEmail:
    """Carry caller-supplied email content and its explicitly declared format.

    Explicit source typing avoids unreliable content heuristics at the
    application boundary. JSON payloads may be supplied as a mapping, UTF-8
    string, or bytes. EML and future MSG payloads may be supplied as text or
    bytes.

    Args:
        payload: Unprocessed email content from a trusted transport boundary.
        source_kind: Declared representation of ``payload``.
        source_name: Optional non-sensitive source identifier for diagnostics.
    """

    payload: RawPayload
    source_kind: EmailSourceKind
    source_name: str | None = None

    def __post_init__(self) -> None:
        """Validate lightweight transport metadata without inspecting content."""
        if not self.source_name:
            return
        if len(self.source_name) > 1_024:
            message = "source_name must not exceed 1024 characters."
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class LoadedEmail:
    """Represent an immutable, canonical binary payload ready for parsing.

    Loaders are responsible for encoding text and mapping payloads into bytes.
    Parsers therefore receive a single payload representation regardless of the
    original caller input.

    Args:
        content: Canonical raw email bytes.
        source_kind: Declared source representation.
        source_name: Optional non-sensitive source identifier for diagnostics.
    """

    content: bytes
    source_kind: EmailSourceKind
    source_name: str | None = None


class ParserError(Exception):
    """Describe an expected, safely reportable failure in the parsing pipeline.

    The exception excludes raw email content by design, preventing sensitive
    message data from being accidentally emitted to logs.

    Args:
        stage: Pipeline stage that raised the error.
        message: Human-readable operational description.
        source_name: Optional non-sensitive source identifier.
    """

    def __init__(
        self,
        stage: ParsingStage,
        message: str,
        source_name: str | None = None,
    ) -> None:
        self.stage = stage
        self.source_name = source_name
        super().__init__(message)


@runtime_checkable
class EmailLoader(Protocol):
    """Load one declared raw email representation into canonical bytes."""

    def load(self, raw_email: RawEmail) -> LoadedEmail:
        """Load and canonicalize a raw email payload.

        Args:
            raw_email: Declared source content to load.

        Returns:
            Canonical bytes and source metadata.

        Raises:
            ParserError: If source content cannot be safely loaded.
        """


@runtime_checkable
class EmailParser(Protocol):
    """Normalize a loaded email into the application input contract."""

    def parse(self, loaded_email: LoadedEmail) -> EmailInput:
        """Parse loaded content into a normalized email model.

        Args:
            loaded_email: Canonical email payload supplied by an ``EmailLoader``.

        Returns:
            Fully normalized ``EmailInput`` for downstream consumers.

        Raises:
            ParserError: If the parser cannot recover from malformed content.
        """
