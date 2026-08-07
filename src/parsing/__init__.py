"""MIME Parsing & Decomposition Package for ScamON Enterprise."""

from __future__ import annotations

from src.parsing.engine import MimeParserEngine
from src.parsing.exceptions import (
    AttachmentExtractionError,
    MalformedMimeError,
    ParsingError,
)
from src.parsing.models import (
    ExtractedAttachmentDTO,
    ExtractedURLDTO,
    HeaderAddressDTO,
    ParsedEmail,
    ParsingDiagnosticDTO,
    ReceivedHopDTO,
)
from src.parsing.module import ParsingModule, register_parsing_module
from src.parsing.pipeline import ParsingPipeline

__all__ = [
    "AttachmentExtractionError",
    "ExtractedAttachmentDTO",
    "ExtractedURLDTO",
    "HeaderAddressDTO",
    "MalformedMimeError",
    "MimeParserEngine",
    "ParsedEmail",
    "ParsingDiagnosticDTO",
    "ParsingError",
    "ParsingModule",
    "ParsingPipeline",
    "ReceivedHopDTO",
    "register_parsing_module",
]
