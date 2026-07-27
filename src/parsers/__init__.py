"""Email parsing contracts and implementations.

This package owns conversion of raw email representations into the normalized
application model. It contains no security-analysis behaviour.
"""

from src.parsers.contracts import (
    EmailLoader,
    EmailParser,
    EmailSourceKind,
    LoadedEmail,
    ParserError,
    ParsingStage,
    RawEmail,
)

__all__ = [
    "EmailLoader",
    "EmailParser",
    "EmailSourceKind",
    "LoadedEmail",
    "ParserError",
    "ParsingStage",
    "RawEmail",
]
