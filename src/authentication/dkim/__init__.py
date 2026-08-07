"""DKIM verification subpackage for ScamON Enterprise."""

from __future__ import annotations

from src.authentication.dkim.dkim_verifier import (
    parse_dkim_header,
    verify_dkim_signatures,
)

__all__ = [
    "parse_dkim_header",
    "verify_dkim_signatures",
]
