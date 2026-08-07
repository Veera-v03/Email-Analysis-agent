"""Sender identity evaluation subpackage for ScamON Enterprise."""

from __future__ import annotations

from src.transmission.identity.mismatch_analyzer import evaluate_sender_identity
from src.transmission.identity.spoofing_detector import (
    FREE_WEBMAIL_DOMAINS,
    detect_display_name_spoofing,
)

__all__ = [
    "FREE_WEBMAIL_DOMAINS",
    "detect_display_name_spoofing",
    "evaluate_sender_identity",
]
