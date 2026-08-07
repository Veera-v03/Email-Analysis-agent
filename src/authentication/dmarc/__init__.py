"""DMARC evaluation subpackage for ScamON Enterprise."""

from __future__ import annotations

from src.authentication.dmarc.dmarc_evaluator import (
    check_domain_alignment,
    evaluate_dmarc,
)

__all__ = [
    "check_domain_alignment",
    "evaluate_dmarc",
]
