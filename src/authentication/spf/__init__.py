"""SPF evaluation subpackage for ScamON Enterprise."""

from __future__ import annotations

from src.authentication.spf.spf_evaluator import (
    MAX_SPF_DNS_LOOKUPS,
    SPF_QUALIFIER_MAP,
    evaluate_spf_record,
)

__all__ = [
    "MAX_SPF_DNS_LOOKUPS",
    "SPF_QUALIFIER_MAP",
    "evaluate_spf_record",
]
