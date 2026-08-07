"""RFC 8617 Authenticated Received Chain (ARC) validator."""

from __future__ import annotations

import re

from src.authentication.models import ARCChainResultDTO
from src.parsing.models import ParsedEmail

ARC_CV_PATTERN = re.compile(r"cv\s*=\s*(?P<status>[a-z]+)", re.IGNORECASE)


def validate_arc_chain(parsed: ParsedEmail) -> ARCChainResultDTO:
    """Validate ARC authentication chain headers (ARC-Seal, ARC-Authentication-Results)."""
    arc_seals = parsed.raw_headers.get("arc-seal", [])
    if not arc_seals:
        return ARCChainResultDTO(
            chain_valid=False,
            instance_count=0,
            latest_result="none",
        )

    instance_count = len(arc_seals)
    latest_seal = arc_seals[0]

    match = ARC_CV_PATTERN.search(latest_seal)
    latest_result = match.group("status").lower() if match else "none"
    chain_valid = latest_result == "pass"

    return ARCChainResultDTO(
        chain_valid=chain_valid,
        instance_count=instance_count,
        latest_result=latest_result,
    )
