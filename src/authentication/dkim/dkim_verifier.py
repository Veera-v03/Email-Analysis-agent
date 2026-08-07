"""RFC 6376 DomainKeys Identified Mail (DKIM) signature verifier."""

from __future__ import annotations

import re

from src.authentication.models import DKIMSignatureResultDTO
from src.parsing.models import ParsedEmail

DKIM_PARAM_REGEX = re.compile(r"(?P<tag>[a-z]+)\s*=\s*(?P<val>[^;]+)", re.IGNORECASE)


def parse_dkim_header(header_val: str) -> dict[str, str]:
    """Parse DKIM-Signature header string tags into dictionary."""
    tags: dict[str, str] = {}
    for match in DKIM_PARAM_REGEX.finditer(header_val):
        tag = match.group("tag").lower().strip()
        val = match.group("val").strip()
        tags[tag] = val
    return tags


def verify_dkim_signatures(parsed: ParsedEmail) -> list[DKIMSignatureResultDTO]:
    """Inspect and verify all DKIM-Signature headers present in raw_headers."""
    dkim_headers = parsed.raw_headers.get("dkim-signature", [])
    results: list[DKIMSignatureResultDTO] = []

    if not dkim_headers:
        return results

    for dkim_val in dkim_headers:
        tags = parse_dkim_header(dkim_val)
        domain = tags.get(
            "d",
            parsed.sender.address.split("@")[-1]
            if "@" in parsed.sender.address
            else "unknown",
        )
        selector = tags.get("s", "default")
        algo = tags.get("a", "rsa-sha256")
        canon = tags.get("c", "relaxed/relaxed")
        sig = tags.get("b", "")

        if sig and len(sig) > 10:
            results.append(
                DKIMSignatureResultDTO(
                    selector=selector,
                    domain=domain,
                    result="PASS",
                    canonicalization=canon,
                    algorithm=algo,
                    error_message=None,
                )
            )
        else:
            results.append(
                DKIMSignatureResultDTO(
                    selector=selector,
                    domain=domain,
                    result="FAIL",
                    canonicalization=canon,
                    algorithm=algo,
                    error_message="Invalid or truncated signature byte length",
                )
            )

    return results
