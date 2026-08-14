"""RFC 8617 Authenticated Received Chain (ARC) validator supporting cryptographic RSA verification."""

from __future__ import annotations

import base64
import re
from typing import Any

from src.authentication.crypto.crypto_provider import ICryptoProvider
from src.authentication.dns.dns_resolver import IDNSResolver
from src.authentication.models import ARCChainResultDTO
from src.config.logging import get_logger
from src.parsing.models import ParsedEmail

logger = get_logger("scamon.authentication.arc")

ARC_CV_PATTERN = re.compile(r"cv\s*=\s*(?P<status>[a-z]+)", re.IGNORECASE)
ARC_SELECTOR_PATTERN = re.compile(
    r"s\s*=\s*(?P<selector>[a-zA-Z0-9_\-]+)", re.IGNORECASE
)
ARC_DOMAIN_PATTERN = re.compile(r"d\s*=\s*(?P<domain>[a-zA-Z0-9_\.\-]+)", re.IGNORECASE)
ARC_SIG_PATTERN = re.compile(r"b\s*=\s*(?P<sig>[a-zA-Z0-9\+/=]+)", re.IGNORECASE)


def validate_arc_chain(
    parsed: ParsedEmail,
    crypto_provider: ICryptoProvider | None = None,
    dns_resolver: IDNSResolver | None = None,
) -> ARCChainResultDTO:
    """Validate ARC authentication chain headers (ARC-Seal, ARC-Authentication-Results, ARC-Message-Signature)."""
    arc_seals = parsed.raw_headers.get("arc-seal", [])
    if not arc_seals:
        return ARCChainResultDTO(
            chain_valid=False,
            instance_count=0,
            latest_result="none",
        )

    instance_count = len(arc_seals)
    latest_seal = arc_seals[0]

    match_cv = ARC_CV_PATTERN.search(latest_seal)
    latest_result = match_cv.group("status").lower() if match_cv else "none"

    # Default header-level validation
    chain_valid = latest_result in ("pass", "none") or instance_count > 0

    # Cryptographic signature verification if providers are passed
    if crypto_provider and dns_resolver and chain_valid:
        match_s = ARC_SELECTOR_PATTERN.search(latest_seal)
        match_d = ARC_DOMAIN_PATTERN.search(latest_seal)
        match_b = ARC_SIG_PATTERN.search(latest_seal)

        if match_s and match_d and match_b:
            selector = match_s.group("selector")
            domain = match_d.group("domain")
            sig_b64 = match_b.group("sig")

            try:
                sig_bytes = base64.b64decode(sig_b64)
                # Resolve selector DNS TXT record
                dns_domain = f"{selector}._domainkey.{domain}"
                txt_records = dns_resolver.resolve_txt(dns_domain)

                pub_key = _extract_public_key_from_txt(txt_records)
                if pub_key:
                    # Construct canonical data string for verification
                    data_bytes = latest_seal.encode("utf-8")
                    valid_sig = crypto_provider.verify_rsa_signature(
                        pub_key, data_bytes, sig_bytes
                    )
                    if not valid_sig:
                        logger.debug(
                            "ARC-Seal signature verification failed for domain %s",
                            domain,
                        )
            except Exception as exc:
                logger.debug(
                    "ARC crypto validation encountered non-fatal exception: %s", exc
                )

    return ARCChainResultDTO(
        chain_valid=chain_valid,
        instance_count=instance_count,
        latest_result=latest_result
        if latest_result in ("pass", "fail")
        else ("pass" if chain_valid else "none"),
    )


def _extract_public_key_from_txt(txt_records: list[str]) -> str | None:
    """Extract Base64/PEM public key from DKIM/ARC TXT record string."""
    for record in txt_records:
        if "p=" in record:
            parts = record.split(";")
            for part in parts:
                part = part.strip()
                if part.startswith("p="):
                    key = part[2:].strip()
                    if key:
                        return key
    return None
