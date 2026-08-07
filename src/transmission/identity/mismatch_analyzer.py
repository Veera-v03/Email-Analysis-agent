"""Sender identity mismatch analysis (Reply-To, Return-Path, Envelope From)."""

from __future__ import annotations

from src.parsing.models import ParsedEmail
from src.transmission.identity.spoofing_detector import (
    FREE_WEBMAIL_DOMAINS,
    detect_display_name_spoofing,
)
from src.transmission.models import SenderIdentityAnalysisDTO


def evaluate_sender_identity(parsed: ParsedEmail) -> SenderIdentityAnalysisDTO:
    """Evaluate From, Sender, Reply-To, Return-Path, and Envelope From alignment."""
    from_addr = parsed.sender.address.strip().lower()
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    from_display_name = parsed.sender.name.strip()

    sender_addr = parsed.sender.address if parsed.sender else None
    reply_to_addr = parsed.reply_to.address if parsed.reply_to else None

    # Extract Return-Path and Envelope-From from raw headers if available
    return_path_list = parsed.raw_headers.get("return-path", [])
    return_path_addr = return_path_list[0].strip("<> ") if return_path_list else None

    env_from_list = parsed.raw_headers.get("envelope-from", [])
    envelope_from_addr = (
        env_from_list[0].strip("<> ") if env_from_list else return_path_addr
    )

    # 1. Executive Display Name Spoofing Check
    is_display_name_spoofed = detect_display_name_spoofing(from_display_name, from_addr)

    # 2. Reply-To Mismatch Check
    is_reply_to_mismatched = False
    is_reply_to_free_webmail = False

    if reply_to_addr:
        reply_to_clean = reply_to_addr.strip().lower()
        if reply_to_clean != from_addr:
            is_reply_to_mismatched = True

        reply_domain = reply_to_clean.split("@")[-1] if "@" in reply_to_clean else ""
        if (
            reply_domain in FREE_WEBMAIL_DOMAINS
            and from_domain not in FREE_WEBMAIL_DOMAINS
        ):
            is_reply_to_free_webmail = True

    # 3. Return-Path Mismatch Check
    is_return_path_mismatched = False
    if return_path_addr:
        rp_clean = return_path_addr.strip().lower()
        if rp_clean and rp_clean != from_addr:
            is_return_path_mismatched = True

    # 4. Envelope From Mismatch Check
    is_envelope_from_mismatched = False
    if envelope_from_addr:
        env_clean = envelope_from_addr.strip().lower()
        if env_clean and env_clean != from_addr:
            is_envelope_from_mismatched = True

    return SenderIdentityAnalysisDTO(
        from_address=from_addr,
        from_domain=from_domain,
        from_display_name=from_display_name,
        sender_address=sender_addr,
        reply_to_address=reply_to_addr,
        return_path_address=return_path_addr,
        envelope_from_address=envelope_from_addr,
        is_display_name_spoofed=is_display_name_spoofed,
        is_reply_to_mismatched=is_reply_to_mismatched,
        is_reply_to_free_webmail=is_reply_to_free_webmail,
        is_return_path_mismatched=is_return_path_mismatched,
        is_envelope_from_mismatched=is_envelope_from_mismatched,
    )
