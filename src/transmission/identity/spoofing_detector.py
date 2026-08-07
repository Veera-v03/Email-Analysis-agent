"""Executive & Brand Display Name Impersonation (CEO Fraud / BEC) detector."""

from __future__ import annotations

import re

# Common executive titles and brand impersonation target terms
EXECUTIVE_TITLE_REGEX = re.compile(
    r"\b(CEO|CFO|COO|CTO|CIO|President|Vice President|Executive|Director|Manager|Payroll|HR|Finance)\b",
    re.IGNORECASE,
)

FREE_WEBMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "icloud.com",
    "protonmail.com",
    "zoho.com",
}


def detect_display_name_spoofing(display_name: str, from_address: str) -> bool:
    """Detect executive title or brand impersonation in display name paired with external/free webmail email address."""
    if not display_name or not from_address:
        return False

    name_clean = display_name.strip()
    addr_clean = from_address.strip().lower()
    domain = addr_clean.split("@")[-1] if "@" in addr_clean else ""

    # 1. Executive title in display name paired with free webmail address
    if EXECUTIVE_TITLE_REGEX.search(name_clean) and domain in FREE_WEBMAIL_DOMAINS:
        return True

    # 2. Display Name contains an email address that does not match From address
    email_in_name = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", name_clean)
    if email_in_name:
        embedded_addr = email_in_name.group(0).lower()
        if embedded_addr != addr_clean:
            return True

    return False
