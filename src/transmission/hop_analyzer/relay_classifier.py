"""SMTP Relay classification (INTERNAL, EXTERNAL_TRUSTED, EXTERNAL_UNTRUSTED) and Cloud Provider detection."""

from __future__ import annotations

import ipaddress

from src.transmission.models import EvaluatedHopDTO

TRUSTED_CLOUD_DOMAINS = {
    "google.com": "GSuite",
    "googlemail.com": "GSuite",
    "outlook.com": "M365",
    "microsoft.com": "M365",
    "amazonses.com": "AWS_SES",
    "sendgrid.net": "SendGrid",
    "mailchimp.com": "Mailchimp",
}

INTERNAL_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_private_ip(ip_str: str | None) -> bool:
    """Check if IP address string belongs to RFC 1918 private IP ranges."""
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in INTERNAL_PRIVATE_NETWORKS)
    except ValueError:
        return False


def classify_relay_and_provider(hop: EvaluatedHopDTO) -> tuple[str, str | None]:
    """Classify relay as INTERNAL, EXTERNAL_TRUSTED, or EXTERNAL_UNTRUSTED and return identified cloud provider."""
    if is_private_ip(hop.client_ip):
        return "INTERNAL", None

    server_str = f"{hop.from_server or ''} {hop.by_server or ''}".lower()
    for domain, provider_name in TRUSTED_CLOUD_DOMAINS.items():
        if domain in server_str:
            return "EXTERNAL_TRUSTED", provider_name

    return "EXTERNAL_UNTRUSTED", None
