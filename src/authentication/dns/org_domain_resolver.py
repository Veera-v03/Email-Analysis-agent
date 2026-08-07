"""Organizational Domain Resolver using Public Suffix List (tldextract) for DMARC alignment."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import tldextract


@runtime_checkable
class IOrgDomainResolver(Protocol):
    """Protocol interface for organizational domain extraction."""

    def get_organizational_domain(self, domain: str) -> str:
        """Extract organizational domain under Public Suffix List (e.g. sub.mail.example.co.uk -> example.co.uk)."""
        ...


class PublicSuffixOrgDomainResolver(IOrgDomainResolver):
    """Production-grade Organizational Domain Resolver utilizing Public Suffix List via tldextract."""

    def get_organizational_domain(self, domain: str) -> str:
        if not domain or not domain.strip():
            return ""

        domain_clean = domain.strip().lower()
        extracted = tldextract.extract(domain_clean)
        # Use top_domain_under_public_suffix (falling back to domain itself if unavailable)
        org_domain = extracted.top_domain_under_public_suffix or domain_clean
        return org_domain
