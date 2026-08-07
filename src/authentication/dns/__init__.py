"""DNS resolution subpackage for ScamON Enterprise."""

from __future__ import annotations

from src.authentication.dns.dns_resolver import (
    CachedDNSResolver,
    DNSCacheEntry,
    IDNSResolver,
)
from src.authentication.dns.org_domain_resolver import (
    IOrgDomainResolver,
    PublicSuffixOrgDomainResolver,
)

__all__ = [
    "CachedDNSResolver",
    "DNSCacheEntry",
    "IDNSResolver",
    "IOrgDomainResolver",
    "PublicSuffixOrgDomainResolver",
]
