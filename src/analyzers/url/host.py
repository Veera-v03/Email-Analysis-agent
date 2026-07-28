"""Deterministic host analysis for Phase 4 URL intelligence."""

from __future__ import annotations

import ipaddress

from src.models.url import ParsedUrlComponents, UrlHostAnalysis, UrlHostType


class DeterministicUrlHostAnalyzer:
    """Analyze the host component of parsed URL components."""

    def analyze(self, components: ParsedUrlComponents) -> UrlHostAnalysis:
        host = components.host or ""
        if not host:
            return UrlHostAnalysis(host_type=UrlHostType.EMPTY)

        try:
            ip = ipaddress.ip_address(host)
            host_type = UrlHostType.IP_V4 if ip.version == 4 else UrlHostType.IP_V6
        except ValueError:
            host_type = UrlHostType.DOMAIN

        normalized_host = host.lower()
        labels = [label for label in normalized_host.split(".") if label]
        registered_domain = labels[-1] if labels else None
        subdomain = ".".join(labels[:-2]) if len(labels) > 2 else None
        tld = labels[-1] if labels else None

        return UrlHostAnalysis(
            raw_host=host,
            host_type=host_type,
            normalized_host=normalized_host,
            registered_domain=registered_domain,
            effective_tld=tld,
            subdomain=subdomain,
            subdomain_depth=max(0, len(labels) - 2),
            is_ip_address=host_type in {UrlHostType.IP_V4, UrlHostType.IP_V6},
            is_localhost=normalized_host == "localhost",
            is_punycode="xn--" in normalized_host,
            is_idn=any(ord(ch) > 127 for ch in host),
        )
