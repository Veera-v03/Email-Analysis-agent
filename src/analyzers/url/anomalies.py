"""Deterministic structural anomaly detection for Phase 4 URL intelligence.

This module does not make any security decision. It only returns structured
observations for suspicious structural characteristics of a URL.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from src.models.url import (
    ParsedUrlComponents,
    SuspiciousPatternCategory,
    SuspiciousPatternMatch,
)


class StructuralUrlAnomalyAnalyzer:
    """Detect deterministic structural URL anomalies.

    The analyzer inspects parsed URL components and emits structured
    ``SuspiciousPatternMatch`` observations for known anomaly patterns.
    No phishing decision, score, or verdict is produced.
    """

    def __init__(self, suspicious_keywords: Iterable[str] | None = None) -> None:
        self._suspicious_keywords = tuple(
            keyword.lower() for keyword in (suspicious_keywords or ())
        )

    def analyze(
        self, components: ParsedUrlComponents
    ) -> tuple[SuspiciousPatternMatch, ...]:
        """Return structural anomaly indicators for the supplied URL components."""
        if not components.is_parseable:
            return ()

        matches: list[SuspiciousPatternMatch] = []
        host = components.host or ""
        path = components.path or ""
        query = components.query or ""
        full_url = f"{components.scheme or ''}{host}{path}{query}".lower()

        if self._is_ip_address_host(host):
            matches.append(
                SuspiciousPatternMatch(
                    category=SuspiciousPatternCategory.IP_ADDRESS_HOST,
                    detail="host uses an IP address instead of a domain name",
                )
            )

        if components.username or components.password:
            matches.append(
                SuspiciousPatternMatch(
                    category=SuspiciousPatternCategory.CREDENTIAL_IN_URL,
                    detail="URL embeds credentials in the authority component",
                )
            )

        if self._is_long_hostname(host):
            matches.append(
                SuspiciousPatternMatch(
                    category=SuspiciousPatternCategory.EXCESSIVE_SUBDOMAINS,
                    detail="hostname is unusually long",
                )
            )

        if self._subdomain_count(components.subdomain) > 3:
            matches.append(
                SuspiciousPatternMatch(
                    category=SuspiciousPatternCategory.EXCESSIVE_SUBDOMAINS,
                    detail="hostname contains excessive subdomains",
                )
            )

        if len(full_url) > 120:
            matches.append(
                SuspiciousPatternMatch(
                    category=SuspiciousPatternCategory.LONG_PATH,
                    detail="URL length exceeds the common threshold",
                )
            )

        if self._contains_suspicious_keywords(full_url):
            matches.append(
                SuspiciousPatternMatch(
                    category=SuspiciousPatternCategory.ENCODED_PAYLOAD,
                    detail="URL contains suspicious keywords",
                )
            )

        if self._has_encoded_characters(path + query):
            matches.append(
                SuspiciousPatternMatch(
                    category=SuspiciousPatternCategory.ENCODED_PAYLOAD,
                    detail="URL contains encoded characters",
                )
            )

        if self._has_unusual_port(components):
            matches.append(
                SuspiciousPatternMatch(
                    category=SuspiciousPatternCategory.NON_STANDARD_PORT,
                    detail="URL uses a non-standard port",
                )
            )

        if self._has_repeated_separators(path + query):
            matches.append(
                SuspiciousPatternMatch(
                    category=SuspiciousPatternCategory.ENCODED_PAYLOAD,
                    detail="URL contains repeated separators",
                )
            )

        return tuple(matches)

    @staticmethod
    def _is_ip_address_host(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True

    @staticmethod
    def _is_long_hostname(host: str) -> bool:
        return len(host) > 63

    @staticmethod
    def _subdomain_count(subdomain: str | None) -> int:
        if not subdomain:
            return 0
        return len([segment for segment in subdomain.split(".") if segment])

    def _contains_suspicious_keywords(self, text: str) -> bool:
        lowered = text.lower()
        return any(keyword in lowered for keyword in self._suspicious_keywords)

    @staticmethod
    def _has_encoded_characters(text: str) -> bool:
        return bool(re.search(r"%(?:[0-9a-f]{2})", text, re.IGNORECASE))

    @staticmethod
    def _has_unusual_port(components: ParsedUrlComponents) -> bool:
        if components.port is None:
            return False
        default_ports = {"http": 80, "https": 443, "ftp": 21}
        scheme = (components.scheme or "").lower()
        return components.port != default_ports.get(scheme)

    @staticmethod
    def _has_repeated_separators(text: str) -> bool:
        return bool(re.search(r"(?:--|//|\\\\)", text))
