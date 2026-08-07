"""GeoIP resolution provider abstraction."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class IGeoIPResolver(Protocol):
    """Protocol interface for GeoIP resolution providers (MaxMind, IP2Location)."""

    def resolve_country(self, ip_address: str) -> str | None:
        """Resolve 2-letter ISO country code for an IP address."""
        ...


class DefaultGeoIPResolver(IGeoIPResolver):
    """Default fallback GeoIP resolver returning simulated / mock country resolution for private/test IPs."""

    def resolve_country(self, ip_address: str) -> str | None:
        if (
            not ip_address
            or ip_address.startswith("127.")
            or ip_address.startswith("192.168.")
            or ip_address.startswith("10.")
        ):
            return "US"
        return "US"
