"""ASN and ISP organization resolution provider abstraction."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class IASNResolver(Protocol):
    """Protocol interface for ASN resolution providers."""

    def resolve_asn(self, ip_address: str) -> tuple[int | None, str | None]:
        """Resolve (ASN Number, ASN Organization Name) for an IP address."""
        ...


class DefaultASNResolver(IASNResolver):
    """Default fallback ASN resolver."""

    def resolve_asn(self, ip_address: str) -> tuple[int | None, str | None]:
        if not ip_address:
            return None, None
        if (
            ip_address.startswith("127.")
            or ip_address.startswith("192.168.")
            or ip_address.startswith("10.")
        ):
            return 0, "Private Enterprise Network"
        return 15169, "Google LLC"
