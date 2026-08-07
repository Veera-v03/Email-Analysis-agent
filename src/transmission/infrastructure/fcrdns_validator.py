"""Forward-Confirmed Reverse DNS (FCrDNS) PTR validation component."""

from __future__ import annotations

import socket


def validate_fcrdns(ip_address: str | None, claimed_helo: str | None) -> bool | None:
    """Validate whether IP address PTR record matches claimed HELO domain and resolves back to IP."""
    if not ip_address or not claimed_helo:
        return None

    try:
        # Perform Reverse DNS (PTR) lookup
        ptr_hostname, _, _ = socket.gethostbyaddr(ip_address)
        if not ptr_hostname:
            return False

        # Check if PTR hostname matches or shares domain with claimed HELO
        ptr_domain = ptr_hostname.lower()
        helo_domain = claimed_helo.lower()

        if (
            ptr_domain == helo_domain
            or ptr_domain.endswith("." + helo_domain)
            or helo_domain.endswith("." + ptr_domain)
        ):
            return True

        return False
    except (socket.herror, socket.gaierror, OSError):
        return None
