"""RFC 5322 Received Header Hop Transport Chain Analyzer."""

from __future__ import annotations

import re
from email.utils import parsedate_to_datetime

from src.parsing.models import ReceivedHopDTO

# Regular expression to extract HELO/from, by, and client IP from Received header strings
FROM_PATTERN = re.compile(r"from\s+([^\s;]+)", re.IGNORECASE)
BY_PATTERN = re.compile(r"by\s+([^\s;]+)", re.IGNORECASE)
IP_PATTERN = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")


def parse_received_hops(received_headers: list[str]) -> list[ReceivedHopDTO]:
    """Parse list of Received header strings into ordered ReceivedHopDTO timeline."""
    hops: list[ReceivedHopDTO] = []
    if not received_headers:
        return hops

    for idx, header in enumerate(received_headers):
        # Extract From server
        from_match = FROM_PATTERN.search(header)
        from_server = from_match.group(1) if from_match else None

        # Extract By server
        by_match = BY_PATTERN.search(header)
        by_server = by_match.group(1) if by_match else None

        # Extract Client IP address
        ip_match = IP_PATTERN.search(header)
        client_ip = ip_match.group(1) if ip_match else None

        # Extract Timestamp if semicolon exists
        hop_dt = None
        if ";" in header:
            date_str = header.split(";")[-1].strip()
            try:
                hop_dt = parsedate_to_datetime(date_str)
            except Exception:
                hop_dt = None

        hops.append(
            ReceivedHopDTO(
                hop_index=idx,
                from_server=from_server,
                by_server=by_server,
                client_ip=client_ip,
                timestamp=hop_dt,
                protocol="ESMTP" if "esmtp" in header.lower() else "SMTP",
            )
        )

    return hops
