"""Transport timeline reconstruction and hop latency calculation."""

from __future__ import annotations

from src.parsing.models import ReceivedHopDTO
from src.transmission.models import EvaluatedHopDTO


def reconstruct_evaluated_hops(raw_hops: list[ReceivedHopDTO]) -> list[EvaluatedHopDTO]:
    """Sort and enrich received hops, calculating per-hop transport latency deltas."""
    if not raw_hops:
        return []

    # Reverse to process chronologically from origin to edge receiver
    chronological_hops = list(reversed(raw_hops))

    evaluated_chrono: list[tuple[ReceivedHopDTO, float]] = []
    prev_timestamp = None

    for hop in chronological_hops:
        latency_sec = 0.0
        if hop.timestamp and prev_timestamp:
            delta = (hop.timestamp - prev_timestamp).total_seconds()
            latency_sec = max(0.0, delta)

        if hop.timestamp:
            prev_timestamp = hop.timestamp

        evaluated_chrono.append((hop, latency_sec))

    # Reverse back so index 0 = Edge receiver
    evaluated_chrono.reverse()

    results: list[EvaluatedHopDTO] = []
    for idx, (hop, latency_sec) in enumerate(evaluated_chrono):
        results.append(
            EvaluatedHopDTO(
                hop_index=idx,
                from_server=hop.from_server,
                by_server=hop.by_server,
                client_ip=hop.client_ip,
                timestamp=hop.timestamp,
                latency_seconds=latency_sec,
            )
        )

    return results
