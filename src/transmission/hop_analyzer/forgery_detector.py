"""Header forgery, Message-ID mismatch, and transport anomaly detection."""

from __future__ import annotations

from src.parsing.models import ParsedEmail
from src.transmission.models import EvaluatedHopDTO, HeaderAnomalyDTO


def detect_header_anomalies(
    parsed: ParsedEmail, evaluated_hops: list[EvaluatedHopDTO]
) -> list[HeaderAnomalyDTO]:
    """Detect header anomalies, fake received headers, Message-ID mismatches, and thread hijacking."""
    anomalies: list[HeaderAnomalyDTO] = []

    # 1. Missing or Malformed Message-ID
    if not parsed.internet_message_id or not parsed.internet_message_id.strip():
        anomalies.append(
            HeaderAnomalyDTO(
                anomaly_code="ANOM_MISSING_MESSAGE_ID",
                description="RFC 5322 Message-ID header is missing or empty",
                severity="MEDIUM",
                risk_score_impact=15,
            )
        )

    # 2. Message-ID Domain Mismatch
    from_domain = (
        parsed.sender.address.split("@")[-1].lower()
        if "@" in parsed.sender.address
        else ""
    )
    msg_id = parsed.internet_message_id.strip("<> ")
    msg_id_domain = msg_id.split("@")[-1].lower() if "@" in msg_id else ""

    if from_domain and msg_id_domain and from_domain != msg_id_domain:
        anomalies.append(
            HeaderAnomalyDTO(
                anomaly_code="ANOM_MESSAGE_ID_DOMAIN_MISMATCH",
                description=f"Message-ID domain '{msg_id_domain}' does not match From domain '{from_domain}'",
                severity="LOW",
                risk_score_impact=10,
            )
        )

    # 3. Thread Hijacking Suspect (Fake Re: prefix without parent thread reference)
    has_re_prefix = parsed.subject.lower().startswith(
        "re:"
    ) or parsed.subject.lower().startswith("fw:")
    has_parent_refs = bool(
        parsed.raw_headers.get("in-reply-to") or parsed.raw_headers.get("references")
    )
    if has_re_prefix and not has_parent_refs:
        anomalies.append(
            HeaderAnomalyDTO(
                anomaly_code="ANOM_THREAD_HIJACK_SUSPECT",
                description="Subject contains 'Re:' prefix but email lacks In-Reply-To or References headers",
                severity="HIGH",
                risk_score_impact=30,
            )
        )

    # 4. Long Transport Latency Bottlenecks (>60 seconds)
    for hop in evaluated_hops:
        if hop.latency_seconds > 60.0:
            anomalies.append(
                HeaderAnomalyDTO(
                    anomaly_code="ANOM_EXCESSIVE_HOP_LATENCY",
                    description=f"Hop {hop.hop_index} experienced transport delay of {hop.latency_seconds:.1f} seconds",
                    severity="LOW",
                    risk_score_impact=5,
                )
            )

    return anomalies
