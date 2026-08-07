"""Multi-stage Header & Transmission Analysis Pipeline implementing Module 7 Specification."""

from __future__ import annotations

import time

from src.config.logging import get_logger
from src.parsing.models import ParsedEmail
from src.transmission.hop_analyzer.forgery_detector import detect_header_anomalies
from src.transmission.hop_analyzer.hop_reconstructor import reconstruct_evaluated_hops
from src.transmission.hop_analyzer.relay_classifier import classify_relay_and_provider
from src.transmission.identity.mismatch_analyzer import evaluate_sender_identity
from src.transmission.infrastructure.asn_resolver import (
    DefaultASNResolver,
    IASNResolver,
)
from src.transmission.infrastructure.geoip_resolver import (
    DefaultGeoIPResolver,
    IGeoIPResolver,
)
from src.transmission.models import (
    EvaluatedHopDTO,
    HeaderAnomalyDTO,
    TransmissionAnalysis,
)

logger = get_logger("scamon.transmission.pipeline")


class TransmissionAnalysisPipeline:
    """Orchestrates transport hop evaluation, identity verification, and anomaly detection."""

    def __init__(
        self,
        geoip_resolver: IGeoIPResolver | None = None,
        asn_resolver: IASNResolver | None = None,
    ) -> None:
        self.geoip_resolver = geoip_resolver or DefaultGeoIPResolver()
        self.asn_resolver = asn_resolver or DefaultASNResolver()

    def analyze(self, parsed: ParsedEmail) -> TransmissionAnalysis:
        """Execute complete header & transmission analysis pipeline on ParsedEmail object."""
        start_time = time.perf_counter()

        # Stage 1: Hop Chain & Timeline Reconstruction
        raw_hops = reconstruct_evaluated_hops(parsed.received_hops)
        evaluated_hops: list[EvaluatedHopDTO] = []
        total_latency = 0.0

        for hop in raw_hops:
            classification, cloud_provider = classify_relay_and_provider(hop)
            country_code = None
            asn_num = None
            asn_org = None

            # Enrich with GeoIP & ASN if client IP is present
            if hop.client_ip:
                country_code = self.geoip_resolver.resolve_country(hop.client_ip)
                asn_num, asn_org = self.asn_resolver.resolve_asn(hop.client_ip)

            enriched_hop = EvaluatedHopDTO(
                hop_index=hop.hop_index,
                from_server=hop.from_server,
                by_server=hop.by_server,
                client_ip=hop.client_ip,
                timestamp=hop.timestamp,
                latency_seconds=hop.latency_seconds,
                hop_classification=classification,
                cloud_provider=cloud_provider,
                country_code=country_code,
                asn=asn_num,
                asn_org=asn_org,
            )

            total_latency += enriched_hop.latency_seconds
            evaluated_hops.append(enriched_hop)

        # Originating Client IP (First external hop from end of chain)
        originating_ip = None
        originating_country = None
        originating_asn_org = None

        for hop in reversed(evaluated_hops):
            if hop.hop_classification.startswith("EXTERNAL"):
                originating_ip = hop.client_ip
                originating_country = hop.country_code
                originating_asn_org = hop.asn_org
                break

        # Stage 2: Sender Identity Evaluation
        sender_identity = evaluate_sender_identity(parsed)

        # Stage 3: Header Anomaly & Forgery Detection
        anomalies = detect_header_anomalies(parsed, evaluated_hops)

        # Add identity anomalies
        if sender_identity.is_display_name_spoofed:
            anomalies.append(
                HeaderAnomalyDTO(
                    anomaly_code="ANOM_DISPLAY_NAME_SPOOFING",
                    description=f"Executive display name '{sender_identity.from_display_name}' paired with address '{sender_identity.from_address}'",
                    severity="CRITICAL",
                    risk_score_impact=40,
                )
            )

        if sender_identity.is_reply_to_mismatched:
            anomalies.append(
                HeaderAnomalyDTO(
                    anomaly_code="ANOM_REPLY_TO_MISMATCH",
                    description=f"Reply-To address '{sender_identity.reply_to_address}' does not match From address '{sender_identity.from_address}'",
                    severity="HIGH",
                    risk_score_impact=25,
                )
            )

        if sender_identity.is_reply_to_free_webmail:
            anomalies.append(
                HeaderAnomalyDTO(
                    anomaly_code="ANOM_REPLY_TO_FREE_WEBMAIL",
                    description=f"Reply-To address '{sender_identity.reply_to_address}' is a free webmail account",
                    severity="HIGH",
                    risk_score_impact=30,
                )
            )

        # Stage 4: Calculate Confidence Metrics
        total_risk_impact = sum(a.risk_score_impact for a in anomalies)
        header_integrity = max(0.0, 1.0 - (total_risk_impact / 100.0))
        sender_authenticity = (
            0.3
            if sender_identity.is_display_name_spoofed
            or sender_identity.is_reply_to_mismatched
            else 1.0
        )

        # Additional Header Flags
        is_thread_hijack = any(
            a.anomaly_code == "ANOM_THREAD_HIJACK_SUSPECT" for a in anomalies
        )
        is_list = bool(
            parsed.raw_headers.get("list-id")
            or parsed.raw_headers.get("list-unsubscribe")
        )
        is_auto = bool(parsed.raw_headers.get("auto-submitted"))
        is_bounce = parsed.sender.address == "" or "postmaster" in parsed.sender.address

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return TransmissionAnalysis(
            parsed_id=parsed.parsed_id,
            raw_email_id=parsed.raw_email_id,
            account_id=parsed.account_id,
            tenant_id=parsed.tenant_id,
            message_id=parsed.message_id,
            internet_message_id=parsed.internet_message_id,
            evaluated_hops=evaluated_hops,
            total_transport_latency_seconds=total_latency,
            originating_ip=originating_ip,
            originating_country=originating_country,
            originating_asn_org=originating_asn_org,
            sender_identity=sender_identity,
            is_missing_message_id=not bool(parsed.internet_message_id.strip()),
            is_thread_hijack_suspect=is_thread_hijack,
            is_mailing_list=is_list,
            is_auto_submitted=is_auto,
            is_bounce_notice=is_bounce,
            anomalies=anomalies,
            header_integrity_score=header_integrity,
            sender_authenticity_score=sender_authenticity,
            analysis_time_ms=elapsed_ms,
        )
