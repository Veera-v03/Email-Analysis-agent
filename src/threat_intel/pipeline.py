"""Multi-stage Threat Intelligence & IOC Enrichment Pipeline matching Module 9 Specification."""

from __future__ import annotations

import time

from src.authentication.models import AuthenticationVerification
from src.config.logging import get_logger
from src.parsing.models import ParsedEmail
from src.security_intelligence.threat_intel.framework import ThreatIntelTargetType
from src.threat_intel.graph import IOCRelationshipGraph
from src.threat_intel.harvester import IOCHarvester
from src.threat_intel.manager import ThreatIntelManager
from src.threat_intel.models import (
    ConfidenceScoreDTO,
    IOCTargetDetailDTO,
    ThreatCategory,
    ThreatIntelEnrichmentResult,
)
from src.transmission.models import TransmissionAnalysis

logger = get_logger("scamon.threat_intel.pipeline")


class ThreatIntelPipeline:
    """Orchestrates IOC harvesting, relationship graph building, manager lookups, and scoring."""

    def __init__(
        self,
        harvester: IOCHarvester | None = None,
        manager: ThreatIntelManager | None = None,
    ) -> None:
        self.harvester = harvester or IOCHarvester()
        self.manager = manager or ThreatIntelManager()

    def enrich(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis,
        auth: AuthenticationVerification,
    ) -> ThreatIntelEnrichmentResult:
        """Execute complete Threat Intelligence enrichment pipeline."""
        start_time = time.perf_counter()

        # Stage 1: Harvest IOCs
        harvested = self.harvester.harvest(parsed, transmission, auth)

        # Stage 2: Build IOC Relationship Graph
        graph = IOCRelationshipGraph()
        email_node = graph.add_node("email_message", parsed.message_id)

        for ip in harvested.get("ips", []):
            node = graph.add_node("ip", ip)
            graph.add_edge(
                email_node,
                node,
                "ORIGINATED_FROM"
                if ip == transmission.originating_ip
                else "TRAVERSED_HOP",
            )

        for dom in harvested.get("domains", []):
            node = graph.add_node("domain", dom)
            graph.add_edge(
                email_node,
                node,
                "SENDER_DOMAIN"
                if dom == transmission.sender_identity.from_domain
                else "REFERENCED_DOMAIN",
            )

        for url in harvested.get("urls", []):
            node = graph.add_node("url", url)
            graph.add_edge(email_node, node, "CONTAINS_URL")

        for h in harvested.get("hashes", []):
            node = graph.add_node("hash", h)
            graph.add_edge(email_node, node, "ATTACHMENT_HASH")

        # Stage 3: Perform Provider Lookups via ThreatIntelManager
        enriched_targets: list[IOCTargetDetailDTO] = []
        matched_feeds_set: set[str] = set()
        categories_set: set[str] = set()
        malicious_count = 0
        total_evidence: list[str] = []

        type_mapping = [
            ("ips", ThreatIntelTargetType.IP),
            ("domains", ThreatIntelTargetType.DOMAIN),
            ("urls", ThreatIntelTargetType.URL),
            ("hashes", ThreatIntelTargetType.HASH),
            ("emails", ThreatIntelTargetType.EMAIL),
        ]

        for key, target_type in type_mapping:
            for target_val in harvested.get(key, []):
                obs_list = self.manager.lookup_indicator(target_val, target_type)
                flagged_obs = [o for o in obs_list if o.malicious]

                is_mal = len(flagged_obs) > 0
                max_conf = max(
                    (o.confidence for o in obs_list if o.confidence is not None),
                    default=0.0,
                )
                feeds = sorted(list(set(o.provider_name for o in flagged_obs)))

                cat = "UNKNOWN"
                if flagged_obs:
                    cat_val = flagged_obs[0].threat_category.upper()
                    if cat_val in ThreatCategory.__members__:
                        cat = cat_val
                    else:
                        cat = ThreatCategory.SUSPICIOUS_INFRASTRUCTURE.value

                evidence_lines = [
                    f"[{o.provider_name}] Flagged {target_type.value} '{target_val}' as {o.threat_category}"
                    for o in flagged_obs
                ]

                if is_mal:
                    malicious_count += 1
                    matched_feeds_set.update(feeds)
                    categories_set.add(cat)
                    total_evidence.extend(evidence_lines)

                confidence_model = ConfidenceScoreDTO(
                    confidence=max_conf if is_mal else 0.0,
                    provider_count=len(obs_list),
                    evidence=evidence_lines,
                    explanation=(
                        f"Indicator '{target_val}' flagged malicious by {len(feeds)} providers ({', '.join(feeds)})"
                        if is_mal
                        else f"Indicator '{target_val}' clean across provider checks"
                    ),
                )

                enriched_targets.append(
                    IOCTargetDetailDTO(
                        target=target_val,
                        target_type=target_type.value,
                        is_malicious=is_mal,
                        confidence=confidence_model,
                        matched_feeds=feeds,
                        threat_category=cat,
                        observations=obs_list,
                    )
                )

        # Stage 4: Consolidated Confidence & Risk Impact Calculation
        overall_conf_val = max(
            (t.confidence.confidence for t in enriched_targets if t.is_malicious),
            default=0.0,
        )
        overall_confidence = ConfidenceScoreDTO(
            confidence=overall_conf_val,
            provider_count=len(self.manager.registry.get_all_providers()),
            evidence=total_evidence,
            explanation=(
                f"Detected {malicious_count} malicious IOCs across {len(matched_feeds_set)} threat feeds"
                if malicious_count > 0
                else "Zero malicious IOCs detected across threat intelligence feeds"
            ),
        )

        # Additive risk score impact (0 to 50 points)
        risk_impact = min(50, malicious_count * 20)

        total_harvested = sum(len(v) for v in harvested.values())
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ThreatIntelEnrichmentResult(
            parsed_id=parsed.parsed_id,
            transmission_id=transmission.analysis_id,
            auth_verification_id=auth.verification_id,
            account_id=parsed.account_id,
            tenant_id=parsed.tenant_id,
            message_id=parsed.message_id,
            total_iocs_harvested=total_harvested,
            harvested_iocs=harvested,
            graph_node_count=len(graph.nodes),
            graph_edge_count=len(graph.edges),
            enriched_targets=enriched_targets,
            malicious_ioc_count=malicious_count,
            overall_confidence=overall_confidence,
            matched_feeds=sorted(list(matched_feeds_set)),
            threat_categories=sorted(list(categories_set)),
            intel_risk_score_impact=risk_impact,
            enrichment_time_ms=elapsed_ms,
        )
