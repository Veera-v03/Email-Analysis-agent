"""Threat Correlation Pipeline coordinating graph building, campaign clustering, MITRE mapping, and memory retrieval."""

from __future__ import annotations

import time
from typing import Any

from src.authentication.models import AuthenticationVerification
from src.config.logging import get_logger
from src.content_intelligence.models import ContentAnalysisResult
from src.memory.services.retrieval_service import MemoryRetrievalService
from src.parsing.models import ParsedEmail
from src.security_intelligence.campaign.campaign_correlation import (
    CampaignCorrelationEngine,
)
from src.security_intelligence.risk.risk_enrichment import RiskEnrichmentService
from src.threat_correlation.graph_builder import IOCGraphBuilder
from src.threat_correlation.models import ThreatCorrelationResult
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.transmission.models import TransmissionAnalysis
from src.url_intelligence.models import URLAnalysisResult

logger = get_logger("scamon.threat_correlation.pipeline")


class ThreatCorrelationPipeline:
    """Orchestrates relationship graph building, campaign clustering, MITRE mapping, and memory retrieval."""

    def __init__(
        self,
        graph_builder: IOCGraphBuilder | None = None,
        campaign_engine: CampaignCorrelationEngine | None = None,
        risk_enrichment: RiskEnrichmentService | None = None,
        memory_retrieval: MemoryRetrievalService | None = None,
    ) -> None:
        self.graph_builder = graph_builder or IOCGraphBuilder()
        self.campaign_engine = campaign_engine or CampaignCorrelationEngine()
        self.risk_enrichment = risk_enrichment or RiskEnrichmentService()
        self.memory_retrieval = memory_retrieval

    def correlate(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis | None = None,
        auth: AuthenticationVerification | None = None,
        intel: ThreatIntelEnrichmentResult | None = None,
        content_res: ContentAnalysisResult | None = None,
        url_res: URLAnalysisResult | None = None,
    ) -> ThreatCorrelationResult:
        """Execute complete threat correlation pipeline on upstream DTOs."""
        start_time = time.perf_counter()

        # 1. Build IOC Relationship Graph
        rel_graph = self.graph_builder.build_graph(
            parsed=parsed,
            transmission=transmission,
            auth=auth,
            intel=intel,
            content_res=content_res,
            url_res=url_res,
        )

        # 2. Campaign Correlation using SQLite (Enforcing Tenant Isolation via org_id)
        extracted_iocs = {
            "urls": [u.url for u in parsed.urls],
            "domains": [u.domain for u in parsed.urls if u.domain],
        }
        campaign_res = self.campaign_engine.correlate_investigation(
            org_id=str(parsed.tenant_id),
            sender=parsed.sender.address,
            subject=parsed.subject,
            extracted_iocs=extracted_iocs,
        )

        # 3. MITRE ATT&CK Technique Mapping using RiskEnrichmentService
        behavioral_results: dict[str, Any] = {"detected_tactics": []}
        if content_res:
            behavioral_results["detected_tactics"] = (
                content_res.intent_analysis.detected_tactics
            )

        enrichment_res = self.risk_enrichment.enrich_risk_profile(
            risk_level="MEDIUM",
            behavioral_results=behavioral_results,
        )

        # 4. Memory Retrieval Search (Enforcing Tenant Isolation)
        historical_matches: list[dict[str, Any]] = campaign_res.get(
            "correlated_investigations", []
        )
        if self.memory_retrieval:
            try:
                mem_results = self.memory_retrieval.find_similar_investigations(
                    subject=parsed.subject,
                    sender=parsed.sender.address,
                    top_k=5,
                )
                for mem in mem_results:
                    historical_matches.append(
                        {
                            "investigation_id": str(mem.record.memory_id),
                            "match_type": "vector_similarity",
                            "score": float(mem.similarity_score),
                        }
                    )
            except Exception as exc:
                logger.debug(
                    "Memory retrieval search encountered non-fatal error: %s", exc
                )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        confidence = 0.85 if campaign_res.get("campaign_detected") else 0.50

        return ThreatCorrelationResult(
            parsed_id=parsed.parsed_id,
            tenant_id=parsed.tenant_id,
            message_id=parsed.message_id,
            related_iocs=rel_graph.nodes,
            relationship_graph=rel_graph,
            campaign_detected=bool(campaign_res.get("campaign_detected", False)),
            campaign_id=f"cmp_{hash(parsed.subject)}"
            if campaign_res.get("campaign_detected")
            else None,
            campaign_score=float(campaign_res.get("campaign_score", 0.0)),
            matched_campaign_indicators=campaign_res.get("indicators_matched", []),
            historical_matches=historical_matches,
            threat_categories=enrichment_res.get("threat_categories", []),
            mitre_techniques=enrichment_res.get("mitre_attack_mapping", []),
            correlation_confidence=confidence,
            evidence_summary=[
                f"Graph nodes: {rel_graph.total_nodes}, edges: {rel_graph.total_edges}",
                f"Campaign score: {campaign_res.get('campaign_score', 0.0)}",
            ],
            execution_time_ms=elapsed_ms,
        )
