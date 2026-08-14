"""IOC Graph Builder mapping cross-indicator relationships without duplicating IOC extraction."""

from __future__ import annotations

from typing import Any

from src.authentication.models import AuthenticationVerification
from src.content_intelligence.models import ContentAnalysisResult
from src.parsing.models import ParsedEmail
from src.threat_correlation.models import IOCRelationshipGraphDTO
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.transmission.models import TransmissionAnalysis
from src.url_intelligence.models import URLAnalysisResult


class IOCGraphBuilder:
    """Constructs cross-indicator adjacency graph linking URL -> Domain -> IP -> Sender -> Auth."""

    def build_graph(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis | None = None,
        auth: AuthenticationVerification | None = None,
        intel: ThreatIntelEnrichmentResult | None = None,
        content_res: ContentAnalysisResult | None = None,
        url_res: URLAnalysisResult | None = None,
    ) -> IOCRelationshipGraphDTO:
        """Synthesize upstream normalized indicators into an adjacency list graph."""
        nodes: set[str] = set()
        edges: dict[str, list[str]] = {}

        def add_edge(src: str, dst: str) -> None:
            if not src or not dst or src == dst:
                return
            nodes.add(src)
            nodes.add(dst)
            edges.setdefault(src, [])
            if dst not in edges[src]:
                edges[src].append(dst)

        sender_email = parsed.sender.address.lower()
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

        if sender_email and sender_domain:
            add_edge(sender_email, f"domain:{sender_domain}")

        # Transmission hops & IPs
        if transmission:
            from_dom = transmission.sender_identity.from_domain.lower()
            if from_dom:
                add_edge(sender_email, f"domain:{from_dom}")

        # Auth details
        if auth:
            spf_dom = auth.spf.domain.lower()
            if spf_dom:
                add_edge(f"domain:{sender_domain}", f"spf_domain:{spf_dom}")

        # Extracted URLs
        for url_dto in parsed.urls:
            url_str = url_dto.url.lower()
            url_dom = url_dto.domain.lower()
            add_edge(sender_email, f"url:{url_str}")
            if url_dom:
                add_edge(f"url:{url_str}", f"domain:{url_dom}")

        # QR Extracted URLs from Content Analysis
        if content_res and content_res.media_evidence.qr_extracted_urls:
            for qr_url in content_res.media_evidence.qr_extracted_urls:
                add_edge(sender_email, f"qr_url:{qr_url.lower()}")

        # Expanded Redirect Hops from URL Intelligence
        if url_res and url_res.redirect_chain:
            for hop in url_res.redirect_chain.hops:
                hop_url = hop.canonical_url.lower()
                hop_ip = hop.resolved_ip
                if hop_url:
                    add_edge(sender_email, f"redirect_url:{hop_url}")
                if hop_ip and hop_ip != "0.0.0.0":
                    add_edge(f"redirect_url:{hop_url}", f"ip:{hop_ip}")

        total_edges_count = sum(len(dsts) for dsts in edges.values())

        return IOCRelationshipGraphDTO(
            nodes=sorted(list(nodes)),
            edges=edges,
            total_nodes=len(nodes),
            total_edges=total_edges_count,
        )
