"""URL Intelligence Pipeline coordinating canonicalization, SSRF checks, redirect expansion, threat feeds, and sandboxing."""

from __future__ import annotations

import time

from src.config.logging import get_logger
from src.content_intelligence.models import ContentAnalysisResult, MediaStatus
from src.parsing.models import ParsedEmail
from src.security_intelligence.threat_intel.framework import ThreatIntelTargetType
from src.threat_intel.manager import ThreatIntelManager
from src.url_intelligence.models import (
    URLAnalysisResult,
    URLRedirectChainDTO,
    URLSandboxResultDTO,
)
from src.url_intelligence.redirect_expander import RedirectExpander
from src.url_intelligence.sandbox_engine import PlaywrightSandboxEngine
from src.url_intelligence.ssrf_validator import SSRFValidator

logger = get_logger("scamon.url_intelligence.pipeline")


class URLIntelligencePipeline:
    """Orchestrates URL normalization, SSRF checks, redirect expansion, threat feeds, and browser sandboxing."""

    def __init__(
        self,
        ssrf_validator: SSRFValidator | None = None,
        redirect_expander: RedirectExpander | None = None,
        sandbox_engine: PlaywrightSandboxEngine | None = None,
        intel_manager: ThreatIntelManager | None = None,
    ) -> None:
        self.ssrf_validator = ssrf_validator or SSRFValidator()
        self.redirect_expander = redirect_expander or RedirectExpander(
            ssrf_validator=self.ssrf_validator
        )
        self.sandbox_engine = sandbox_engine or PlaywrightSandboxEngine(
            ssrf_validator=self.ssrf_validator
        )
        self.intel_manager = intel_manager or ThreatIntelManager()

    def analyze_urls(
        self,
        parsed: ParsedEmail,
        content_res: ContentAnalysisResult | None = None,
    ) -> URLAnalysisResult:
        """Execute complete URL intelligence pipeline on email URLs and extracted QR code URLs."""
        start_time = time.perf_counter()

        # Combine URLs from email body and extracted QR code evidence
        target_urls: list[str] = [u.url for u in parsed.urls]
        if content_res and content_res.media_evidence.qr_extracted_urls:
            target_urls.extend(content_res.media_evidence.qr_extracted_urls)

        target_urls = sorted(list(set(target_urls)))

        has_mismatched = any(u.is_mismatched for u in parsed.urls)
        has_shortened = any(u.is_shortened for u in parsed.urls)
        ssrf_violation = False

        flagged_feeds: list[str] = []
        redirect_chain = URLRedirectChainDTO(
            initial_url=target_urls[0] if target_urls else "",
            final_destination_url=target_urls[0] if target_urls else "",
        )
        sandbox_res = URLSandboxResultDTO(sandbox_status=MediaStatus.SKIPPED)

        if target_urls:
            primary_url = target_urls[0]

            # 1. Threat Intel Feed Lookups (GSB, PhishTank, OpenPhish, VirusTotal)
            obs_list = self.intel_manager.lookup_indicator(
                primary_url, ThreatIntelTargetType.URL
            )
            for obs in obs_list:
                if obs.malicious:
                    flagged_feeds.append(obs.provider_name)

            # 2. Redirect Expansion with per-hop SSRF validation
            redirect_chain = self.redirect_expander.expand_url(primary_url)
            for hop in redirect_chain.hops:
                if not hop.is_ssrf_safe:
                    ssrf_violation = True
                    break

            # 3. Justified Sandbox Execution
            sandbox_res = self.sandbox_engine.run_sandbox(
                redirect_chain.final_destination_url,
                is_shortened=has_shortened,
                is_mismatched=has_mismatched,
                is_redirected=redirect_chain.total_hops > 1,
            )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return URLAnalysisResult(
            parsed_id=parsed.parsed_id,
            tenant_id=parsed.tenant_id,
            message_id=parsed.message_id,
            extracted_urls_count=len(target_urls),
            has_mismatched_urls=has_mismatched,
            has_shortened_urls=has_shortened,
            ssrf_violation_detected=ssrf_violation,
            redirect_chain=redirect_chain,
            sandbox_result=sandbox_res,
            threat_feeds_flagged=sorted(list(set(flagged_feeds))),
            execution_time_ms=elapsed_ms,
        )
