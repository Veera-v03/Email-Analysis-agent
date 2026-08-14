"""Multi-stage Email Authentication & Verification Pipeline implementing Module 8 Specification."""

from __future__ import annotations

import time

from src.authentication.arc.arc_validator import validate_arc_chain
from src.authentication.crypto.crypto_provider import ICryptoProvider, RSACryptoProvider
from src.authentication.dkim.dkim_verifier import verify_dkim_signatures
from src.authentication.dmarc.dmarc_evaluator import evaluate_dmarc
from src.authentication.dns.dns_resolver import CachedDNSResolver, IDNSResolver
from src.authentication.dns.org_domain_resolver import (
    IOrgDomainResolver,
    PublicSuffixOrgDomainResolver,
)
from src.authentication.models import AuthenticationVerification
from src.authentication.spf.spf_evaluator import evaluate_spf_record
from src.config.logging import get_logger
from src.parsing.models import ParsedEmail
from src.transmission.models import TransmissionAnalysis

logger = get_logger("scamon.authentication.pipeline")


class AuthenticationPipeline:
    """Orchestrates SPF, DKIM, DMARC, and ARC verification pipeline execution."""

    def __init__(
        self,
        dns_resolver: IDNSResolver | None = None,
        org_resolver: IOrgDomainResolver | None = None,
        crypto_provider: ICryptoProvider | None = None,
    ) -> None:
        self.dns_resolver = dns_resolver or CachedDNSResolver()
        self.org_resolver = org_resolver or PublicSuffixOrgDomainResolver()
        self.crypto_provider = crypto_provider or RSACryptoProvider()

    def verify(
        self, parsed: ParsedEmail, transmission: TransmissionAnalysis
    ) -> AuthenticationVerification:
        """Execute complete authentication verification pipeline."""
        start_time = time.perf_counter()

        from_domain = transmission.sender_identity.from_domain
        originating_ip = transmission.originating_ip

        # Stage 1: SPF Evaluation
        raw_spf_list = parsed.raw_headers.get("received-spf", [])
        raw_spf = raw_spf_list[0] if raw_spf_list else None
        spf_res = evaluate_spf_record(from_domain, originating_ip, raw_spf)

        # Stage 2: DKIM Verification
        dkim_sigs = verify_dkim_signatures(parsed)
        if any(d.result == "PASS" for d in dkim_sigs):
            dkim_overall = "PASS"
        elif any(d.result == "FAIL" for d in dkim_sigs):
            dkim_overall = "FAIL"
        else:
            dkim_overall = "NONE"

        # Stage 3: DMARC Policy & Alignment Evaluation
        raw_dmarc_list = parsed.raw_headers.get("dmarc-filter", [])
        raw_dmarc = raw_dmarc_list[0] if raw_dmarc_list else None
        dmarc_res = evaluate_dmarc(
            from_domain,
            spf_res,
            dkim_sigs,
            raw_dmarc,
            org_resolver=self.org_resolver,
        )

        # Stage 4: ARC Chain Validation
        arc_res = validate_arc_chain(
            parsed,
            crypto_provider=self.crypto_provider,
            dns_resolver=self.dns_resolver,
        )

        # Calculate Aggregated Security Metrics
        auth_pass = (dmarc_res.result == "PASS") or (
            spf_res.result == "PASS" and dkim_overall == "PASS"
        )

        # Risk score impact calculation (0 to 50 additive points)
        auth_risk_impact = 0
        if dmarc_res.result == "FAIL":
            auth_risk_impact += 30
        if spf_res.result in ("FAIL", "SOFTFAIL"):
            auth_risk_impact += 10
        if dkim_overall == "FAIL":
            auth_risk_impact += 10

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return AuthenticationVerification(
            parsed_id=parsed.parsed_id,
            transmission_id=transmission.analysis_id,
            account_id=parsed.account_id,
            tenant_id=parsed.tenant_id,
            message_id=parsed.message_id,
            internet_message_id=parsed.internet_message_id,
            spf=spf_res,
            dkim_signatures=dkim_sigs,
            dkim_overall_result=dkim_overall,
            dmarc=dmarc_res,
            arc=arc_res,
            auth_pass_summary=auth_pass,
            auth_risk_score_impact=min(50, auth_risk_impact),
            verification_time_ms=elapsed_ms,
        )
