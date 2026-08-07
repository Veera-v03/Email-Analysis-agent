"""IOC Harvester aggregating indicators across ParsedEmail, TransmissionAnalysis, and AuthenticationVerification."""

from __future__ import annotations

from src.authentication.models import AuthenticationVerification
from src.parsing.models import ParsedEmail
from src.security_intelligence.ioc.ioc_extractor import IOCExtractor
from src.transmission.models import TransmissionAnalysis


class IOCHarvester:
    """Harvests and deduplicates all Indicators of Compromise from email analysis outputs."""

    def __init__(self, extractor: IOCExtractor | None = None) -> None:
        self.extractor = extractor or IOCExtractor()

    def harvest(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis,
        auth: AuthenticationVerification,
    ) -> dict[str, list[str]]:
        """Harvest IPs, Domains, URLs, Hashes, and Emails across all analytical stages."""
        text_corpus = f"{parsed.subject} {parsed.body_plain} {parsed.body_html}"
        extracted = self.extractor.extract_iocs(text_corpus)

        ips = set(extracted.get("ips", []))
        domains = set(extracted.get("domains", []))
        urls = set(extracted.get("urls", []))
        emails = set(extracted.get("emails", []))
        hashes = set(extracted.get("hashes", []))

        # Add Originating IP & Hop IPs from Transmission Analysis
        if transmission.originating_ip:
            ips.add(transmission.originating_ip)
        for hop in transmission.evaluated_hops:
            if hop.client_ip:
                ips.add(hop.client_ip)

        # Add Sender & Reply-To Domains
        if transmission.sender_identity.from_domain:
            domains.add(transmission.sender_identity.from_domain)

        # Add DKIM & SPF Domains from Auth Verification
        if auth.spf.domain:
            domains.add(auth.spf.domain)
        for dkim in auth.dkim_signatures:
            if dkim.domain:
                domains.add(dkim.domain)

        # Add Parsed Attachment Hashes / Filenames
        for att in parsed.attachments:
            if att.filename:
                # Add filename to text corpus scan
                fn_iocs = self.extractor.extract_iocs(att.filename)
                hashes.update(fn_iocs.get("hashes", []))

        return {
            "ips": sorted(list(ips)),
            "domains": sorted(list(domains)),
            "urls": sorted(list(urls)),
            "emails": sorted(list(emails)),
            "hashes": sorted(list(hashes)),
        }
