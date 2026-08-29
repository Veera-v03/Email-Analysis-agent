"""Multimodal threat signal fusion and normalization engine (Module 23)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from src.authentication.models import AuthenticationVerification
from src.content_intelligence.models import ContentAnalysisResult, MediaStatus
from src.notifications.sanitizer import sanitize_metadata
from src.parsing.models import ParsedEmail
from src.risk.fusion_models import (
    EvidenceStatus,
    MultimodalFeatureVectorDTO,
    NormalizedSignalDTO,
    SignalDomain,
)
from src.threat_correlation.models import ThreatCorrelationResult
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.transmission.models import TransmissionAnalysis
from src.utils.logging import get_logger

logger = get_logger(__name__)


class MultimodalSignalFuser:
    """Deterministic, multi-tenant multimodal threat signal aggregator and normalizer."""

    def fuse_signals(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis,
        auth: AuthenticationVerification,
        intel: ThreatIntelEnrichmentResult,
        content_res: ContentAnalysisResult | None = None,
        url_res: Any | None = None,
        correlation_res: ThreatCorrelationResult | None = None,
    ) -> MultimodalFeatureVectorDTO:
        """Gather, normalize, and fuse heterogeneous upstream threat signals across all 7 domains."""
        tenant_id: UUID = parsed.tenant_id
        message_id: str = parsed.message_id or "unknown"
        signals: list[NormalizedSignalDTO] = []

        # 1. Authentication Domain Signals
        signals.extend(self._normalize_auth_signals(auth))

        # 2. Transmission Domain Signals
        signals.extend(self._normalize_transmission_signals(transmission))

        # 3. Threat Intelligence Domain Signals
        signals.extend(self._normalize_threat_intel_signals(intel))

        # 4. Content Intelligence Domain Signals
        signals.extend(self._normalize_content_signals(content_res))

        # 5. Media (OCR & QR) Domain Signals
        signals.extend(self._normalize_media_signals(content_res))

        # 6. URL & Sandbox Domain Signals
        signals.extend(self._normalize_url_signals(url_res))

        # 7. Threat Correlation & Campaign Domain Signals
        signals.extend(self._normalize_correlation_signals(correlation_res))

        # Calculate evaluated counts and completeness ratio
        evaluated_signals = [
            s
            for s in signals
            if s.status in (EvidenceStatus.EVALUATED_POSITIVE, EvidenceStatus.EVALUATED_NEGATIVE)
        ]
        total_evaluated = len(evaluated_signals)
        total_potential = len(signals)
        completeness_ratio = (
            float(total_evaluated) / float(total_potential) if total_potential > 0 else 1.0
        )

        # Calculate domain-level normalized subscores [0.0, 1.0]
        domain_subscores: dict[str, float] = {}
        for domain in SignalDomain:
            domain_signals = [s for s in evaluated_signals if s.domain == domain]
            if domain_signals:
                # Weighted average of evaluated signals for the domain
                total_weight = sum(s.weight for s in domain_signals)
                if total_weight > 0:
                    weighted_sum = sum(s.normalized_score * s.weight for s in domain_signals)
                    domain_subscores[domain.value] = min(1.0, max(0.0, weighted_sum / total_weight))
                else:
                    domain_subscores[domain.value] = 0.0
            else:
                domain_subscores[domain.value] = 0.0

        return MultimodalFeatureVectorDTO(
            tenant_id=tenant_id,
            message_id=message_id,
            domain_subscores=domain_subscores,
            signals=signals,
            completeness_ratio=round(completeness_ratio, 4),
            total_evaluated_signals=total_evaluated,
        )

    # -----------------------------------------------------------------------
    # Domain Normalizers
    # -----------------------------------------------------------------------
    def _normalize_auth_signals(
        self, auth: AuthenticationVerification | None
    ) -> list[NormalizedSignalDTO]:
        signals: list[NormalizedSignalDTO] = []
        if not auth:
            for sig in ("dmarc_result", "spf_result", "dkim_result", "arc_chain_valid"):
                signals.append(
                    NormalizedSignalDTO(
                        domain=SignalDomain.AUTHENTICATION,
                        signal_name=sig,
                        raw_value=None,
                        normalized_score=0.0,
                        confidence=0.0,
                        weight=0.0,
                        status=EvidenceStatus.SKIPPED,
                        explanation="Authentication verification was not executed",
                    )
                )
            return signals

        # 1.1 DMARC
        dmarc_res = (auth.dmarc.result or "NONE").upper()
        if dmarc_res == "PASS":
            dmarc_score = 0.0
            dmarc_status = EvidenceStatus.EVALUATED_NEGATIVE
            dmarc_exp = f"DMARC validation passed for domain '{auth.dmarc.domain}'"
        elif dmarc_res == "FAIL":
            dmarc_score = 1.0
            dmarc_status = EvidenceStatus.EVALUATED_POSITIVE
            dmarc_exp = f"DMARC validation failed for domain '{auth.dmarc.domain}' (Policy: {auth.dmarc.policy})"
        else:
            dmarc_score = 0.2
            dmarc_status = EvidenceStatus.EVALUATED_NEGATIVE
            dmarc_exp = f"DMARC record absent or neutral for domain '{auth.dmarc.domain}'"

        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.AUTHENTICATION,
                signal_name="dmarc_result",
                raw_value=dmarc_res,
                normalized_score=dmarc_score,
                confidence=1.0,
                weight=1.5,
                status=dmarc_status,
                explanation=dmarc_exp,
            )
        )

        # 1.2 SPF
        spf_res = (auth.spf.result or "NONE").upper()
        if spf_res == "PASS":
            spf_score = 0.0
            spf_status = EvidenceStatus.EVALUATED_NEGATIVE
            spf_exp = f"SPF record passed for domain '{auth.spf.domain}'"
        elif spf_res == "FAIL":
            spf_score = 0.9
            spf_status = EvidenceStatus.EVALUATED_POSITIVE
            spf_exp = f"SPF validation failed (Hardfail) for client IP {auth.spf.client_ip}"
        elif spf_res == "SOFTFAIL":
            spf_score = 0.6
            spf_status = EvidenceStatus.EVALUATED_POSITIVE
            spf_exp = f"SPF validation softfailed (~all) for client IP {auth.spf.client_ip}"
        else:
            spf_score = 0.2
            spf_status = EvidenceStatus.EVALUATED_NEGATIVE
            spf_exp = f"SPF validation result: {spf_res}"

        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.AUTHENTICATION,
                signal_name="spf_result",
                raw_value=spf_res,
                normalized_score=spf_score,
                confidence=0.95,
                weight=1.0,
                status=spf_status,
                explanation=spf_exp,
            )
        )

        # 1.3 DKIM
        dkim_res = (auth.dkim_overall_result or "NONE").upper()
        if dkim_res == "PASS":
            dkim_score = 0.0
            dkim_status = EvidenceStatus.EVALUATED_NEGATIVE
            dkim_exp = "DKIM cryptographic signature verified successfully"
        elif dkim_res == "FAIL":
            dkim_score = 0.8
            dkim_status = EvidenceStatus.EVALUATED_POSITIVE
            dkim_exp = "DKIM cryptographic signature verification failed"
        else:
            dkim_score = 0.2
            dkim_status = EvidenceStatus.EVALUATED_NEGATIVE
            dkim_exp = "No valid DKIM signature present"

        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.AUTHENTICATION,
                signal_name="dkim_result",
                raw_value=dkim_res,
                normalized_score=dkim_score,
                confidence=0.95,
                weight=1.0,
                status=dkim_status,
                explanation=dkim_exp,
            )
        )

        # 1.4 ARC
        arc_valid = bool(auth.arc.chain_valid) if auth.arc else False
        if arc_valid:
            arc_score = 0.0
            arc_status = EvidenceStatus.EVALUATED_NEGATIVE
            arc_exp = f"Authenticated Received Chain (ARC) valid across {auth.arc.instance_count} hop(s)"
        else:
            arc_score = 0.7 if (auth.arc and auth.arc.instance_count > 0) else 0.0
            arc_status = (
                EvidenceStatus.EVALUATED_POSITIVE
                if (auth.arc and auth.arc.instance_count > 0)
                else EvidenceStatus.EVALUATED_NEGATIVE
            )
            arc_exp = "ARC chain invalid or broken across intermediary relays"

        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.AUTHENTICATION,
                signal_name="arc_chain_valid",
                raw_value=arc_valid,
                normalized_score=arc_score,
                confidence=0.85,
                weight=0.8,
                status=arc_status,
                explanation=arc_exp,
            )
        )

        return signals

    def _normalize_transmission_signals(
        self, transmission: TransmissionAnalysis | None
    ) -> list[NormalizedSignalDTO]:
        signals: list[NormalizedSignalDTO] = []
        if not transmission:
            for sig in (
                "is_display_name_spoofed",
                "is_reply_to_mismatched",
                "is_thread_hijack_suspect",
                "header_integrity_score",
            ):
                signals.append(
                    NormalizedSignalDTO(
                        domain=SignalDomain.TRANSMISSION,
                        signal_name=sig,
                        raw_value=None,
                        normalized_score=0.0,
                        confidence=0.0,
                        weight=0.0,
                        status=EvidenceStatus.SKIPPED,
                        explanation="Transmission analysis was not executed",
                    )
                )
            return signals

        # 2.1 Display Name Spoofing
        spoofed = bool(transmission.sender_identity.is_display_name_spoofed)
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.TRANSMISSION,
                signal_name="is_display_name_spoofed",
                raw_value=spoofed,
                normalized_score=1.0 if spoofed else 0.0,
                confidence=1.0,
                weight=1.8,
                status=EvidenceStatus.EVALUATED_POSITIVE if spoofed else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation=(
                    f"Executive / VIP display name spoofing detected for '{transmission.sender_identity.from_display_name}'"
                    if spoofed
                    else "Sender display name aligns with From address domain"
                ),
            )
        )

        # 2.2 Reply-To Mismatch
        reply_mismatch = bool(transmission.sender_identity.is_reply_to_mismatched)
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.TRANSMISSION,
                signal_name="is_reply_to_mismatched",
                raw_value=reply_mismatch,
                normalized_score=0.9 if reply_mismatch else 0.0,
                confidence=0.95,
                weight=1.2,
                status=EvidenceStatus.EVALUATED_POSITIVE if reply_mismatch else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation=(
                    f"Reply-To address '{transmission.sender_identity.reply_to_address}' differs from From address '{transmission.sender_identity.from_address}'"
                    if reply_mismatch
                    else "Reply-To address matches sender"
                ),
            )
        )

        # 2.3 Thread Hijacking Suspect
        thread_hijack = bool(transmission.is_thread_hijack_suspect)
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.TRANSMISSION,
                signal_name="is_thread_hijack_suspect",
                raw_value=thread_hijack,
                normalized_score=0.85 if thread_hijack else 0.0,
                confidence=0.90,
                weight=1.2,
                status=EvidenceStatus.EVALUATED_POSITIVE if thread_hijack else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation=(
                    "Thread hijacking indicator detected: fake 'Re:' subject prefix without valid in-reply-to headers"
                    if thread_hijack
                    else "Thread references consistent"
                ),
            )
        )

        # 2.4 Header Integrity
        integrity = float(transmission.header_integrity_score)
        norm_integrity_threat = max(0.0, min(1.0, 1.0 - integrity))
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.TRANSMISSION,
                signal_name="header_integrity_score",
                raw_value=integrity,
                normalized_score=norm_integrity_threat,
                confidence=0.85,
                weight=0.9,
                status=EvidenceStatus.EVALUATED_POSITIVE if norm_integrity_threat > 0.4 else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation=f"Header anomaly score: {norm_integrity_threat:.2f} (integrity: {integrity:.2f})",
            )
        )

        return signals

    def _normalize_threat_intel_signals(
        self, intel: ThreatIntelEnrichmentResult | None
    ) -> list[NormalizedSignalDTO]:
        signals: list[NormalizedSignalDTO] = []
        if not intel:
            for sig in ("malicious_ioc_count", "whois_age_days"):
                signals.append(
                    NormalizedSignalDTO(
                        domain=SignalDomain.THREAT_INTEL,
                        signal_name=sig,
                        raw_value=None,
                        normalized_score=0.0,
                        confidence=0.0,
                        weight=0.0,
                        status=EvidenceStatus.SKIPPED,
                        explanation="Threat intelligence enrichment was not executed",
                    )
                )
            return signals

        # 3.1 Malicious IOC Count
        mal_count = int(intel.malicious_ioc_count)
        norm_ioc_score = min(1.0, mal_count * 0.50)
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.THREAT_INTEL,
                signal_name="malicious_ioc_count",
                raw_value=mal_count,
                normalized_score=norm_ioc_score,
                confidence=intel.overall_confidence.confidence if intel.overall_confidence else 0.9,
                weight=1.6,
                status=EvidenceStatus.EVALUATED_POSITIVE if mal_count > 0 else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation=(
                    f"{mal_count} indicator(s) matched threat intelligence feeds: {', '.join(intel.matched_feeds)}"
                    if mal_count > 0
                    else "No matched indicators across active threat feeds"
                ),
            )
        )

        # 3.2 WHOIS Domain Age
        # Extract age from enriched targets if available
        whois_age = None
        for target in intel.enriched_targets:
            for obs in target.observations:
                payload = getattr(obs, "metadata", None) or getattr(obs, "raw_payload", None) or {}
                if isinstance(payload, dict) and "domain_age_days" in payload:
                    try:
                        whois_age = int(payload["domain_age_days"])
                        break
                    except (ValueError, TypeError):
                        pass

        if whois_age is not None:
            if whois_age < 7:
                age_score = 0.90
                age_status = EvidenceStatus.EVALUATED_POSITIVE
                age_exp = f"Newly registered domain (Age: {whois_age} days < 7 days)"
            elif whois_age < 30:
                age_score = 0.60
                age_status = EvidenceStatus.EVALUATED_POSITIVE
                age_exp = f"Recently registered domain (Age: {whois_age} days < 30 days)"
            else:
                age_score = 0.0
                age_status = EvidenceStatus.EVALUATED_NEGATIVE
                age_exp = f"Established domain (Age: {whois_age} days)"

            signals.append(
                NormalizedSignalDTO(
                    domain=SignalDomain.THREAT_INTEL,
                    signal_name="whois_age_days",
                    raw_value=whois_age,
                    normalized_score=age_score,
                    confidence=0.85,
                    weight=0.9,
                    status=age_status,
                    explanation=age_exp,
                )
            )
        else:
            signals.append(
                NormalizedSignalDTO(
                    domain=SignalDomain.THREAT_INTEL,
                    signal_name="whois_age_days",
                    raw_value=None,
                    normalized_score=0.0,
                    confidence=0.0,
                    weight=0.0,
                    status=EvidenceStatus.UNAVAILABLE,
                    explanation="WHOIS domain registration age data unavailable",
                )
            )

        return signals

    def _normalize_content_signals(
        self, content_res: ContentAnalysisResult | None
    ) -> list[NormalizedSignalDTO]:
        signals: list[NormalizedSignalDTO] = []
        if not content_res:
            for sig in ("urgency_score", "financial_coercion_score", "has_hidden_dom_text", "tracking_beacons"):
                signals.append(
                    NormalizedSignalDTO(
                        domain=SignalDomain.CONTENT,
                        signal_name=sig,
                        raw_value=None,
                        normalized_score=0.0,
                        confidence=0.0,
                        weight=0.0,
                        status=EvidenceStatus.SKIPPED,
                        explanation="Content intelligence was not executed",
                    )
                )
            return signals

        # 4.1 Urgency
        urg_score = max(0.0, min(1.0, float(content_res.intent_analysis.urgency_score)))
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.CONTENT,
                signal_name="urgency_score",
                raw_value=urg_score,
                normalized_score=urg_score,
                confidence=0.90,
                weight=1.0,
                status=EvidenceStatus.EVALUATED_POSITIVE if urg_score > 0.4 else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation=f"Linguistic urgency manipulation score: {urg_score:.2f}",
            )
        )

        # 4.2 Financial Coercion
        fin_score = max(0.0, min(1.0, float(content_res.intent_analysis.financial_coercion_score)))
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.CONTENT,
                signal_name="financial_coercion_score",
                raw_value=fin_score,
                normalized_score=fin_score,
                confidence=0.90,
                weight=1.2,
                status=EvidenceStatus.EVALUATED_POSITIVE if fin_score > 0.4 else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation=f"Financial coercion / payment pressure score: {fin_score:.2f} (Intent: {content_res.intent_analysis.primary_intent})",
            )
        )

        # 4.3 Hidden DOM Text
        has_hidden = bool(content_res.dom_signals.has_hidden_text)
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.CONTENT,
                signal_name="has_hidden_dom_text",
                raw_value=has_hidden,
                normalized_score=0.80 if has_hidden else 0.0,
                confidence=0.95,
                weight=1.0,
                status=EvidenceStatus.EVALUATED_POSITIVE if has_hidden else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation="CSS zero-font or hidden text detected in HTML DOM" if has_hidden else "No hidden DOM text detected",
            )
        )

        # 4.4 Tracking Beacons / Scripts
        beacon_detected = bool(content_res.dom_signals.script_tag_count > 0 or content_res.dom_signals.html_entity_obfuscation_count > 2)
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.CONTENT,
                signal_name="tracking_beacons",
                raw_value=beacon_detected,
                normalized_score=0.30 if beacon_detected else 0.0,
                confidence=0.80,
                weight=0.5,
                status=EvidenceStatus.EVALUATED_POSITIVE if beacon_detected else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation="HTML script tags or entity obfuscation present" if beacon_detected else "No malicious tracking or script elements detected",
            )
        )

        return signals

    def _normalize_media_signals(
        self, content_res: ContentAnalysisResult | None
    ) -> list[NormalizedSignalDTO]:
        signals: list[NormalizedSignalDTO] = []
        if not content_res or not hasattr(content_res, "media_evidence") or not content_res.media_evidence:
            for sig in ("ocr_phishing_detected", "qr_malicious_destination"):
                signals.append(
                    NormalizedSignalDTO(
                        domain=SignalDomain.MEDIA,
                        signal_name=sig,
                        raw_value=None,
                        normalized_score=0.0,
                        confidence=0.0,
                        weight=0.0,
                        status=EvidenceStatus.SKIPPED,
                        explanation="Media extraction was not executed",
                    )
                )
            return signals

        media = content_res.media_evidence

        # 5.1 OCR Phishing Text
        if media.ocr_status == MediaStatus.SUCCESS:
            ocr_text = media.ocr_extracted_text or ""
            ocr_conf = float(media.ocr_confidence)
            has_ocr_threat = any(
                keyword in ocr_text.lower()
                for keyword in ("urgent", "invoice", "bank", "password", "wire", "security alert")
            )
            ocr_score = min(1.0, ocr_conf * 0.90) if has_ocr_threat else 0.0
            signals.append(
                NormalizedSignalDTO(
                    domain=SignalDomain.MEDIA,
                    signal_name="ocr_phishing_detected",
                    raw_value=sanitize_metadata({"snippet": ocr_text[:120] if ocr_text else ""}),
                    normalized_score=ocr_score,
                    confidence=ocr_conf,
                    weight=1.1,
                    status=EvidenceStatus.EVALUATED_POSITIVE if has_ocr_threat else EvidenceStatus.EVALUATED_NEGATIVE,
                    explanation=(
                        f"Phishing/coercion text extracted from attachment image via OCR (Confidence: {ocr_conf:.2f})"
                        if has_ocr_threat
                        else "OCR scanned attachment image without malicious keywords"
                    ),
                )
            )
        elif media.ocr_status == MediaStatus.UNAVAILABLE:
            signals.append(
                NormalizedSignalDTO(
                    domain=SignalDomain.MEDIA,
                    signal_name="ocr_phishing_detected",
                    raw_value=None,
                    normalized_score=0.0,
                    confidence=0.0,
                    weight=0.0,
                    status=EvidenceStatus.UNAVAILABLE,
                    explanation="OCR engine unavailable",
                )
            )
        elif media.ocr_status == MediaStatus.FAILED:
            signals.append(
                NormalizedSignalDTO(
                    domain=SignalDomain.MEDIA,
                    signal_name="ocr_phishing_detected",
                    raw_value=None,
                    normalized_score=0.0,
                    confidence=0.0,
                    weight=0.0,
                    status=EvidenceStatus.ERROR,
                    explanation="OCR extraction failed",
                )
            )
        else:
            signals.append(
                NormalizedSignalDTO(
                    domain=SignalDomain.MEDIA,
                    signal_name="ocr_phishing_detected",
                    raw_value=None,
                    normalized_score=0.0,
                    confidence=0.0,
                    weight=0.0,
                    status=EvidenceStatus.SKIPPED,
                    explanation="No image or PDF attachments present for OCR scanning",
                )
            )

        # 5.2 QR Code Malicious Destination
        if media.qr_status == MediaStatus.SUCCESS:
            qr_detected = bool(media.qr_detected)
            qr_urls = media.qr_extracted_urls or []
            is_mal_qr = any("phish" in u.lower() or "malicious" in u.lower() or "login" in u.lower() for u in qr_urls)
            qr_score = 1.0 if is_mal_qr else (0.20 if qr_detected else 0.0)

            signals.append(
                NormalizedSignalDTO(
                    domain=SignalDomain.MEDIA,
                    signal_name="qr_malicious_destination",
                    raw_value=sanitize_metadata({"urls": qr_urls}),
                    normalized_score=qr_score,
                    confidence=0.95,
                    weight=1.3,
                    status=EvidenceStatus.EVALUATED_POSITIVE if qr_detected else EvidenceStatus.EVALUATED_NEGATIVE,
                    explanation=(
                        f"QR code matrix detected in attachment pointing to '{qr_urls[0] if qr_urls else 'destination'}'"
                        if qr_detected
                        else "No QR code matrix found in attachments"
                    ),
                )
            )
        elif media.qr_status == MediaStatus.UNAVAILABLE:
            signals.append(
                NormalizedSignalDTO(
                    domain=SignalDomain.MEDIA,
                    signal_name="qr_malicious_destination",
                    raw_value=None,
                    normalized_score=0.0,
                    confidence=0.0,
                    weight=0.0,
                    status=EvidenceStatus.UNAVAILABLE,
                    explanation="QR decoder engine unavailable",
                )
            )
        elif media.qr_status == MediaStatus.FAILED:
            signals.append(
                NormalizedSignalDTO(
                    domain=SignalDomain.MEDIA,
                    signal_name="qr_malicious_destination",
                    raw_value=None,
                    normalized_score=0.0,
                    confidence=0.0,
                    weight=0.0,
                    status=EvidenceStatus.ERROR,
                    explanation="QR code extraction failed",
                )
            )
        else:
            signals.append(
                NormalizedSignalDTO(
                    domain=SignalDomain.MEDIA,
                    signal_name="qr_malicious_destination",
                    raw_value=None,
                    normalized_score=0.0,
                    confidence=0.0,
                    weight=0.0,
                    status=EvidenceStatus.SKIPPED,
                    explanation="No image attachments present for QR scanning",
                )
            )

        return signals

    def _normalize_url_signals(self, url_res: Any | None) -> list[NormalizedSignalDTO]:
        signals: list[NormalizedSignalDTO] = []
        if not url_res:
            for sig in ("has_credential_form", "redirect_depth", "ssrf_violation"):
                signals.append(
                    NormalizedSignalDTO(
                        domain=SignalDomain.URL,
                        signal_name=sig,
                        raw_value=None,
                        normalized_score=0.0,
                        confidence=0.0,
                        weight=0.0,
                        status=EvidenceStatus.SKIPPED,
                        explanation="URL intelligence was not executed",
                    )
                )
            return signals

        # 6.1 Credential Form in Sandbox
        has_cred = False
        if hasattr(url_res, "sandbox_result") and url_res.sandbox_result:
            has_cred = bool(url_res.sandbox_result.has_credential_inputs)

        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.URL,
                signal_name="has_credential_form",
                raw_value=has_cred,
                normalized_score=1.0 if has_cred else 0.0,
                confidence=0.95,
                weight=1.5,
                status=EvidenceStatus.EVALUATED_POSITIVE if has_cred else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation=(
                    "Credential harvesting login form detected in URL sandbox"
                    if has_cred
                    else "No password or credential input fields detected on landing page"
                ),
            )
        )

        # 6.2 Redirect Depth
        total_hops = 0
        if hasattr(url_res, "redirect_chain") and url_res.redirect_chain:
            total_hops = int(url_res.redirect_chain.total_hops)

        redirect_score = min(1.0, total_hops * 0.25) if total_hops > 2 else 0.0
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.URL,
                signal_name="redirect_depth",
                raw_value=total_hops,
                normalized_score=redirect_score,
                confidence=0.90,
                weight=0.8,
                status=EvidenceStatus.EVALUATED_POSITIVE if total_hops > 2 else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation=(
                    f"Excessive HTTP redirect hops detected ({total_hops} hops)"
                    if total_hops > 2
                    else f"Standard direct or single-hop link ({total_hops} hop(s))"
                ),
            )
        )

        # 6.3 SSRF Violation
        ssrf = bool(getattr(url_res, "ssrf_violation_detected", False))
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.URL,
                signal_name="ssrf_violation",
                raw_value=ssrf,
                normalized_score=1.0 if ssrf else 0.0,
                confidence=1.0,
                weight=2.0,
                status=EvidenceStatus.EVALUATED_POSITIVE if ssrf else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation="SSRF attempt detected: link targets internal RFC 1918 or metadata IP" if ssrf else "No SSRF private network targets detected",
            )
        )

        return signals

    def _normalize_correlation_signals(
        self, correlation_res: ThreatCorrelationResult | None
    ) -> list[NormalizedSignalDTO]:
        signals: list[NormalizedSignalDTO] = []
        if not correlation_res:
            for sig in ("campaign_detected", "historical_similarity_score"):
                signals.append(
                    NormalizedSignalDTO(
                        domain=SignalDomain.CORRELATION,
                        signal_name=sig,
                        raw_value=None,
                        normalized_score=0.0,
                        confidence=0.0,
                        weight=0.0,
                        status=EvidenceStatus.SKIPPED,
                        explanation="Threat correlation was not executed",
                    )
                )
            return signals

        # 7.1 Campaign Detected
        campaign = bool(correlation_res.campaign_detected)
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.CORRELATION,
                signal_name="campaign_detected",
                raw_value=campaign,
                normalized_score=0.85 if campaign else 0.0,
                confidence=0.90,
                weight=1.4,
                status=EvidenceStatus.EVALUATED_POSITIVE if campaign else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation=(
                    f"Correlated incident cluster detected (Campaign ID: {correlation_res.campaign_id or 'CLUSTER'})"
                    if campaign
                    else "No coordinated campaign clusters matched"
                ),
            )
        )

        # 7.2 Historical Similarity
        camp_score = float(correlation_res.campaign_score)
        norm_similarity = min(1.0, max(0.0, camp_score / 10.0))
        signals.append(
            NormalizedSignalDTO(
                domain=SignalDomain.CORRELATION,
                signal_name="historical_similarity_score",
                raw_value=camp_score,
                normalized_score=norm_similarity,
                confidence=0.85,
                weight=1.0,
                status=EvidenceStatus.EVALUATED_POSITIVE if norm_similarity > 0.4 else EvidenceStatus.EVALUATED_NEGATIVE,
                explanation=f"Historical threat correlation score: {camp_score:.2f}/10.0",
            )
        )

        return signals
