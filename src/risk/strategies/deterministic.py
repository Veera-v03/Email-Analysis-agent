"""Deterministic weighted risk scoring strategy with multimodal signal fusion and anti-double-counting (Module 23)."""

from __future__ import annotations

from typing import Any

from src.common.constants import ThreatCategory
from src.risk.fusion_models import (
    EvidenceStatus,
    MultimodalFeatureVectorDTO,
    SignalDomain,
)
from src.risk.models import RiskEvidenceDTO, RiskPolicyConfig
from src.risk.strategies.base_strategy import IRiskScoringStrategy


class DeterministicWeightedScoringStrategy(IRiskScoringStrategy):
    """Deterministic rule-weighted risk scoring strategy supporting legacy feature dicts and multimodal feature vectors."""

    DOMAIN_CEILINGS: dict[SignalDomain, int] = {
        SignalDomain.AUTHENTICATION: 30,
        SignalDomain.TRANSMISSION: 40,
        SignalDomain.THREAT_INTEL: 35,
        SignalDomain.CONTENT: 25,
        SignalDomain.MEDIA: 25,
        SignalDomain.URL: 35,
        SignalDomain.CORRELATION: 20,
    }

    BASE_SIGNAL_WEIGHTS: dict[str, int] = {
        # Authentication
        "dmarc_result": 30,
        "spf_result": 15,
        "dkim_result": 15,
        "arc_chain_valid": 10,
        # Transmission
        "is_display_name_spoofed": 40,
        "is_reply_to_mismatched": 25,
        "is_thread_hijack_suspect": 25,
        "header_integrity_score": 15,
        # Threat Intel
        "malicious_ioc_count": 35,
        "whois_age_days": 15,
        # Content
        "urgency_score": 15,
        "financial_coercion_score": 20,
        "has_hidden_dom_text": 15,
        "tracking_beacons": 5,
        # Media
        "ocr_phishing_detected": 20,
        "qr_malicious_destination": 25,
        # URL
        "has_credential_form": 30,
        "redirect_depth": 15,
        "ssrf_violation": 35,
        # Correlation
        "campaign_detected": 20,
        "historical_similarity_score": 15,
    }

    @property
    def strategy_name(self) -> str:
        return "DeterministicWeightedScoringStrategy"

    def calculate_score(
        self,
        features: dict[str, Any] | MultimodalFeatureVectorDTO,
        config: RiskPolicyConfig | None = None,
    ) -> tuple[int, list[RiskEvidenceDTO], list[str]]:
        """Calculate weighted risk score. Dispatches to multimodal scorer if MultimodalFeatureVectorDTO is passed."""
        policy_cfg = config or RiskPolicyConfig()
        if isinstance(features, MultimodalFeatureVectorDTO):
            return self.calculate_multimodal_score(features, policy_cfg)
        return self._calculate_legacy_score(features, policy_cfg)

    def calculate_multimodal_score(
        self,
        multimodal_vector: MultimodalFeatureVectorDTO,
        config: RiskPolicyConfig | None = None,
    ) -> tuple[int, list[RiskEvidenceDTO], list[str]]:
        """Calculate domain-bounded multimodal risk score with causal anti-double-counting."""
        evidence: list[RiskEvidenceDTO] = []
        categories: set[str] = set()

        signals_map = {s.signal_name: s for s in multimodal_vector.signals}

        # -------------------------------------------------------------------
        # Anti-Double-Counting Context Analysis
        # -------------------------------------------------------------------
        dmarc_sig = signals_map.get("dmarc_result")
        spf_sig = signals_map.get("spf_result")
        ioc_sig = signals_map.get("malicious_ioc_count")
        cred_sig = signals_map.get("has_credential_form")
        spoof_sig = signals_map.get("is_display_name_spoofed")

        # RULE A: DMARC + SPF/DKIM Causal Overlap
        # If DMARC fails and SPF fails, scale SPF penalty by 0.50
        scale_spf = 1.0
        if dmarc_sig and dmarc_sig.normalized_score >= 0.5 and spf_sig and spf_sig.normalized_score >= 0.5:
            scale_spf = 0.50

        # RULE B: Threat Intel Malicious IOC + URL Sandbox Credential Form
        # If IOC is already known malicious, sandbox form acts as corroboration (scale by 0.50)
        scale_sandbox_cred = 1.0
        if ioc_sig and ioc_sig.normalized_score >= 0.5 and cred_sig and cred_sig.normalized_score >= 0.5:
            scale_sandbox_cred = 0.50

        # RULE C: Executive Spoof + BEC Urgency/Coercion
        # If executive spoof is detected, scale linguistic urgency/coercion to prevent redundant penalty
        scale_bec_linguistics = 1.0
        if spoof_sig and spoof_sig.normalized_score >= 0.5:
            scale_bec_linguistics = 0.50

        # -------------------------------------------------------------------
        # Domain Scoring & Ceiling Evaluation
        # -------------------------------------------------------------------
        total_score = 0

        for domain in SignalDomain:
            domain_ceiling = self.DOMAIN_CEILINGS.get(domain, 30)
            domain_signals = [
                s
                for s in multimodal_vector.signals
                if s.domain == domain and s.status == EvidenceStatus.EVALUATED_POSITIVE
            ]

            domain_raw_pts = 0.0
            for signal in domain_signals:
                base_weight = float(self.BASE_SIGNAL_WEIGHTS.get(signal.signal_name, 10))

                # Apply anti-double-counting scaling factors
                scale_factor = 1.0
                if signal.signal_name == "spf_result":
                    scale_factor = scale_spf
                elif signal.signal_name == "has_credential_form":
                    scale_factor = scale_sandbox_cred
                elif signal.signal_name in ("urgency_score", "financial_coercion_score"):
                    scale_factor = scale_bec_linguistics

                # Signal contribution = base_weight * normalized_score * confidence * scale_factor
                signal_pts = base_weight * signal.normalized_score * signal.confidence * scale_factor
                domain_raw_pts += signal_pts

                # Category Tagging
                if signal.signal_name in ("is_display_name_spoofed", "is_thread_hijack_suspect", "financial_coercion_score"):
                    categories.add(ThreatCategory.BEC.value)
                elif signal.signal_name in ("malicious_ioc_count", "ocr_phishing_detected", "qr_malicious_destination", "campaign_detected", "historical_similarity_score"):
                    categories.add(ThreatCategory.PHISHING.value)
                elif signal.signal_name in ("has_credential_form", "is_reply_to_mismatched"):
                    categories.add(ThreatCategory.CREDENTIAL_HARVESTING.value)

                applied_int_weight = int(round(signal_pts))
                if applied_int_weight > 0:
                    evidence.append(
                        RiskEvidenceDTO(
                            source_module=domain.value,
                            feature_name=signal.signal_name,
                            applied_weight=applied_int_weight,
                            confidence=round(signal.confidence, 2),
                            explanation=signal.explanation or f"{signal.signal_name} threat indicator detected",
                        )
                    )

            # Enforce domain ceiling
            domain_final_pts = int(round(min(float(domain_ceiling), domain_raw_pts)))
            total_score += domain_final_pts

        final_score = min(100, max(0, total_score))
        return final_score, evidence, sorted(list(categories))

    # -----------------------------------------------------------------------
    # Legacy Score Method for Backward Compatibility
    # -----------------------------------------------------------------------
    def _calculate_legacy_score(
        self,
        features: dict[str, Any],
        config: RiskPolicyConfig,
    ) -> tuple[int, list[RiskEvidenceDTO], list[str]]:
        score = 0
        evidence: list[RiskEvidenceDTO] = []
        categories: set[str] = set()

        if features.get("is_display_name_spoofed"):
            w = config.weight_display_name_spoof
            score += w
            categories.add(ThreatCategory.BEC.value)
            evidence.append(
                RiskEvidenceDTO(
                    source_module="transmission",
                    feature_name="is_display_name_spoofed",
                    applied_weight=w,
                    confidence=1.0,
                    explanation="Executive display name spoofing detected (BEC attempt)",
                )
            )

        mal_count = features.get("malicious_ioc_count", 0)
        if mal_count > 0:
            w = config.weight_malicious_ioc
            score += w
            categories.add(ThreatCategory.PHISHING.value)
            evidence.append(
                RiskEvidenceDTO(
                    source_module="threat_intel",
                    feature_name="malicious_ioc_count",
                    applied_weight=w,
                    confidence=features.get("intel_confidence", 0.9),
                    explanation=f"{mal_count} malicious indicator(s) matched threat intelligence feeds",
                )
            )

        if features.get("dmarc_result") == "FAIL":
            w = config.weight_dmarc_fail
            score += w
            evidence.append(
                RiskEvidenceDTO(
                    source_module="authentication",
                    feature_name="dmarc_result",
                    applied_weight=w,
                    confidence=1.0,
                    explanation="DMARC authentication failed (Domain alignment or validation failure)",
                )
            )

        if features.get("is_reply_to_mismatched"):
            w = config.weight_reply_to_mismatch
            score += w
            categories.add(ThreatCategory.CREDENTIAL_HARVESTING.value)
            evidence.append(
                RiskEvidenceDTO(
                    source_module="transmission",
                    feature_name="is_reply_to_mismatched",
                    applied_weight=w,
                    confidence=1.0,
                    explanation="Reply-To address does not match From address",
                )
            )

        if features.get("is_thread_hijack_suspect"):
            w = config.weight_thread_hijack
            score += w
            categories.add(ThreatCategory.BEC.value)
            evidence.append(
                RiskEvidenceDTO(
                    source_module="transmission",
                    feature_name="is_thread_hijack_suspect",
                    applied_weight=w,
                    confidence=0.85,
                    explanation="Thread hijacking suspect (fake Re: prefix without parent headers)",
                )
            )

        if features.get("spf_result") in ("FAIL", "SOFTFAIL"):
            w = config.weight_spf_fail
            score += w
            evidence.append(
                RiskEvidenceDTO(
                    source_module="authentication",
                    feature_name="spf_result",
                    applied_weight=w,
                    confidence=0.9,
                    explanation=f"SPF evaluation resulted in {features.get('spf_result')}",
                )
            )

        if features.get("dkim_result") == "FAIL":
            w = config.weight_dkim_fail
            score += w
            evidence.append(
                RiskEvidenceDTO(
                    source_module="authentication",
                    feature_name="dkim_result",
                    applied_weight=w,
                    confidence=0.9,
                    explanation="DKIM signature verification failed",
                )
            )

        h_score = features.get("header_integrity_score", 1.0)
        if h_score < 0.6:
            w = config.weight_low_header_integrity
            score += w
            evidence.append(
                RiskEvidenceDTO(
                    source_module="transmission",
                    feature_name="header_integrity_score",
                    applied_weight=w,
                    confidence=0.8,
                    explanation=f"Header integrity score is low ({h_score:.2f})",
                )
            )

        if features.get("is_reply_to_free_webmail"):
            w = config.weight_free_webmail_reply_to
            score += w
            evidence.append(
                RiskEvidenceDTO(
                    source_module="transmission",
                    feature_name="is_reply_to_free_webmail",
                    applied_weight=w,
                    confidence=0.8,
                    explanation="Reply-To target is a free webmail account",
                )
            )

        if features.get("is_return_path_mismatched"):
            w = config.weight_return_path_mismatch
            score += w
            evidence.append(
                RiskEvidenceDTO(
                    source_module="transmission",
                    feature_name="is_return_path_mismatched",
                    applied_weight=w,
                    confidence=0.7,
                    explanation="Return-Path domain differs from From domain",
                )
            )

        final_score = min(100, score)
        return final_score, evidence, sorted(list(categories))
