"""Deterministic weighted risk scoring strategy using RiskPolicyConfig."""

from __future__ import annotations

from typing import Any

from src.common.constants import ThreatCategory
from src.risk.models import RiskEvidenceDTO, RiskPolicyConfig
from src.risk.strategies.base_strategy import IRiskScoringStrategy


class DeterministicWeightedScoringStrategy(IRiskScoringStrategy):
    """Default deterministic rule-weighted risk scoring strategy."""

    @property
    def strategy_name(self) -> str:
        return "DeterministicWeightedScoringStrategy"

    def calculate_score(
        self,
        features: dict[str, Any],
        config: RiskPolicyConfig,
    ) -> tuple[int, list[RiskEvidenceDTO], list[str]]:
        """Calculate weighted risk score, generating rich RiskEvidenceDTO items."""
        score = 0
        evidence: list[RiskEvidenceDTO] = []
        categories: set[str] = set()

        # 1. Executive Display Name Spoofing
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

        # 2. Malicious Threat Intel IOC Match
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

        # 3. DMARC Authentication Failure
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

        # 4. Reply-To Mismatch
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

        # 5. Thread Hijacking Suspect
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

        # 6. SPF Failure
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

        # 7. DKIM Failure
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

        # 8. Low Header Integrity
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

        # 9. Free Webmail Reply-To
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

        # 10. Return-Path Mismatch
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
