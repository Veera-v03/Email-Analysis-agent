"""Risk Enrichment service generating MITRE ATT&CK technique mappings and mitigator steps."""

from __future__ import annotations

from typing import Any


class RiskEnrichmentService:
    """Enriches investigations with MITRE ATT&CK maps, threats, and mitigation recommendations."""

    # Map behavioral/malware triggers to MITRE ATT&CK Techniques
    MITRE_MAPPINGS = {
        "urgency_manipulation": {
            "id": "T1566",
            "name": "Phishing",
            "tactic": "Initial Access",
            "description": "Adversaries may send phishing messages to gain access to sensitive systems.",
        },
        "bec_impersonation": {
            "id": "T1566.003",
            "name": "Phishing: Spearphishing Attachment",
            "tactic": "Initial Access",
            "description": "Targeted spearphishing to compromise business emails and financial details.",
        },
        "credential_harvesting": {
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "description": "Adversaries send spearphishing emails containing links to harvest credentials.",
        },
        "double_extension": {
            "id": "T1204.002",
            "name": "User Execution: Malicious File",
            "tactic": "Execution",
            "description": "User execution of a disguised execution payload file.",
        },
        "vba_macros": {
            "id": "T1204.002",
            "name": "User Execution: Malicious File",
            "tactic": "Execution",
            "description": "Adversaries rely on user execution of embedded VBA macros inside documents.",
        },
    }

    def enrich_risk_profile(
        self,
        risk_level: str,
        behavioral_results: dict[str, Any],
        malware_results: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compile a complete MITRE ATT&CK map, threat taxonomy, and SOC mitigation list."""
        mitre_techniques = []
        recommendations = []
        threat_categories = []

        # Parse behavioral tactics
        for tactic in behavioral_results.get("detected_tactics", []):
            if tactic in self.MITRE_MAPPINGS:
                mitre_techniques.append(self.MITRE_MAPPINGS[tactic])

            if tactic == "credential_harvesting":
                threat_categories.append("Credential Phishing")
                recommendations.extend(
                    [
                        "Force account password reset on active identity.",
                        "Verify active login logs in Azure AD / Okta.",
                        "Enable MFA protection enforcement rules.",
                    ]
                )
            elif tactic == "bec_impersonation" or tactic == "financial_fraud":
                threat_categories.append("Business Email Compromise (BEC)")
                recommendations.extend(
                    [
                        "Alert the accounting department to block related wire instructions.",
                        "Initiate out-of-band communication check with the vendor/sender.",
                    ]
                )
            elif tactic == "urgency_manipulation":
                threat_categories.append("Social Engineering & Urgency Exploitation")
                recommendations.extend(
                    [
                        "Warn recipient against acting on artificial urgency prompts.",
                        "Verify request out-of-band using official internal directory contacts.",
                    ]
                )

        # Parse static malware indicators
        if malware_results and malware_results.get("is_malicious"):
            threat_categories.append("Malware Delivery")
            recommendations.extend(
                [
                    "Isolate recipient endpoint device immediately.",
                    "Scan device with endpoint detection agent (EDR).",
                    "Quarantine target attachment file globally.",
                ]
            )
            if malware_results.get("vba_macros_detected"):
                mitre_techniques.append(self.MITRE_MAPPINGS["vba_macros"])
            if any(
                "double extension" in r.lower()
                for r in malware_results.get("reasons", [])
            ):
                mitre_techniques.append(self.MITRE_MAPPINGS["double_extension"])

        # Deduplicate
        threat_categories = list(set(threat_categories))
        if not threat_categories:
            threat_categories = ["Generic Phishing Alert"]

        recommendations = list(set(recommendations))
        if not recommendations:
            recommendations = [
                "Monitor email traffic for visual typosquatting indicators."
            ]

        # Clean MITRE techniques duplicates by ID
        seen_ids = set()
        unique_techniques = []
        for tech in mitre_techniques:
            if tech["id"] not in seen_ids:
                seen_ids.add(tech["id"])
                unique_techniques.append(tech)

        return {
            "threat_categories": threat_categories,
            "mitre_attack_mapping": unique_techniques,
            "soc_recommendations": recommendations,
        }
