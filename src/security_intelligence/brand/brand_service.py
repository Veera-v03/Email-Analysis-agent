"""Brand Impersonation Detection Service checking display name mismatches, typosquatting, and homographs."""

from __future__ import annotations

from typing import Any

import tldextract


class BrandService:
    """Analyzes sender display names, homograph domains, and look-alike brands."""

    # Targeted high-value brands
    TARGETED_BRANDS = {
        "microsoft",
        "google",
        "apple",
        "amazon",
        "paypal",
        "github",
        "adobe",
        "dropbox",
        "linkedin",
        "chase",
        "bankofamerica",
        "netflix",
    }

    def analyze_sender(self, display_name: str, sender_email: str) -> dict[str, Any]:
        """Perform brand impersonation checks on display name and sender email address."""
        email_parts = sender_email.split("@")
        if len(email_parts) != 2:
            return {"impersonation_detected": False, "reason": None}

        local_part, domain = email_parts
        extracted = tldextract.extract(domain.lower())
        sender_brand = extracted.domain

        display_name_lower = display_name.lower()
        matched_brand = None

        # 1. Display name spoofing (e.g. display name contains "PayPal Alert" but domain is "gmail.com")
        for brand in self.TARGETED_BRANDS:
            if brand in display_name_lower:
                matched_brand = brand
                break

        if matched_brand and sender_brand != matched_brand:
            # Domain check (allow common domain extensions or internal aliases)
            if not any(
                sender_brand.endswith(b) for b in (matched_brand, "internal-com")
            ):
                return {
                    "impersonation_detected": True,
                    "reason": f"Display name contains brand '{matched_brand.upper()}' but sender domain '{domain}' is unrelated.",
                    "matched_brand": matched_brand,
                    "type": "display_name_spoofing",
                }

        # 2. Typosquatting / Levenshtein distance check (e.g., micr0soft, paypa1)
        for brand in self.TARGETED_BRANDS:
            if sender_brand == brand:
                continue

            # Simple Levenshtein check for typosquatting (edit distance <= 2)
            dist = self.levenshtein_distance(sender_brand, brand)
            if dist in (1, 2) and len(sender_brand) >= 4:
                return {
                    "impersonation_detected": True,
                    "reason": f"Typosquatting detected: sender domain '{domain}' is visually similar to brand '{brand.upper()}'.",
                    "matched_brand": brand,
                    "type": "typosquatting",
                }

        # 3. Homograph domain checking (Unicode/IDNA spoofing)
        # Check if domain starts with xn-- punycode prefix
        if domain.startswith("xn--"):
            try:
                decoded_unicode = domain.encode("utf-8").decode("idna").split(".")[0]
                for brand in self.TARGETED_BRANDS:
                    dist = self.levenshtein_distance(decoded_unicode, brand)
                    if dist in (0, 1, 2):
                        return {
                            "impersonation_detected": True,
                            "reason": f"IDNA Homograph IDN spoofing detected: Punycode domain '{domain}' decodes to '{decoded_unicode}' target brand '{brand.upper()}'.",
                            "matched_brand": brand,
                            "type": "homograph_impersonation",
                        }
            except Exception:
                pass

        # Check visual indicators (subdomain structure like pay-pal.com, google-login.support)
        for brand in self.TARGETED_BRANDS:
            subdomain_spoof = f"{brand}-"
            if subdomain_spoof in domain or f"-{brand}" in domain:
                return {
                    "impersonation_detected": True,
                    "reason": f"Subdomain/visual indicator brand impersonation: '{domain}' contains hyphenated brand '{brand.upper()}'.",
                    "matched_brand": brand,
                    "type": "hyphen_impersonation",
                }

        return {"impersonation_detected": False, "reason": None}

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Compute the Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return BrandService.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]
