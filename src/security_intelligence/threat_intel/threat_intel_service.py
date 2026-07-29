"""Threat Intelligence Integration Layer validating IPs, URLs, senders, and hashes against reputation feeds."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class IThreatIntelProvider(ABC):
    """Abstract interface for threat feeds looking up reputations."""

    @abstractmethod
    def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        """Lookup IP reputation."""

    @abstractmethod
    def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        """Lookup Domain reputation."""

    @abstractmethod
    def lookup_hash(self, file_hash: str) -> dict[str, Any] | None:
        """Lookup File Hash reputation."""


class LocalThreatIntelProvider(IThreatIntelProvider):
    """Threat feed database holding known IOC indicators."""

    BLACK_IPS = {"198.51.100.42", "203.0.113.11", "192.0.2.16"}
    BLACK_DOMAINS = {
        "phishing-portal.com",
        "fakebank-login.com",
        "credential-harvest.com",
    }
    BLACK_HASHES = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Empty SHA-256
        "44d88612fe8383e36e8383e36e8383e3",  # Mock MD5
    }

    def lookup_ip(self, ip: str) -> dict[str, Any] | None:
        if ip in self.BLACK_IPS:
            return {
                "malicious": True,
                "threat_score": 0.95,
                "category": "botnet_cnc",
                "source": "LocalThreatIntel",
            }
        return {"malicious": False, "threat_score": 0.0}

    def lookup_domain(self, domain: str) -> dict[str, Any] | None:
        domain_clean = domain.lower().strip()
        if any(bad in domain_clean for bad in self.BLACK_DOMAINS):
            return {
                "malicious": True,
                "threat_score": 0.98,
                "category": "phishing_host",
                "source": "LocalThreatIntel",
            }
        return {"malicious": False, "threat_score": 0.0}

    def lookup_hash(self, file_hash: str) -> dict[str, Any] | None:
        if file_hash.lower() in self.BLACK_HASHES:
            return {
                "malicious": True,
                "threat_score": 0.99,
                "category": "ransomware_payload",
                "source": "LocalThreatIntel",
            }
        return {"malicious": False, "threat_score": 0.0}


class ThreatIntelService:
    """Enriches extracted email components using registered Threat Intelligence providers."""

    def __init__(self, provider: IThreatIntelProvider | None = None) -> None:
        self.provider = provider or LocalThreatIntelProvider()

    def enrich_iocs(self, iocs: dict[str, list[str]]) -> dict[str, Any]:
        """Verify reputation scores for all extracted list of IOCs."""
        threats_found = []
        max_score = 0.0

        for ip in iocs.get("ips", []):
            res = self.provider.lookup_ip(ip)
            if res and res.get("malicious"):
                threats_found.append({"indicator": ip, "type": "ip", **res})
                max_score = max(max_score, res.get("threat_score", 0.0))

        for domain in iocs.get("domains", []):
            res = self.provider.lookup_domain(domain)
            if res and res.get("malicious"):
                threats_found.append({"indicator": domain, "type": "domain", **res})
                max_score = max(max_score, res.get("threat_score", 0.0))

        for val in iocs.get("hashes", []):
            res = self.provider.lookup_hash(val)
            if res and res.get("malicious"):
                threats_found.append({"indicator": val, "type": "hash", **res})
                max_score = max(max_score, res.get("threat_score", 0.0))

        return {
            "is_threat_detected": len(threats_found) > 0,
            "max_threat_score": max_score,
            "threats": threats_found,
        }
