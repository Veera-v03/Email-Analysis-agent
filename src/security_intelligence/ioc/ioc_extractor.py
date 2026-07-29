"""IOC Extractor scanning text files and payloads for IPs, hashes, domains, and files."""

from __future__ import annotations

import re


class IOCExtractor:
    """Regex-based utility to extract common Indicators of Compromise from raw emails."""

    # Pre-compiled high-speed regexes
    IPV4_REGEX = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b")
    URL_REGEX = re.compile(r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(?:/[^\s]*)?")

    # Hashes
    MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
    SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
    SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")

    # Filenames, process names, mutexes, registry keys
    FILENAME_REGEX = re.compile(
        r"\b[A-Za-z0-9_-]+\.(?:exe|dll|vbs|bat|scr|zip|pdf|docx|lnk)\b", re.IGNORECASE
    )
    REGISTRY_REGEX = re.compile(r"\bHKLM\\Software\\[A-Za-z0-9_\\]+\b", re.IGNORECASE)
    MUTEX_REGEX = re.compile(
        r"\b(?:Global|Local)\\[A-Za-z0-9_-]{8,64}\b", re.IGNORECASE
    )

    def extract_iocs(self, text: str) -> dict[str, list[str]]:
        """Extract all standard categories of IOCs from raw string text."""
        ips = list(set(self.IPV4_REGEX.findall(text)))
        emails = list(set(self.EMAIL_REGEX.findall(text)))
        urls = list(set(self.URL_REGEX.findall(text)))

        # Filter domains out of email/URL matches
        raw_domains = self.DOMAIN_REGEX.findall(text)
        domains = list(
            set(
                d
                for d in raw_domains
                if not any(d in email or d in url for email in emails for url in urls)
            )
        )

        md5s = list(set(self.MD5_REGEX.findall(text)))
        sha1s = list(set(self.SHA1_REGEX.findall(text)))
        sha256s = list(set(self.SHA256_REGEX.findall(text)))

        filenames = list(set(self.FILENAME_REGEX.findall(text)))
        registry_keys = list(set(self.REGISTRY_REGEX.findall(text)))
        mutexes = list(set(self.MUTEX_REGEX.findall(text)))

        return {
            "ips": sorted(ips),
            "emails": sorted(emails),
            "domains": sorted(domains),
            "urls": sorted(urls),
            "hashes": sorted(md5s + sha1s + sha256s),
            "filenames": sorted(filenames),
            "registry_keys": sorted(registry_keys),
            "mutexes": sorted(mutexes),
        }
