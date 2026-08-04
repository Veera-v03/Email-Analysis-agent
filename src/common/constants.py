"""Global constants and enumeration types for ScamON Enterprise."""

from __future__ import annotations

from enum import StrEnum


class SystemEnvironment(StrEnum):
    """Execution deployment environment."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TEST = "test"


class LogFormat(StrEnum):
    """Logging output encoding format."""

    JSON = "json"
    CONSOLE = "console"


class Verdict(StrEnum):
    """Final email incident threat verdict classification."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class ThreatCategory(StrEnum):
    """Identified email attack categories."""

    BEC = "BEC"
    PHISHING = "PHISHING"
    QUISHING = "QUISHING"
    MALWARE = "MALWARE"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    RANSOMWARE = "RANSOMWARE"
    SPAM = "SPAM"
    UNKNOWN = "UNKNOWN"


class ActionTaken(StrEnum):
    """Enforced security policy remediation action."""

    DELIVERED = "DELIVERED"
    QUARANTINED = "QUARANTINED"
    RETRACTED = "RETRACTED"
    BANNER_INJECTED = "BANNER_INJECTED"
    BLOCKED = "BLOCKED"
    PENDING = "PENDING"


class SPFResult(StrEnum):
    """SPF authentication evaluation result."""

    PASS = "PASS"
    FAIL = "FAIL"
    SOFTFAIL = "SOFTFAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"


class DKIMResult(StrEnum):
    """DKIM authentication evaluation result."""

    PASS = "PASS"
    FAIL = "FAIL"
    NONE = "NONE"


class DMARCResult(StrEnum):
    """DMARC authentication evaluation result."""

    PASS = "PASS"
    FAIL = "FAIL"
    NONE = "NONE"


class ARCResult(StrEnum):
    """ARC chain validation result."""

    PASS = "PASS"
    FAIL = "FAIL"
    NONE = "NONE"


# Pipeline Performance SLA Constants (ms) - SAS v1.1.0 Section 4
SLA_INGESTION_MAX_MS: int = 100
SLA_MIME_PARSER_MAX_MS: int = 250
SLA_HEADER_ANALYZER_MAX_MS: int = 50
SLA_AUTH_VERIFICATION_MAX_MS: int = 500
SLA_DOMAIN_REPUTATION_MAX_MS: int = 80
SLA_URL_INTELLIGENCE_MAX_MS: int = 1500
SLA_ATTACHMENT_SCANNER_MAX_MS: int = 1000
SLA_OCR_ENGINE_MAX_MS: int = 800
SLA_NLP_INTENT_MAX_MS: int = 150
SLA_LLM_REASONING_MAX_MS: int = 5000
SLA_RISK_ENGINE_MAX_MS: int = 100
SLA_PIPELINE_STANDARD_MAX_MS: int = 2000
SLA_PIPELINE_LLM_MAX_MS: int = 7000
