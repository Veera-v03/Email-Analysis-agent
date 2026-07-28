"""Immutable data contracts for Phase 4 URL intelligence.

Every model in this module is consumed by the URL analysis pipeline.
No model performs analysis, makes security decisions, or produces verdicts.
All models use ``extra="forbid"``, ``strict=True``, and ``frozen=True``.

Length constants are defined at module level so downstream components can
reference them without importing the model classes.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
)

# ---------------------------------------------------------------------------
# Length bounds
# ---------------------------------------------------------------------------

MAX_RAW_URL_LENGTH: int = 8_192
MAX_NORMALIZED_URL_LENGTH: int = 8_192
MAX_SCHEME_LENGTH: int = 32
MAX_HOST_LENGTH: int = 253
MAX_PATH_LENGTH: int = 4_096
MAX_QUERY_LENGTH: int = 4_096
MAX_FRAGMENT_LENGTH: int = 1_024
MAX_PORT_VALUE: int = 65_535
MAX_URL_SOURCE_LENGTH: int = 256
MAX_PATTERN_NAME_LENGTH: int = 128
MAX_SHORTENER_HOST_LENGTH: int = 253
MAX_EXTRACTION_CONTEXT_LENGTH: int = 512


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class UrlScheme(StrEnum):
    """Identify the scheme component of an extracted URL.

    Only schemes that can appear in email body content are represented.
    Unknown or unsupported schemes are captured by ``OTHER``.
    """

    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    MAILTO = "mailto"
    DATA = "data"
    JAVASCRIPT = "javascript"
    OTHER = "other"


class UrlExtractionSource(StrEnum):
    """Identify the email field or HTML context from which a URL was extracted."""

    BODY_TEXT = "body_text"
    SUBJECT = "subject"
    HEADER_SENDER = "header_sender"
    HEADER_REPLY_TO = "header_reply_to"
    HTML_ANCHOR = "html_anchor"
    HTML_IMAGE = "html_image"
    HTML_FORM = "html_form"
    CSS_URL = "css_url"
    META_REFRESH = "meta_refresh"
    INLINE_STYLE = "inline_style"
    SVG_REFERENCE = "svg_reference"
    JS_STRING = "js_string"


class UrlHostType(StrEnum):
    """Classify the structural type of a URL's host component."""

    DOMAIN = "domain"
    IP_V4 = "ipv4"
    IP_V6 = "ipv6"
    LOCALHOST = "localhost"
    EMPTY = "empty"
    INVALID = "invalid"


class UnicodeScriptCategory(StrEnum):
    """Identify the Unicode script category observed in a URL component.

    Used to flag mixed-script or non-Latin characters without making a
    security judgement about their presence.
    """

    LATIN = "latin"
    CYRILLIC = "cyrillic"
    GREEK = "greek"
    ARABIC = "arabic"
    CJK = "cjk"
    DEVANAGARI = "devanagari"
    OTHER = "other"


class HyperlinkObservationCategory(StrEnum):
    """Categorize a structural observation about an HTML hyperlink.

    Each value describes *what was observed* in the hyperlink's structure or
    relationship between its visible text and its destination.  No value
    implies a risk score or security verdict.
    """

    ANCHOR_TEXT_MISMATCH = "anchor_text_mismatch"
    HIDDEN_URL = "hidden_url"
    JAVASCRIPT_LINK = "javascript_link"
    MAILTO_LINK = "mailto_link"
    TELEPHONE_LINK = "telephone_link"
    EMPTY_HREF = "empty_href"
    IMAGE_HYPERLINK = "image_hyperlink"
    BUTTON_LINK = "button_link"
    META_REFRESH = "meta_refresh"


class SuspiciousPatternCategory(StrEnum):
    """Categorize a deterministic structural observation in a URL.

    Categories describe observable characteristics only. They carry no
    implied risk score or security verdict.
    """

    IP_ADDRESS_HOST = "ip_address_host"
    EXCESSIVE_SUBDOMAINS = "excessive_subdomains"
    LONG_PATH = "long_path"
    LONG_QUERY = "long_query"
    ENCODED_PAYLOAD = "encoded_payload"
    MULTIPLE_AT_SIGNS = "multiple_at_signs"
    CREDENTIAL_IN_URL = "credential_in_url"
    JAVASCRIPT_SCHEME = "javascript_scheme"
    DATA_SCHEME = "data_scheme"
    NON_STANDARD_PORT = "non_standard_port"
    HOMOGLYPH_CANDIDATE = "homoglyph_candidate"
    MIXED_UNICODE_SCRIPTS = "mixed_unicode_scripts"
    PUNYCODE_HOST = "punycode_host"
    KNOWN_SHORTENER = "known_shortener"
    DOUBLE_EXTENSION = "double_extension"
    EXCESSIVE_DOTS = "excessive_dots"
    HEX_ENCODED_HOST = "hex_encoded_host"


# ---------------------------------------------------------------------------
# Extracted URL — raw evidence before any analysis
# ---------------------------------------------------------------------------


class RedirectMechanism(StrEnum):
    """Identify the mechanism by which a redirect was observed."""

    HTTP = "http"
    HTML = "html"
    JAVASCRIPT = "javascript"


class HttpRedirectSignal(BaseModel):
    """Represent an abstract HTTP redirect signal without performing I/O."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    status_code: StrictInt = Field(ge=100, le=599)
    location_header: StrictStr | None = Field(
        default=None, max_length=MAX_RAW_URL_LENGTH
    )


class HtmlRedirectSignal(BaseModel):
    """Represent an abstract HTML redirect signal without performing I/O."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    meta_refresh_content: StrictStr | None = Field(
        default=None, max_length=MAX_RAW_URL_LENGTH
    )


class JavaScriptRedirectSignal(BaseModel):
    """Represent an abstract JavaScript redirect signal without performing I/O."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    script_fragment: StrictStr | None = Field(
        default=None, max_length=MAX_RAW_URL_LENGTH
    )
    expression: StrictStr | None = Field(default=None, max_length=MAX_RAW_URL_LENGTH)


class RedirectObservation(BaseModel):
    """Contain a deterministic redirect observation for later pipeline stages."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    mechanism: RedirectMechanism
    detected: StrictBool = False
    target: StrictStr | None = Field(default=None, max_length=MAX_RAW_URL_LENGTH)
    detail: StrictStr = Field(min_length=1, max_length=MAX_PATTERN_NAME_LENGTH)


class ExtractedUrl(BaseModel):
    """Represent one URL occurrence found in an email field.

    ``raw_value`` preserves the exact text as found. ``source`` identifies
    which email field or HTML context contained the URL. ``position`` is the
    zero-based character offset within the source field, used for provenance.
    ``html_context`` preserves the surrounding HTML tag text when the URL was
    extracted from an HTML attribute, enabling downstream context analysis.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    raw_value: StrictStr = Field(min_length=1, max_length=MAX_RAW_URL_LENGTH)
    source: UrlExtractionSource
    position: StrictInt = Field(ge=0)
    html_context: StrictStr | None = Field(
        default=None, max_length=MAX_EXTRACTION_CONTEXT_LENGTH
    )


# ---------------------------------------------------------------------------
# Parsed URL components
# ---------------------------------------------------------------------------


class ParsedUrlComponents(BaseModel):
    """Contain the structural components of a parsed URL.

    All fields are optional because any component may be absent or
    unparseable. ``is_parseable`` is False when the raw value cannot be
    decomposed into any recognizable structure.

    ``subdomain``, ``registered_domain``, and ``tld`` are populated by
    ``StructuralUrlFeatureExtractor`` using PSL decomposition and are
    available to all downstream pipeline stages.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    scheme: StrictStr | None = Field(default=None, max_length=MAX_SCHEME_LENGTH)
    username: StrictStr | None = Field(default=None, max_length=MAX_HOST_LENGTH)
    password: StrictStr | None = Field(default=None, max_length=MAX_HOST_LENGTH)
    host: StrictStr | None = Field(default=None, max_length=MAX_HOST_LENGTH)
    port: StrictInt | None = Field(default=None, ge=0, le=MAX_PORT_VALUE)
    path: StrictStr | None = Field(default=None, max_length=MAX_PATH_LENGTH)
    query: StrictStr | None = Field(default=None, max_length=MAX_QUERY_LENGTH)
    fragment: StrictStr | None = Field(default=None, max_length=MAX_FRAGMENT_LENGTH)
    is_parseable: StrictBool = False
    subdomain: StrictStr | None = Field(default=None, max_length=MAX_HOST_LENGTH)
    registered_domain: StrictStr | None = Field(
        default=None, max_length=MAX_HOST_LENGTH
    )
    tld: StrictStr | None = Field(default=None, max_length=MAX_HOST_LENGTH)


# ---------------------------------------------------------------------------
# Normalized URL
# ---------------------------------------------------------------------------


class NormalizedUrl(BaseModel):
    """Contain the canonical form of a URL after normalization.

    Normalization covers scheme lowercasing, host lowercasing, default-port
    removal, path percent-encoding normalization, and trailing-slash
    canonicalization. The ``actions`` tuple records every transformation
    applied so the audit trail is preserved.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    raw_value: StrictStr = Field(max_length=MAX_RAW_URL_LENGTH)
    normalized_value: StrictStr | None = Field(
        default=None, max_length=MAX_NORMALIZED_URL_LENGTH
    )
    is_valid: StrictBool = False
    actions: tuple[StrictStr, ...] = Field(default=())


# ---------------------------------------------------------------------------
# Host analysis
# ---------------------------------------------------------------------------


class UrlHostAnalysis(BaseModel):
    """Contain structural observations about the host component of a URL.

    This model records what the host *is*, not what it *means*. No reputation
    data, no risk score, no verdict.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    raw_host: StrictStr | None = Field(default=None, max_length=MAX_HOST_LENGTH)
    host_type: UrlHostType = UrlHostType.EMPTY
    normalized_host: StrictStr | None = Field(default=None, max_length=MAX_HOST_LENGTH)
    registered_domain: StrictStr | None = Field(
        default=None, max_length=MAX_HOST_LENGTH
    )
    effective_tld: StrictStr | None = Field(default=None, max_length=MAX_HOST_LENGTH)
    subdomain: StrictStr | None = Field(default=None, max_length=MAX_HOST_LENGTH)
    subdomain_depth: StrictInt = Field(default=0, ge=0)
    is_ip_address: StrictBool = False
    is_localhost: StrictBool = False
    is_punycode: StrictBool = False
    is_idn: StrictBool = False


# ---------------------------------------------------------------------------
# Unicode analysis
# ---------------------------------------------------------------------------


class UrlUnicodeAnalysis(BaseModel):
    """Contain Unicode-level observations for a URL's components.

    Observations cover script mixing, non-ASCII presence, punycode encoding,
    Unicode normalization form, and confusable character detection.
    No homoglyph resolution is performed — only structural facts are recorded.
    No risk score or security verdict is produced.

    Fields:
        contains_non_ascii: True when any component contains non-ASCII chars.
        contains_punycode: True when the host contains an ``xn--`` ACE label.
        contains_percent_encoded_unicode: True when ``%XX`` sequences decode
            to non-ASCII code points.
        detected_scripts: Ordered tuple of Unicode script categories found
            across all URL components.
        has_mixed_scripts: True when two or more distinct script categories
            are present in the host component.
        has_rtl_characters: True when any RTL Unicode character is present.
        normalization_form: The Unicode normalization form of the host
            (``NFC``, ``NFD``, ``NFKC``, ``NFKD``, or ``NONE`` when the
            host is already ASCII or normalization cannot be determined).
        confusable_characters: Tuple of (original_char, ascii_lookalike)
            pairs for every non-ASCII character in the host that has a
            visually similar ASCII counterpart in the confusable table.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    contains_non_ascii: StrictBool = False
    contains_punycode: StrictBool = False
    contains_percent_encoded_unicode: StrictBool = False
    detected_scripts: tuple[UnicodeScriptCategory, ...] = Field(default=())
    has_mixed_scripts: StrictBool = False
    has_rtl_characters: StrictBool = False
    normalization_form: StrictStr = Field(default="NONE", max_length=8)
    confusable_characters: tuple[tuple[StrictStr, StrictStr], ...] = Field(default=())


# ---------------------------------------------------------------------------
# Structural features
# ---------------------------------------------------------------------------


class UrlStructuralFeatures(BaseModel):
    """Contain deterministic structural measurements of a URL.

    All integer counts and lengths are computed from the URL text alone.
    Ratio fields (``digit_ratio``, ``symbol_ratio``) are in [0.0, 1.0].
    ``entropy_score`` is the Shannon entropy of the full URL string in
    bits per character, bounded to [0.0, 8.0].
    No external lookups, no heuristics, no security verdicts.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    # --- lengths ---
    total_length: StrictInt = Field(ge=0)
    host_length: StrictInt = Field(ge=0)
    path_length: StrictInt = Field(ge=0)
    # --- structural counts ---
    path_depth: StrictInt = Field(ge=0)
    query_parameter_count: StrictInt = Field(ge=0)
    fragment_length: StrictInt = Field(ge=0)
    subdomain_count: StrictInt = Field(ge=0)
    dot_count: StrictInt = Field(ge=0)
    hyphen_count: StrictInt = Field(ge=0)
    digit_count: StrictInt = Field(ge=0)
    at_sign_count: StrictInt = Field(ge=0)
    percent_encoded_count: StrictInt = Field(ge=0)
    # --- boolean flags ---
    has_credentials: StrictBool = False
    has_port: StrictBool = False
    has_fragment: StrictBool = False
    has_query: StrictBool = False
    uses_default_port: StrictBool = False
    path_has_double_extension: StrictBool = False
    # --- ratio / entropy features ---
    digit_ratio: StrictFloat = Field(default=0.0, ge=0.0, le=1.0)
    symbol_ratio: StrictFloat = Field(default=0.0, ge=0.0, le=1.0)
    entropy_score: StrictFloat = Field(default=0.0, ge=0.0, le=8.0)


# ---------------------------------------------------------------------------
# Shortener detection
# ---------------------------------------------------------------------------


class UrlShortenerAnalysis(BaseModel):
    """Record whether a URL's host matches a known shortener service.

    The shortener list is injected at analysis time. This model records
    only the observation — no redirect resolution is performed here.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    is_shortened: StrictBool = False
    matched_shortener_host: StrictStr | None = Field(
        default=None, max_length=MAX_SHORTENER_HOST_LENGTH
    )


# ---------------------------------------------------------------------------
# Suspicious pattern observations
# ---------------------------------------------------------------------------


class SuspiciousPatternMatch(BaseModel):
    """Record one deterministic structural observation about a URL.

    A match describes *what was observed*, not *what it means*. The
    ``category`` field identifies the observation type. ``detail`` provides
    a human-readable description of the specific finding.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    category: SuspiciousPatternCategory
    detail: StrictStr = Field(min_length=1, max_length=MAX_PATTERN_NAME_LENGTH)


# ---------------------------------------------------------------------------
# Hyperlink analysis
# ---------------------------------------------------------------------------


MAX_ANCHOR_TEXT_LENGTH: int = 1_024


class HyperlinkObservation(BaseModel):
    """Record one structural observation about an HTML hyperlink.

    ``category`` identifies the observation type.  ``href`` is the raw
    destination value.  ``anchor_text`` is the visible label when present.
    ``html_context`` preserves the surrounding tag text for provenance.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    category: HyperlinkObservationCategory
    href: StrictStr | None = Field(default=None, max_length=MAX_RAW_URL_LENGTH)
    anchor_text: StrictStr | None = Field(
        default=None, max_length=MAX_ANCHOR_TEXT_LENGTH
    )
    html_context: StrictStr | None = Field(
        default=None, max_length=MAX_EXTRACTION_CONTEXT_LENGTH
    )


class HyperlinkAnalysisResult(BaseModel):
    """Contain all hyperlink observations extracted from one email message.

    ``observations`` holds one ``HyperlinkObservation`` per detected
    characteristic.  Multiple observations may reference the same hyperlink
    when it exhibits more than one notable property.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    observations: tuple[HyperlinkObservation, ...] = Field(default=())


# ---------------------------------------------------------------------------
# Reputation interface placeholder
# ---------------------------------------------------------------------------


class UrlReputationStub(BaseModel):
    """Reserve the reputation slot in the URL intelligence result.

    Phase 4 Milestone 4.1 defines this stub so the unified result contract
    is complete. Concrete reputation providers are introduced in a later
    milestone. The stub carries no data and makes no assessment.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    queried: StrictBool = False


class UrlEvidence(BaseModel):
    """Represent a single deterministic evidence artifact for a URL."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    source: StrictStr = Field(min_length=1, max_length=MAX_PATTERN_NAME_LENGTH)
    detail: StrictStr = Field(min_length=1, max_length=MAX_PATTERN_NAME_LENGTH)
    observed: StrictBool = False


class HtmlContext(BaseModel):
    """Capture structural HTML context surrounding a URL occurrence."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    tag: StrictStr | None = Field(default=None, max_length=MAX_PATTERN_NAME_LENGTH)
    attribute: StrictStr | None = Field(
        default=None, max_length=MAX_PATTERN_NAME_LENGTH
    )
    snippet: StrictStr | None = Field(
        default=None, max_length=MAX_EXTRACTION_CONTEXT_LENGTH
    )


class RedirectResult(BaseModel):
    """Contain a deterministic redirect observation for a URL."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    mechanism: RedirectMechanism
    detected: StrictBool = False
    target: StrictStr | None = Field(default=None, max_length=MAX_RAW_URL_LENGTH)
    detail: StrictStr = Field(min_length=1, max_length=MAX_PATTERN_NAME_LENGTH)


class ReputationResult(BaseModel):
    """Contain a deterministic reputation provider observation for a URL."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    provider_name: StrictStr = Field(min_length=1, max_length=MAX_PATTERN_NAME_LENGTH)
    queried: StrictBool = False
    available: StrictBool = False
    detail: StrictStr = Field(default="not queried", max_length=MAX_PATTERN_NAME_LENGTH)


class FinalUrlIntelligence(BaseModel):
    """Aggregate the full deterministic URL intelligence payload."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    extracted: ExtractedUrl
    components: ParsedUrlComponents = Field(default_factory=ParsedUrlComponents)
    normalized: NormalizedUrl | None = None
    host: UrlHostAnalysis = Field(default_factory=UrlHostAnalysis)
    unicode_analysis: UrlUnicodeAnalysis = Field(default_factory=UrlUnicodeAnalysis)
    structural_features: UrlStructuralFeatures | None = None
    shortener: UrlShortenerAnalysis = Field(default_factory=UrlShortenerAnalysis)
    suspicious_patterns: tuple[SuspiciousPatternMatch, ...] = Field(default=())
    html_context: HtmlContext | None = None
    redirect_result: RedirectResult | None = None
    reputation_result: ReputationResult | None = None
    evidence: tuple[UrlEvidence, ...] = Field(default=())


# ---------------------------------------------------------------------------
# Unified URL intelligence result
# ---------------------------------------------------------------------------


class UrlIntelligenceResult(BaseModel):
    """Compose all Phase 4 URL analysis outputs into one immutable result.

    This is the primary output contract of the Phase 4 pipeline. Every field
    is populated by an independent analyzer stage. No field contains a risk
    score, phishing probability, or security verdict.

    Fields:
        extracted: The raw URL occurrence as found in the email.
        components: Parsed structural components of the URL.
        normalized: Canonical form after normalization.
        host: Structural host observations.
        unicode_analysis: Unicode-level observations.
        structural_features: Deterministic structural measurements.
        shortener: Shortener-service detection result.
        suspicious_patterns: All deterministic structural observations.
        reputation: Reserved reputation slot (stub in Milestone 4.1).
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    extracted: ExtractedUrl
    components: ParsedUrlComponents = Field(default_factory=ParsedUrlComponents)
    normalized: NormalizedUrl | None = None
    host: UrlHostAnalysis = Field(default_factory=UrlHostAnalysis)
    unicode_analysis: UrlUnicodeAnalysis = Field(default_factory=UrlUnicodeAnalysis)
    structural_features: UrlStructuralFeatures | None = None
    shortener: UrlShortenerAnalysis = Field(default_factory=UrlShortenerAnalysis)
    suspicious_patterns: tuple[SuspiciousPatternMatch, ...] = Field(default=())
    reputation: UrlReputationStub = Field(default_factory=UrlReputationStub)


# ---------------------------------------------------------------------------
# Email-level URL analysis result
# ---------------------------------------------------------------------------


class EmailUrlAnalysisResult(BaseModel):
    """Contain all URL intelligence results for one email message.

    ``urls`` holds one ``UrlIntelligenceResult`` per extracted URL occurrence.
    ``total_urls_found`` records the raw extraction count before any
    deduplication. ``unique_hosts`` records the count of distinct normalized
    host values across all results.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    message_id: StrictStr = Field(min_length=1, max_length=998)
    urls: tuple[UrlIntelligenceResult, ...] = Field(default=())
    total_urls_found: StrictInt = Field(ge=0)
    unique_hosts: StrictInt = Field(ge=0)
