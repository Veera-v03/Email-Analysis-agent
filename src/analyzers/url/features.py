"""Deterministic structural feature extraction for Phase 4 URL intelligence.

``StructuralUrlFeatureExtractor`` implements the ``UrlFeatureExtractor``
protocol.  It accepts a ``ParsedUrlComponents`` instance and returns a fully
populated ``UrlStructuralFeatures`` model.

Every feature is computed from the URL components alone — no DNS resolution,
no HTTP requests, no external lookups.  The extractor is stateless and
thread-safe.

Features extracted
------------------
Lengths
    total_length        — character count of the full reconstructed URL
    host_length         — character count of the host component
    path_length         — character count of the path component

Structural counts
    path_depth          — number of non-empty path segments
    query_parameter_count — number of ``&``-separated query parameters
    fragment_length     — character count of the fragment component
    subdomain_count     — number of labels in the subdomain portion
    dot_count           — total ``'.'`` characters in the full URL
    hyphen_count        — total ``'-'`` characters in the full URL
    digit_count         — total ASCII digit characters in the full URL
    at_sign_count       — total ``'@'`` characters in the full URL
    percent_encoded_count — number of ``%XX`` sequences in the full URL

Boolean flags
    has_credentials     — username or password present in authority
    has_port            — explicit port present
    has_fragment        — fragment component present
    has_query           — query string present
    uses_default_port   — port matches the scheme default (80/443/21)
    path_has_double_extension — last two path segments both look like
                          file extensions (e.g. ``.php.jpg``)

Ratio / entropy
    digit_ratio         — digit_count / total_length  (0.0 when length == 0)
    symbol_ratio        — non-alphanumeric, non-space chars / total_length
    entropy_score       — Shannon entropy of the full URL in bits/char
"""

from __future__ import annotations

import math
import re
from urllib.parse import urlunsplit

import tldextract

from src.models.url import (
    ParsedUrlComponents,
    UrlStructuralFeatures,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
    "ftp": 21,
}

# Matches a single percent-encoded sequence: %XX
_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# Characters considered "symbols" for symbol_ratio: anything that is not
# ASCII alphanumeric and not whitespace.
_SYMBOL_RE = re.compile(r"[^A-Za-z0-9\s]")

# A file extension: a dot followed by 1–10 word characters at end of segment.
_EXTENSION_RE = re.compile(r"\.[A-Za-z0-9]{1,10}$")

# URL analysis is deterministic and must not create or lock a user-level cache
# while resolving the Public Suffix List.  Use tldextract's bundled snapshot.
_PUBLIC_SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _reconstruct(components: ParsedUrlComponents) -> str:
    """Reconstruct the full URL string from parsed components for measurement."""
    scheme = components.scheme or ""
    netloc_parts: list[str] = []
    if components.username:
        if components.password:
            netloc_parts.append(
                f"{components.username}:{components.password}@"
            )
        else:
            netloc_parts.append(f"{components.username}@")
    if components.host:
        netloc_parts.append(components.host)
    if components.port is not None:
        netloc_parts.append(f":{components.port}")
    netloc = "".join(netloc_parts)
    path = components.path or ""
    query = components.query or ""
    fragment = components.fragment or ""
    return urlunsplit((scheme, netloc, path, query, fragment))


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of *text* in bits per character.

    Returns 0.0 for empty strings.  Result is in [0.0, log2(256)] ≈ [0, 8].
    """
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _path_depth(path: str | None) -> int:
    """Count non-empty segments in a URL path."""
    if not path:
        return 0
    return sum(1 for seg in path.split("/") if seg)


def _query_param_count(query: str | None) -> int:
    """Count ``&``-separated parameters in a query string."""
    if not query:
        return 0
    return len(query.split("&"))


def _subdomain_count(subdomain: str | None) -> int:
    """Count dot-separated labels in the subdomain portion."""
    if not subdomain:
        return 0
    return len([s for s in subdomain.split(".") if s])


def _has_double_extension(path: str | None) -> bool:
    """Return True when the filename in the path has two stacked extensions."""
    if not path:
        return False
    filename = path.rstrip("/").rsplit("/", 1)[-1]
    # Strip the outermost extension, then check if what remains also ends
    # with an extension.
    without_outer = _EXTENSION_RE.sub("", filename)
    return bool(_EXTENSION_RE.search(without_outer))


# ---------------------------------------------------------------------------
# Public extractor
# ---------------------------------------------------------------------------


class StructuralUrlFeatureExtractor:
    """Extract deterministic structural features from parsed URL components.

    Implements the ``UrlFeatureExtractor`` protocol.  All 19 features are
    computed from the supplied ``ParsedUrlComponents`` without any I/O.

    The extractor is stateless and thread-safe.  Construct once and reuse.
    """

    def extract(self, components: ParsedUrlComponents) -> UrlStructuralFeatures:
        """Return structural feature measurements for the supplied components.

        When ``components.is_parseable`` is False the extractor still returns
        a valid ``UrlStructuralFeatures`` instance with all counts at zero and
        all flags False.

        Args:
            components: Parsed URL components, typically from
                ``CanonicalUrlNormalizer`` followed by ``urlsplit``.

        Returns:
            Fully populated ``UrlStructuralFeatures``.  All counts are
            non-negative.  Ratio fields are in [0.0, 1.0].
            ``entropy_score`` is in [0.0, 8.0].
        """
        full_url = _reconstruct(components)
        total_length = len(full_url)

        host = components.host or ""
        path = components.path or ""
        query = components.query or ""
        fragment = components.fragment or ""
        scheme = (components.scheme or "").lower()

        # --- subdomain via tldextract (uses already-parsed host) -----------
        if host:
            extracted = _PUBLIC_SUFFIX_EXTRACTOR(host)
            subdomain_str: str | None = extracted.subdomain or None
            # Prefer the values already stored on the components if present,
            # otherwise fall back to tldextract.
            if components.subdomain is not None:
                subdomain_str = components.subdomain or None
        else:
            subdomain_str = None

        # --- lengths -------------------------------------------------------
        host_length = len(host)
        path_length = len(path)

        # --- structural counts ---------------------------------------------
        depth = _path_depth(path)
        qcount = _query_param_count(query if query else None)
        frag_len = len(fragment)
        sub_count = _subdomain_count(subdomain_str)
        dot_count = full_url.count(".")
        hyphen_count = full_url.count("-")
        digit_count = sum(1 for ch in full_url if ch.isdigit())
        at_count = full_url.count("@")
        pct_count = len(_PERCENT_RE.findall(full_url))

        # --- boolean flags -------------------------------------------------
        has_creds = bool(components.username or components.password)
        has_port = components.port is not None
        has_frag = bool(fragment)
        has_query = bool(query)
        default_port = _DEFAULT_PORTS.get(scheme)
        uses_default = (
            has_port
            and default_port is not None
            and components.port == default_port
        )
        double_ext = _has_double_extension(path)

        # --- ratio / entropy -----------------------------------------------
        digit_ratio = digit_count / total_length if total_length else 0.0
        symbol_count = len(_SYMBOL_RE.findall(full_url))
        symbol_ratio = symbol_count / total_length if total_length else 0.0
        entropy = _shannon_entropy(full_url)

        return UrlStructuralFeatures(
            total_length=total_length,
            host_length=host_length,
            path_length=path_length,
            path_depth=depth,
            query_parameter_count=qcount,
            fragment_length=frag_len,
            subdomain_count=sub_count,
            dot_count=dot_count,
            hyphen_count=hyphen_count,
            digit_count=digit_count,
            at_sign_count=at_count,
            percent_encoded_count=pct_count,
            has_credentials=has_creds,
            has_port=has_port,
            has_fragment=has_frag,
            has_query=has_query,
            uses_default_port=uses_default,
            path_has_double_extension=double_ext,
            digit_ratio=digit_ratio,
            symbol_ratio=symbol_ratio,
            entropy_score=entropy,
        )
