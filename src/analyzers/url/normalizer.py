"""Deterministic URL normalization for Phase 4 URL intelligence.

``CanonicalUrlNormalizer`` implements the ``UrlNormalizer`` protocol and
applies eight normalization steps in a fixed order:

1. Scheme lowercasing
2. Host (authority) lowercasing
3. Default-port removal  (80 for http, 443 for https, 21 for ftp)
4. Path percent-encoding normalization  (decode unreserved chars, uppercase
   remaining escape sequences)
5. Dot-segment resolution  (collapse ``/./`` and ``/../`` in the path)
6. Fragment removal  (fragments are not meaningful for link analysis)
7. Trailing-slash normalization  (remove trailing slash from bare-host paths)
8. Unicode host normalization  (IDNA-encode non-ASCII labels; NFC-normalize
   the path and query)

Each step that changes the URL appends a short action string to the audit
trail so callers can reconstruct exactly what was done.

The normalizer is purely textual.  No DNS resolution, no HTTP requests, no
redirect following.  It never raises; malformed inputs return an invalid
result with ``is_valid=False`` and an empty ``normalized_value``.
"""

from __future__ import annotations

import unicodedata
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from src.models.url import MAX_NORMALIZED_URL_LENGTH, NormalizedUrl

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default ports that should be removed from the authority component.
_DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
    "ftp": 21,
}

# RFC 3986 §2.3 unreserved characters — safe to decode from percent-encoding.
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

# Characters that must remain percent-encoded in the path (RFC 3986 §3.3).
# We re-encode everything except unreserved chars and the path delimiters
# that are safe to leave decoded.
_PATH_SAFE = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "-._~"  # unreserved
    ":@!$&'()*+,;="  # sub-delimiters + pchar extras
    "/"  # path separator
)

_QUERY_SAFE = _PATH_SAFE + "?"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalize_percent_encoding(value: str, safe: str) -> tuple[str, bool]:
    """Decode unreserved percent-encoded chars; uppercase remaining escapes.

    Returns the normalized string and a boolean indicating whether any
    change was made.
    """
    # First decode everything that is safe to decode (unreserved chars).
    decoded = unquote(value, encoding="utf-8", errors="replace")
    # Re-encode to ensure only safe characters remain unencoded and all
    # escape sequences use uppercase hex digits.
    reencoded = quote(decoded, safe=safe, encoding="utf-8", errors="replace")
    return reencoded, reencoded != value


def _resolve_dot_segments(path: str) -> tuple[str, bool]:
    """Resolve '.' and '..' segments in a URL path (RFC 3986 §5.2.4)."""
    if "/./" not in path and "/../" not in path and not path.endswith(("/.", "/..")):
        return path, False

    segments = path.split("/")
    resolved: list[str] = []
    for seg in segments:
        if seg == ".":
            # Current directory — skip
            continue
        if seg == "..":
            # Parent directory — pop last segment if possible
            if resolved and resolved[-1] != "":
                resolved.pop()
        else:
            resolved.append(seg)

    result = "/".join(resolved)
    # Preserve leading slash
    if path.startswith("/") and not result.startswith("/"):
        result = "/" + result
    return result, result != path


def _idna_encode_host(host: str) -> tuple[str, bool]:
    """IDNA-encode a hostname that contains non-ASCII labels.

    Returns the encoded host and whether any change was made.
    Falls back to the original host if encoding fails.
    """
    if host.isascii():
        return host, False
    try:
        encoded = host.encode("idna").decode("ascii")
        return encoded, encoded != host
    except (UnicodeError, UnicodeDecodeError):
        return host, False


def _nfc_normalize(value: str) -> tuple[str, bool]:
    """Apply Unicode NFC normalization to a string."""
    normalized = unicodedata.normalize("NFC", value)
    return normalized, normalized != value


# ---------------------------------------------------------------------------
# Public normalizer
# ---------------------------------------------------------------------------


class CanonicalUrlNormalizer:
    """Normalize a raw URL string into its deterministic canonical form.

    Implements the ``UrlNormalizer`` protocol.  All eight normalization steps
    are applied in a fixed order.  Each step that modifies the URL appends a
    short action label to the audit trail.

    The normalizer is stateless and thread-safe.  Construct once and reuse.
    """

    def normalize(self, raw_url: str) -> NormalizedUrl:
        """Return the canonical form of a raw URL string.

        Args:
            raw_url: Exact URL text as extracted from the email.  May be
                empty, malformed, or contain non-ASCII characters.

        Returns:
            ``NormalizedUrl`` with ``is_valid=True`` and a populated
            ``normalized_value`` when normalization succeeds.  Returns
            ``is_valid=False`` with ``normalized_value=None`` when the
            input cannot be parsed into a recognizable URL structure.
        """
        if not raw_url or not raw_url.strip():
            safe = raw_url[:MAX_NORMALIZED_URL_LENGTH]
            return NormalizedUrl(raw_value=safe, is_valid=False)

        # Guard: raw_value field has a max-length constraint in the model.
        # Truncate only for storage in the invalid-result path; the full
        # string is still used for normalization attempts.
        safe_raw = raw_url[:MAX_NORMALIZED_URL_LENGTH]

        try:
            return self._apply(raw_url, safe_raw)
        except Exception:  # noqa: BLE001
            return NormalizedUrl(raw_value=safe_raw, is_valid=False)

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    def _apply(self, raw_url: str, safe_raw: str) -> NormalizedUrl:
        actions: list[str] = []

        # Parse into components.  urlsplit tolerates many malformed inputs.
        parsed = urlsplit(raw_url)

        # A URL must have a non-empty scheme to be considered valid here.
        # Bare www. URLs have no scheme — treat them as http for normalization.
        scheme = parsed.scheme
        if not scheme:
            if raw_url.lower().startswith("www."):
                raw_url = "http://" + raw_url
                safe_raw = raw_url[:MAX_NORMALIZED_URL_LENGTH]
                parsed = urlsplit(raw_url)
                scheme = "http"
                actions.append("scheme_added")
            else:
                return NormalizedUrl(raw_value=safe_raw, is_valid=False)

        # ----------------------------------------------------------------
        # Step 1 — Scheme lowercasing
        # Compare against the original raw text to detect mixed-case schemes
        # because urlsplit() already returns scheme in lowercase.
        # ----------------------------------------------------------------
        original_scheme_in_raw = raw_url.split(":", 1)[0] if ":" in raw_url else ""
        lower_scheme = scheme.lower()
        if original_scheme_in_raw != original_scheme_in_raw.lower():
            actions.append("scheme_lowercased")
        scheme = lower_scheme

        # ----------------------------------------------------------------
        # Step 2 — Host lowercasing
        # urlsplit().hostname lowercases automatically; extract the raw host
        # from netloc to detect whether the original had uppercase letters.
        # ----------------------------------------------------------------
        raw_netloc = parsed.netloc  # preserves original case
        host = parsed.hostname or ""  # already lowercased by urlsplit
        port = parsed.port
        userinfo = ""
        if parsed.username is not None:
            userinfo = parsed.username
            if parsed.password is not None:
                userinfo += ":" + parsed.password
            userinfo += "@"

        # Derive the raw host (before lowercasing) from netloc.
        raw_host_part = raw_netloc
        if userinfo:
            raw_host_part = raw_netloc.split("@", 1)[-1]
        if ":" in raw_host_part:
            raw_host_part = raw_host_part.rsplit(":", 1)[0]

        if raw_host_part != raw_host_part.lower():
            actions.append("host_lowercased")
        # host is already lowercase from parsed.hostname

        # ----------------------------------------------------------------
        # Step 3 — Default-port removal
        # ----------------------------------------------------------------
        if port is not None and _DEFAULT_PORTS.get(scheme) == port:
            port = None
            actions.append("default_port_removed")

        # ----------------------------------------------------------------
        # Step 4 — Path percent-encoding normalization
        # ----------------------------------------------------------------
        path = parsed.path
        normalized_path, path_changed = _normalize_percent_encoding(
            path, safe=_PATH_SAFE
        )
        if path_changed:
            actions.append("path_encoding_normalized")
        path = normalized_path

        # ----------------------------------------------------------------
        # Step 5 — Dot-segment resolution
        # ----------------------------------------------------------------
        resolved_path, path_resolved = _resolve_dot_segments(path)
        if path_resolved:
            actions.append("dot_segments_resolved")
        path = resolved_path

        # ----------------------------------------------------------------
        # Step 6 — Fragment removal
        # ----------------------------------------------------------------
        fragment = parsed.fragment
        if fragment:
            actions.append("fragment_removed")
        # Fragment is dropped — not included in the reconstructed URL.

        # ----------------------------------------------------------------
        # Step 7 — Trailing-slash normalization
        # ----------------------------------------------------------------
        # Remove a trailing slash only when the path is exactly "/" (bare
        # host with no real path).  Preserve trailing slashes on real paths
        # like "/path/" because they may be semantically significant.
        if path == "/" and scheme in ("http", "https", "ftp"):
            path = ""
            actions.append("trailing_slash_removed")

        # ----------------------------------------------------------------
        # Step 8 — Unicode host normalization (IDNA) + NFC path/query
        # ----------------------------------------------------------------
        idna_host, host_idna_changed = _idna_encode_host(host)
        if host_idna_changed:
            actions.append("host_idna_encoded")
        host = idna_host

        query = parsed.query
        nfc_path, path_nfc = _nfc_normalize(path)
        if path_nfc:
            actions.append("path_nfc_normalized")
        path = nfc_path

        nfc_query, query_nfc = _nfc_normalize(query)
        if query_nfc:
            actions.append("query_nfc_normalized")
        query = nfc_query

        # ----------------------------------------------------------------
        # Reconstruct netloc
        # ----------------------------------------------------------------
        if port is not None:
            new_netloc = f"{userinfo}{host}:{port}"
        else:
            new_netloc = f"{userinfo}{host}"

        # ----------------------------------------------------------------
        # Reassemble
        # ----------------------------------------------------------------
        normalized = urlunsplit((scheme, new_netloc, path, query, ""))

        # Guard against the result exceeding the model's length constraint.
        if len(normalized) > MAX_NORMALIZED_URL_LENGTH:
            return NormalizedUrl(raw_value=safe_raw, is_valid=False)

        return NormalizedUrl(
            raw_value=safe_raw,
            normalized_value=normalized,
            is_valid=True,
            actions=tuple(actions),
        )
