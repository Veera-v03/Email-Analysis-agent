"""URL Intelligence Module exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class URLIntelligenceError(ScamONError):
    """Base exception for all URL & Sandbox Intelligence errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_URL_INTEL_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class SSRFViolationError(URLIntelligenceError):
    """Raised when a URL or redirect target attempts to connect to private/reserved CIDR blocks."""

    def __init__(self, target_ip: str, url: str) -> None:
        super().__init__(
            message=f"SSRF Violation: Target IP '{target_ip}' for URL '{url}' is in a prohibited private/reserved CIDR block.",
            error_code="ERR_SSRF_VIOLATION",
            status_code=403,
            details={"target_ip": target_ip, "url": url},
        )


class RedirectLoopError(URLIntelligenceError):
    """Raised when a URL redirect chain contains a loop or exceeds max hop limits."""

    def __init__(self, url: str, hop_count: int) -> None:
        super().__init__(
            message=f"Redirect Loop/Limit Exceeded: URL '{url}' reached {hop_count} hops.",
            error_code="ERR_REDIRECT_LOOP",
            status_code=400,
            details={"url": url, "hop_count": hop_count},
        )
