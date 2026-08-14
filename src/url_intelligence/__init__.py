"""URL & Sandbox Intelligence Package for ScamON Enterprise."""

from __future__ import annotations

from src.url_intelligence.engine import URLIntelligenceEngine
from src.url_intelligence.exceptions import (
    RedirectLoopError,
    SSRFViolationError,
    URLIntelligenceError,
)
from src.url_intelligence.models import (
    URLAnalysisResult,
    URLRedirectChainDTO,
    URLRedirectHopDTO,
    URLSandboxResultDTO,
)
from src.url_intelligence.module import URLIntelligenceModule, register_url_module
from src.url_intelligence.pipeline import URLIntelligencePipeline
from src.url_intelligence.redirect_expander import RedirectExpander
from src.url_intelligence.sandbox_engine import PlaywrightSandboxEngine
from src.url_intelligence.ssrf_validator import SSRFValidator

__all__ = [
    "PlaywrightSandboxEngine",
    "RedirectExpander",
    "RedirectLoopError",
    "SSRFValidator",
    "SSRFViolationError",
    "URLAnalysisResult",
    "URLIntelligenceEngine",
    "URLIntelligenceError",
    "URLIntelligenceModule",
    "URLIntelligencePipeline",
    "URLRedirectChainDTO",
    "URLRedirectHopDTO",
    "URLSandboxResultDTO",
    "register_url_module",
]
