"""Authentication Verification Package (SPF, DKIM, DMARC, ARC) for ScamON Enterprise."""

from __future__ import annotations

from src.authentication.engine import AuthenticationVerificationEngine
from src.authentication.exceptions import (
    ArcValidationError,
    AuthenticationVerificationError,
    DkimVerificationError,
    DmarcEvaluationError,
    SpfEvaluationError,
)
from src.authentication.models import (
    ARCChainResultDTO,
    AuthenticationVerification,
    DKIMSignatureResultDTO,
    DMARCResultDTO,
    SPFResultDTO,
)
from src.authentication.module import (
    AuthenticationModule,
    register_authentication_module,
)
from src.authentication.pipeline import AuthenticationPipeline

__all__ = [
    "ARCChainResultDTO",
    "ArcValidationError",
    "AuthenticationModule",
    "AuthenticationPipeline",
    "AuthenticationVerification",
    "AuthenticationVerificationEngine",
    "AuthenticationVerificationError",
    "DKIMSignatureResultDTO",
    "DMARCResultDTO",
    "DkimVerificationError",
    "DmarcEvaluationError",
    "SPFResultDTO",
    "SpfEvaluationError",
    "register_authentication_module",
]
