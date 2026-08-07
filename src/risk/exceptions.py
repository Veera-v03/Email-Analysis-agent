"""Risk Assessment Module exception hierarchy for ScamON Enterprise."""

from __future__ import annotations

from typing import Any

from src.common.exceptions import ScamONError


class RiskAssessmentError(ScamONError):
    """Base exception for all Risk Assessment Engine errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_RISK_ASSESSMENT_FAILED",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class FeatureExtractionError(RiskAssessmentError):
    """Raised when risk feature extraction or normalization fails."""

    def __init__(
        self,
        message: str = "Feature extraction failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_FEATURE_EXTRACTION_FAILED",
            status_code=422,
            details=details,
        )


class ScoringError(RiskAssessmentError):
    """Raised when risk scoring strategy evaluation encounters errors."""

    def __init__(
        self,
        message: str = "Risk scoring failed",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            error_code="ERR_RISK_SCORING_FAILED",
            status_code=422,
            details=details,
        )
