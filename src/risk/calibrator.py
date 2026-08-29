"""Risk score mathematical calibration engine (Module 23 Phase 2)."""

from __future__ import annotations

import math


class RiskScoreCalibrator:
    """Deterministic mathematical score-to-probability calibration engine.

    NOTE: This calibrator uses a closed-form logistic sigmoid mapping:
        P(Threat | S) = 1.0 / (1.0 + exp(-k * (S - S0)))
    with decision midpoint S0 = 50.0 and temperature factor k = 0.08.

    This is a deterministic mathematical transform bounded to [0.0, 1.0].
    It is NOT an empirical Platt-scaling or isotonic regression model learned
    from a labeled validation dataset. Future empirical ML models may extend
    or replace this mathematical mapper.
    """

    DEFAULT_MIDPOINT: float = 50.0
    DEFAULT_TEMPERATURE: float = 0.08

    def __init__(
        self,
        midpoint: float = DEFAULT_MIDPOINT,
        temperature: float = DEFAULT_TEMPERATURE,
    ) -> None:
        if temperature <= 0.0:
            raise ValueError(f"Calibration temperature 'k' must be strictly positive, got {temperature}")
        self.midpoint = float(midpoint)
        self.temperature = float(temperature)

    def calibrate(self, score: float | int) -> float:
        """Map a deterministic risk score S in [0, 100] to a calibrated probability in [0.0, 1.0].

        Raises:
            ValueError: If score is outside the valid range [0, 100].
        """
        if score < 0 or score > 100:
            raise ValueError(f"Risk score must be in range [0, 100], got {score}")

        score_float = float(score)
        # Logistic sigmoid: P = 1 / (1 + e^(-k * (S - S0)))
        exponent = -self.temperature * (score_float - self.midpoint)
        prob = 1.0 / (1.0 + math.exp(exponent))
        return round(prob, 4)

    def calibrate_batch(self, scores: list[float | int]) -> list[float]:
        """Map a batch of deterministic risk scores to calibrated probabilities."""
        return [self.calibrate(s) for s in scores]
