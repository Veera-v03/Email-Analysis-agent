"""Email-authentication header interpretation utilities.

The interpreter normalizes already supplied header claims. It does not perform
SPF evaluation, DKIM cryptographic verification, DMARC policy evaluation, or
ARC chain validation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from src.analyzers.sender.contracts import HeaderProvider
from src.models.authentication import (
    MAX_AUTHENTICATION_HEADER_VALUE_LENGTH,
    AuthenticationAnalysisResult,
    AuthenticationHeaderSource,
    AuthenticationMechanism,
    AuthenticationMechanismResult,
    AuthenticationStatus,
)

AUTHENTICATION_RESULTS_HEADER = "Authentication-Results"
RECEIVED_SPF_HEADER = "Received-SPF"
DKIM_SIGNATURE_HEADER = "DKIM-Signature"
ARC_AUTHENTICATION_RESULTS_HEADER = "ARC-Authentication-Results"
ARC_SEAL_HEADER = "ARC-Seal"
STATUS_PATTERN = re.compile(
    r"(?<![a-z])(?P<mechanism>spf|dkim|dmarc|arc)\s*=\s*(?P<status>[a-z]+)",
    re.IGNORECASE,
)
ARC_CHAIN_VALIDATION_PATTERN = re.compile(
    r"(?<![a-z])cv\s*=\s*(?P<status>[a-z]+)",
    re.IGNORECASE,
)
LEADING_STATUS_PATTERN = re.compile(r"^\s*(?P<status>[a-z]+)", re.IGNORECASE)
STATUS_MAP = {
    "pass": AuthenticationStatus.PASS,
    "fail": AuthenticationStatus.FAIL,
    "softfail": AuthenticationStatus.SOFTFAIL,
    "none": AuthenticationStatus.NONE,
}


@dataclass(frozen=True, slots=True)
class AuthenticationObservation:
    """Represent one normalized status claim and its source header."""

    status: AuthenticationStatus
    source: AuthenticationHeaderSource
    raw_value: str


@runtime_checkable
class AuthenticationHeaderInterpreter(Protocol):
    """Interpret sender authentication headers into structured normalized evidence."""

    def interpret(self, headers: HeaderProvider) -> AuthenticationAnalysisResult:
        """Interpret header claims without performing live authentication checks."""


class DeterministicAuthenticationHeaderInterpreter:
    """Normalize SPF, DKIM, DMARC, ARC, and Authentication-Results header claims."""

    def interpret(self, headers: HeaderProvider) -> AuthenticationAnalysisResult:
        """Return normalized authentication evidence from the supplied headers."""
        authentication_results = headers.get_all(AUTHENTICATION_RESULTS_HEADER)
        observations = self._authentication_results_observations(authentication_results)
        spf_observations = [
            *observations[AuthenticationMechanism.SPF],
            *self._received_spf_observations(headers.get_all(RECEIVED_SPF_HEADER)),
        ]
        dkim_observations = observations[AuthenticationMechanism.DKIM]
        dmarc_observations = observations[AuthenticationMechanism.DMARC]
        arc_observations = [
            *observations[AuthenticationMechanism.ARC],
            *self._arc_seal_observations(headers.get_all(ARC_SEAL_HEADER)),
        ]

        return AuthenticationAnalysisResult(
            spf=self._result(AuthenticationMechanism.SPF, spf_observations),
            dkim=self._result(
                AuthenticationMechanism.DKIM,
                dkim_observations,
                headers.get_all(DKIM_SIGNATURE_HEADER),
                AuthenticationHeaderSource.DKIM_SIGNATURE,
            ),
            dmarc=self._result(AuthenticationMechanism.DMARC, dmarc_observations),
            arc=self._result(
                AuthenticationMechanism.ARC,
                arc_observations,
                headers.get_all(ARC_AUTHENTICATION_RESULTS_HEADER),
                AuthenticationHeaderSource.ARC_AUTHENTICATION_RESULTS,
            ),
            authentication_results=self._bounded_values(authentication_results),
        )

    @staticmethod
    def _authentication_results_observations(
        header_values: tuple[str, ...],
    ) -> dict[AuthenticationMechanism, list[AuthenticationObservation]]:
        """Extract mechanism status claims from Authentication-Results headers."""
        observations: dict[AuthenticationMechanism, list[AuthenticationObservation]] = {
            mechanism: [] for mechanism in AuthenticationMechanism
        }
        for header_value in header_values:
            for match in STATUS_PATTERN.finditer(header_value):
                mechanism = AuthenticationMechanism(match.group("mechanism").casefold())
                observations[mechanism].append(
                    AuthenticationObservation(
                        status=DeterministicAuthenticationHeaderInterpreter._status(
                            match.group("status")
                        ),
                        source=AuthenticationHeaderSource.AUTHENTICATION_RESULTS,
                        raw_value=header_value,
                    )
                )
        return observations

    @staticmethod
    def _received_spf_observations(
        header_values: tuple[str, ...],
    ) -> tuple[AuthenticationObservation, ...]:
        """Extract SPF status claims from Received-SPF headers."""
        observations: list[AuthenticationObservation] = []
        for header_value in header_values:
            match = LEADING_STATUS_PATTERN.search(header_value)
            if match:
                observations.append(
                    AuthenticationObservation(
                        status=DeterministicAuthenticationHeaderInterpreter._status(
                            match.group("status")
                        ),
                        source=AuthenticationHeaderSource.RECEIVED_SPF,
                        raw_value=header_value,
                    )
                )
        return tuple(observations)

    @staticmethod
    def _arc_seal_observations(
        header_values: tuple[str, ...],
    ) -> tuple[AuthenticationObservation, ...]:
        """Extract ARC chain-validation claims from ARC-Seal headers."""
        observations: list[AuthenticationObservation] = []
        for header_value in header_values:
            match = ARC_CHAIN_VALIDATION_PATTERN.search(header_value)
            if match:
                observations.append(
                    AuthenticationObservation(
                        status=DeterministicAuthenticationHeaderInterpreter._status(
                            match.group("status")
                        ),
                        source=AuthenticationHeaderSource.ARC_SEAL,
                        raw_value=header_value,
                    )
                )
        return tuple(observations)

    @staticmethod
    def _status(raw_status: str) -> AuthenticationStatus:
        """Map a header token to the closed normalized status vocabulary."""
        return STATUS_MAP.get(raw_status.casefold(), AuthenticationStatus.UNKNOWN)

    @staticmethod
    def _result(
        mechanism: AuthenticationMechanism,
        observations: list[AuthenticationObservation]
        | tuple[AuthenticationObservation, ...],
        presence_only_values: tuple[str, ...] = (),
        presence_source: AuthenticationHeaderSource | None = None,
    ) -> AuthenticationMechanismResult:
        """Aggregate observed claims while preserving conflict and source evidence."""
        sources: list[AuthenticationHeaderSource] = []
        statuses: list[AuthenticationStatus] = []
        raw_values: list[str] = []
        for observation in observations:
            if observation.source not in sources:
                sources.append(observation.source)
            if observation.status not in statuses:
                statuses.append(observation.status)
            if observation.raw_value not in raw_values:
                raw_values.append(observation.raw_value)

        if presence_only_values and presence_source is not None:
            if presence_source not in sources:
                sources.append(presence_source)
            raw_values.extend(
                value for value in presence_only_values if value not in raw_values
            )

        status = statuses[0] if len(statuses) == 1 else AuthenticationStatus.UNKNOWN
        bounded_raw_values = (
            DeterministicAuthenticationHeaderInterpreter._bounded_values(
                tuple(raw_values)
            )
        )
        return AuthenticationMechanismResult(
            mechanism=mechanism,
            status=status,
            observed_statuses=tuple(statuses),
            header_sources=tuple(sources),
            raw_header_values=bounded_raw_values,
        )

    @staticmethod
    def _bounded_values(values: tuple[str, ...]) -> tuple[str, ...]:
        """Bound retained raw headers before strict model construction."""
        return tuple(value[:MAX_AUTHENTICATION_HEADER_VALUE_LENGTH] for value in values)
