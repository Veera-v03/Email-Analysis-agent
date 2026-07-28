"""Unit tests for deterministic authentication-header interpretation."""

from __future__ import annotations

from src.analyzers.sender.authentication import (
    DeterministicAuthenticationHeaderInterpreter,
)
from src.analyzers.sender.header_sources import MappingHeaderProvider
from src.models.authentication import (
    AuthenticationHeaderSource,
    AuthenticationStatus,
)


def test_interprets_authentication_results_for_all_supported_mechanisms() -> None:
    """Authentication-Results claims are normalized to the closed status enum."""
    headers = MappingHeaderProvider(
        {
            "Authentication-Results": (
                "mx.example; spf=pass smtp.mailfrom=example.com; "
                "dkim=fail header.d=example.net; dmarc=none header.from=example.org; "
                "arc=softfail"
            )
        }
    )

    result = DeterministicAuthenticationHeaderInterpreter().interpret(headers)

    assert result.spf.status is AuthenticationStatus.PASS
    assert result.dkim.status is AuthenticationStatus.FAIL
    assert result.dmarc.status is AuthenticationStatus.NONE
    assert result.arc.status is AuthenticationStatus.SOFTFAIL


def test_interprets_received_spf_and_arc_seal_headers() -> None:
    """Mechanism-specific headers supply normalizable SPF and ARC evidence."""
    headers = MappingHeaderProvider(
        {
            "Received-SPF": "softfail (sender SPF record does not designate host)",
            "ARC-Seal": "i=1; a=rsa-sha256; cv=pass; d=example.com",
        }
    )

    result = DeterministicAuthenticationHeaderInterpreter().interpret(headers)

    assert result.spf.status is AuthenticationStatus.SOFTFAIL
    assert result.arc.status is AuthenticationStatus.PASS
    assert AuthenticationHeaderSource.RECEIVED_SPF in result.spf.header_sources
    assert AuthenticationHeaderSource.ARC_SEAL in result.arc.header_sources


def test_signature_presence_without_result_remains_unknown() -> None:
    """A signature header alone is evidence of presence, not validation success."""
    headers = MappingHeaderProvider(
        {"DKIM-Signature": "v=1; a=rsa-sha256; d=example.com; s=selector"}
    )

    result = DeterministicAuthenticationHeaderInterpreter().interpret(headers)

    assert result.dkim.status is AuthenticationStatus.UNKNOWN
    assert result.dkim.observed_statuses == ()
    assert result.dkim.header_sources == (AuthenticationHeaderSource.DKIM_SIGNATURE,)


def test_conflicting_claims_normalize_to_unknown_and_preserve_observations() -> None:
    """Conflicting header claims are never resolved by arbitrary precedence."""
    headers = MappingHeaderProvider(
        {
            "Authentication-Results": (
                "first.example; dmarc=pass",
                "second.example; dmarc=fail",
            )
        }
    )

    result = DeterministicAuthenticationHeaderInterpreter().interpret(headers)

    assert result.dmarc.status is AuthenticationStatus.UNKNOWN
    assert result.dmarc.observed_statuses == (
        AuthenticationStatus.PASS,
        AuthenticationStatus.FAIL,
    )


def test_missing_headers_return_unknown_statuses_without_failure() -> None:
    """Absent authentication evidence is represented as unknown, not as failure."""
    result = DeterministicAuthenticationHeaderInterpreter().interpret(
        MappingHeaderProvider({})
    )

    assert result.spf.status is AuthenticationStatus.UNKNOWN
    assert result.dkim.status is AuthenticationStatus.UNKNOWN
    assert result.dmarc.status is AuthenticationStatus.UNKNOWN
    assert result.arc.status is AuthenticationStatus.UNKNOWN
