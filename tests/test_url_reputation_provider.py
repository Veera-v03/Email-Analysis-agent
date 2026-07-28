"""Regression tests for Milestone 4.9 reputation provider abstractions."""

from __future__ import annotations

from src.analyzers.url.reputation import (
    NullReputationProvider,
    NullReputationResult,
    UrlReputationProvider,
)
from src.models.url import ParsedUrlComponents


class StubProvider:
    name = "stub"

    def query(self, components: ParsedUrlComponents) -> NullReputationResult:
        return NullReputationResult()


def test_null_provider_satisfies_protocol() -> None:
    provider = NullReputationProvider()

    assert isinstance(provider, UrlReputationProvider)


def test_null_provider_returns_non_querying_result() -> None:
    provider = NullReputationProvider()

    result = provider.query(
        ParsedUrlComponents(scheme="https", host="example.com", is_parseable=True)
    )

    assert result.provider_name == "null"
    assert result.queried is False
    assert result.available is False


def test_stub_provider_conforms_to_protocol() -> None:
    provider = StubProvider()

    assert isinstance(provider, UrlReputationProvider)
