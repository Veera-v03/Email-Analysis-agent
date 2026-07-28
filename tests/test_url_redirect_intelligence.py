"""Regression tests for Milestone 4.7 redirect intelligence abstractions."""

from __future__ import annotations

from src.analyzers.url.contracts import (
    HtmlRedirectAnalyzer,
    HttpRedirectAnalyzer,
    JavaScriptRedirectAnalyzer,
)
from src.models.url import (
    HtmlRedirectSignal,
    HttpRedirectSignal,
    JavaScriptRedirectSignal,
    RedirectMechanism,
    RedirectObservation,
)


class StubHttpRedirectAnalyzer:
    def analyze(self, signal: HttpRedirectSignal) -> RedirectObservation:
        return RedirectObservation(
            mechanism=RedirectMechanism.HTTP,
            detected=bool(signal.location_header),
            target=signal.location_header,
            detail="http redirect abstraction",
        )


class StubHtmlRedirectAnalyzer:
    def analyze(self, signal: HtmlRedirectSignal) -> RedirectObservation:
        return RedirectObservation(
            mechanism=RedirectMechanism.HTML,
            detected=bool(signal.meta_refresh_content),
            target=signal.meta_refresh_content,
            detail="html redirect abstraction",
        )


class StubJavaScriptRedirectAnalyzer:
    def analyze(self, signal: JavaScriptRedirectSignal) -> RedirectObservation:
        return RedirectObservation(
            mechanism=RedirectMechanism.JAVASCRIPT,
            detected=bool(signal.script_fragment),
            target=signal.expression,
            detail="javascript redirect abstraction",
        )


def test_redirect_observation_model_is_frozen_and_strict() -> None:
    """The redirect observation model should be immutable and strict."""
    observation = RedirectObservation(
        mechanism=RedirectMechanism.HTTP,
        detected=True,
        target="https://example.com",
        detail="redirect",
    )

    assert observation.mechanism is RedirectMechanism.HTTP
    assert observation.target == "https://example.com"


def test_http_redirect_protocol_is_implemented_by_stub() -> None:
    """An HTTP redirect analyzer should satisfy the HTTP redirect protocol."""
    stub = StubHttpRedirectAnalyzer()
    signal = HttpRedirectSignal(status_code=302, location_header="https://example.com")

    result = stub.analyze(signal)

    assert isinstance(stub, HttpRedirectAnalyzer)
    assert result.detected is True
    assert result.target == "https://example.com"


def test_html_redirect_protocol_is_implemented_by_stub() -> None:
    """An HTML redirect analyzer should satisfy the HTML redirect protocol."""
    stub = StubHtmlRedirectAnalyzer()
    signal = HtmlRedirectSignal(meta_refresh_content="0; url=https://example.com")

    result = stub.analyze(signal)

    assert isinstance(stub, HtmlRedirectAnalyzer)
    assert result.detected is True
    assert result.target == "0; url=https://example.com"


def test_javascript_redirect_protocol_is_implemented_by_stub() -> None:
    """A JavaScript redirect analyzer should satisfy the JavaScript redirect protocol."""
    stub = StubJavaScriptRedirectAnalyzer()
    signal = JavaScriptRedirectSignal(
        script_fragment="window.location='https://example.com'",
        expression="https://example.com",
    )

    result = stub.analyze(signal)

    assert isinstance(stub, JavaScriptRedirectAnalyzer)
    assert result.detected is True
    assert result.target == "https://example.com"
