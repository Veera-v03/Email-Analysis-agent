"""Regression tests for Milestone 4.8 structural URL anomaly detection."""

from __future__ import annotations

from src.analyzers.url.anomalies import StructuralUrlAnomalyAnalyzer
from src.models.url import ParsedUrlComponents, SuspiciousPatternCategory


def _components(**overrides: object) -> ParsedUrlComponents:
    defaults = {
        "scheme": "https",
        "host": "example.com",
        "path": "/page",
        "is_parseable": True,
    }
    defaults.update(overrides)
    return ParsedUrlComponents(**defaults)


def test_detects_ip_address_host() -> None:
    analyzer = StructuralUrlAnomalyAnalyzer()

    matches = analyzer.analyze(_components(host="192.168.0.1"))

    assert any(
        match.category is SuspiciousPatternCategory.IP_ADDRESS_HOST for match in matches
    )


def test_detects_embedded_credentials() -> None:
    analyzer = StructuralUrlAnomalyAnalyzer()

    matches = analyzer.analyze(_components(username="user", password="pass"))

    assert any(
        match.category is SuspiciousPatternCategory.CREDENTIAL_IN_URL
        for match in matches
    )


def test_detects_long_hostname_and_excessive_subdomains() -> None:
    analyzer = StructuralUrlAnomalyAnalyzer()

    matches = analyzer.analyze(
        _components(
            host="a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.example.com",
            subdomain="a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p",
        )
    )

    assert any(
        match.category is SuspiciousPatternCategory.EXCESSIVE_SUBDOMAINS
        for match in matches
    )


def test_detects_long_url_and_encoded_characters() -> None:
    analyzer = StructuralUrlAnomalyAnalyzer()

    long_path = "/" + "segment" * 30
    matches = analyzer.analyze(_components(path=long_path + "%2F"))

    assert any(
        match.category is SuspiciousPatternCategory.LONG_PATH for match in matches
    )
    assert any(
        match.category is SuspiciousPatternCategory.ENCODED_PAYLOAD for match in matches
    )


def test_detects_suspicious_keywords_unusual_ports_and_repeated_separators() -> None:
    analyzer = StructuralUrlAnomalyAnalyzer(suspicious_keywords=("login", "verify"))

    matches = analyzer.analyze(_components(path="/login//verify", port=8443))

    assert any(
        match.category is SuspiciousPatternCategory.ENCODED_PAYLOAD for match in matches
    )
    assert any(
        match.category is SuspiciousPatternCategory.NON_STANDARD_PORT
        for match in matches
    )
