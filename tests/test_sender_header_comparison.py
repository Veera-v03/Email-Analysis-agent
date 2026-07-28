"""Unit tests for sender-header consistency comparison."""

from __future__ import annotations

from src.analyzers.sender.header_comparison import DeterministicSenderHeaderComparator
from src.models.sender import ParsedEmailAddress, SenderAnalysisResult
from src.models.sender_consistency import (
    HeaderComparisonPair,
    HeaderMismatchType,
    SenderHeaderName,
    UnexpectedHeaderCombination,
)


def _address(email: str) -> ParsedEmailAddress:
    """Create valid parsed address evidence for comparison tests."""
    username, domain = email.split("@")
    return ParsedEmailAddress(
        raw_value=email,
        email=email,
        username=username,
        domain=domain,
        is_syntactically_valid=True,
    )


def test_reports_email_and_domain_mismatches_as_evidence() -> None:
    """Divergent header values create explicit comparison evidence."""
    sender_data = SenderAnalysisResult(
        from_addresses=(_address("notice@example.com"),),
        sender_addresses=(_address("mailer@delivery.example.net"),),
        reply_to_addresses=(_address("help@example.org"),),
        return_path_addresses=(_address("bounce@example.net"),),
    )

    result = DeterministicSenderHeaderComparator().compare(sender_data)

    from_sender = [
        mismatch
        for mismatch in result.mismatches
        if mismatch.comparison is HeaderComparisonPair.FROM_TO_SENDER
    ]
    assert {mismatch.mismatch_type for mismatch in from_sender} == {
        HeaderMismatchType.EMAIL_ADDRESS,
        HeaderMismatchType.DOMAIN,
    }
    assert not result.missing_headers


def test_reports_missing_and_invalid_header_values_separately() -> None:
    """Absent headers and malformed present values remain distinguishable."""
    invalid_reply_to = ParsedEmailAddress(
        raw_value="invalid mailbox",
        is_syntactically_valid=False,
    )
    sender_data = SenderAnalysisResult(
        from_addresses=(_address("sender@example.com"),),
        reply_to_addresses=(invalid_reply_to,),
    )

    result = DeterministicSenderHeaderComparator().compare(sender_data)

    assert set(result.missing_headers) == {
        SenderHeaderName.SENDER,
        SenderHeaderName.RETURN_PATH,
    }
    assert result.invalid_header_addresses[0].header is SenderHeaderName.REPLY_TO
    assert result.invalid_header_addresses[0].raw_values == ("invalid mailbox",)


def test_shared_address_prevents_mismatch_for_a_header_pair() -> None:
    """Overlapping valid mailbox values are not reported as divergent evidence."""
    sender_data = SenderAnalysisResult(
        from_addresses=(_address("sender@example.com"),),
        reply_to_addresses=(
            _address("sender@example.com"),
            _address("help@example.com"),
        ),
    )

    result = DeterministicSenderHeaderComparator().compare(sender_data)

    assert not [
        mismatch
        for mismatch in result.mismatches
        if mismatch.comparison is HeaderComparisonPair.FROM_TO_REPLY_TO
    ]


def test_reports_unexpected_header_combinations_without_a_risk_score() -> None:
    """Unusual structural combinations are retained as categorical evidence."""
    sender_data = SenderAnalysisResult(
        sender_addresses=(_address("sender@example.com"),),
        reply_to_addresses=(_address("reply@example.com"),),
        return_path_addresses=(
            _address("first@example.com"),
            _address("second@example.com"),
        ),
    )

    result = DeterministicSenderHeaderComparator().compare(sender_data)

    assert (
        UnexpectedHeaderCombination.SENDER_WITHOUT_FROM
        in result.unexpected_combinations
    )
    assert (
        UnexpectedHeaderCombination.REPLY_TO_WITHOUT_FROM
        in result.unexpected_combinations
    )
    assert (
        UnexpectedHeaderCombination.RETURN_PATH_WITHOUT_FROM
        in result.unexpected_combinations
    )
    assert (
        UnexpectedHeaderCombination.MULTIPLE_RETURN_PATH_VALUES
        in result.unexpected_combinations
    )
