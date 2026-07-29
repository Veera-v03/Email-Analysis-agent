"""Deterministic comparison of sender-related address headers.

The comparator produces operational evidence only. Different mailbox values can
be legitimate, so this module intentionally makes no security classification.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable

from src.models.sender import ParsedEmailAddress, SenderAnalysisResult
from src.models.sender_consistency import (
    HeaderComparisonPair,
    HeaderMismatchEvidence,
    HeaderMismatchType,
    InvalidHeaderAddressEvidence,
    SenderHeaderComparisonResult,
    SenderHeaderName,
    UnexpectedHeaderCombination,
)

HeaderAddresses = tuple[ParsedEmailAddress, ...]


@runtime_checkable
class SenderHeaderComparator(Protocol):
    """Compare sender-related headers and produce structured evidence."""

    def compare(
        self, sender_data: SenderAnalysisResult
    ) -> SenderHeaderComparisonResult:
        """Compare header evidence without assigning a final risk value."""


class DeterministicSenderHeaderComparator:
    """Compare From, Sender, Reply-To, and Return-Path header address sets."""

    def compare(
        self, sender_data: SenderAnalysisResult
    ) -> SenderHeaderComparisonResult:
        """Return missing, invalid, divergent, and unusual-header evidence."""
        header_addresses = self._header_addresses(sender_data)
        missing_headers = tuple(
            header_name
            for header_name, addresses in header_addresses.items()
            if not addresses
        )
        invalid_evidence = tuple(
            evidence
            for header_name, addresses in header_addresses.items()
            if (evidence := self._invalid_address_evidence(header_name, addresses))
            is not None
        )

        return SenderHeaderComparisonResult(
            missing_headers=missing_headers,
            invalid_header_addresses=invalid_evidence,
            mismatches=self._mismatches(header_addresses),
            unexpected_combinations=self._unexpected_combinations(header_addresses),
        )

    @staticmethod
    def _header_addresses(
        sender_data: SenderAnalysisResult,
    ) -> dict[SenderHeaderName, HeaderAddresses]:
        """Map each compared header to its extracted address evidence."""
        return {
            SenderHeaderName.FROM: sender_data.from_addresses,
            SenderHeaderName.SENDER: sender_data.sender_addresses,
            SenderHeaderName.REPLY_TO: sender_data.reply_to_addresses,
            SenderHeaderName.RETURN_PATH: sender_data.return_path_addresses,
        }

    @staticmethod
    def _invalid_address_evidence(
        header_name: SenderHeaderName,
        addresses: HeaderAddresses,
    ) -> InvalidHeaderAddressEvidence | None:
        """Return invalid raw values for a present header, when any exist."""
        raw_values = tuple(
            address.raw_value
            for address in addresses
            if not address.is_syntactically_valid
        )
        if not raw_values:
            return None
        return InvalidHeaderAddressEvidence(header=header_name, raw_values=raw_values)

    def _mismatches(
        self,
        header_addresses: dict[SenderHeaderName, HeaderAddresses],
    ) -> tuple[HeaderMismatchEvidence, ...]:
        """Compare every required header pair when both have valid addresses."""
        comparisons: tuple[
            tuple[HeaderComparisonPair, SenderHeaderName, SenderHeaderName], ...
        ] = (
            (
                HeaderComparisonPair.FROM_TO_SENDER,
                SenderHeaderName.FROM,
                SenderHeaderName.SENDER,
            ),
            (
                HeaderComparisonPair.FROM_TO_REPLY_TO,
                SenderHeaderName.FROM,
                SenderHeaderName.REPLY_TO,
            ),
            (
                HeaderComparisonPair.FROM_TO_RETURN_PATH,
                SenderHeaderName.FROM,
                SenderHeaderName.RETURN_PATH,
            ),
        )
        evidence: list[HeaderMismatchEvidence] = []
        for comparison, left_header, right_header in comparisons:
            evidence.extend(
                self._compare_pair(
                    comparison,
                    left_header,
                    right_header,
                    header_addresses[left_header],
                    header_addresses[right_header],
                )
            )
        return tuple(evidence)

    def _compare_pair(
        self,
        comparison: HeaderComparisonPair,
        left_header: SenderHeaderName,
        right_header: SenderHeaderName,
        left_addresses: HeaderAddresses,
        right_addresses: HeaderAddresses,
    ) -> tuple[HeaderMismatchEvidence, ...]:
        """Generate mailbox and domain mismatch evidence for one header pair."""
        left_emails = self._values(left_addresses, lambda address: address.email)
        right_emails = self._values(right_addresses, lambda address: address.email)
        if not left_emails or not right_emails:
            return ()

        evidence: list[HeaderMismatchEvidence] = []
        if not set(left_emails).intersection(right_emails):
            evidence.append(
                HeaderMismatchEvidence(
                    comparison=comparison,
                    mismatch_type=HeaderMismatchType.EMAIL_ADDRESS,
                    left_header=left_header,
                    right_header=right_header,
                    left_values=left_emails,
                    right_values=right_emails,
                )
            )

        left_domains = self._values(left_addresses, lambda address: address.domain)
        right_domains = self._values(right_addresses, lambda address: address.domain)
        if (
            left_domains
            and right_domains
            and not set(left_domains).intersection(right_domains)
        ):
            evidence.append(
                HeaderMismatchEvidence(
                    comparison=comparison,
                    mismatch_type=HeaderMismatchType.DOMAIN,
                    left_header=left_header,
                    right_header=right_header,
                    left_values=left_domains,
                    right_values=right_domains,
                )
            )
        return tuple(evidence)

    @staticmethod
    def _values(
        addresses: HeaderAddresses,
        value_getter: Callable[[ParsedEmailAddress], str | None],
    ) -> tuple[str, ...]:
        """Return stable, de-duplicated valid evidence values for comparison."""
        values: list[str] = []
        for address in addresses:
            value = value_getter(address)
            if (
                address.is_syntactically_valid
                and value
                and value.casefold() not in values
            ):
                values.append(value.casefold())
        return tuple(values)

    @staticmethod
    def _unexpected_combinations(
        header_addresses: dict[SenderHeaderName, HeaderAddresses],
    ) -> tuple[UnexpectedHeaderCombination, ...]:
        """Return unusual but non-judgmental sender-header arrangements."""
        from_addresses = header_addresses[SenderHeaderName.FROM]
        sender_addresses = header_addresses[SenderHeaderName.SENDER]
        reply_to_addresses = header_addresses[SenderHeaderName.REPLY_TO]
        return_path_addresses = header_addresses[SenderHeaderName.RETURN_PATH]

        combinations: list[UnexpectedHeaderCombination] = []
        if sender_addresses and not from_addresses:
            combinations.append(UnexpectedHeaderCombination.SENDER_WITHOUT_FROM)
        if reply_to_addresses and not from_addresses:
            combinations.append(UnexpectedHeaderCombination.REPLY_TO_WITHOUT_FROM)
        if return_path_addresses and not from_addresses:
            combinations.append(UnexpectedHeaderCombination.RETURN_PATH_WITHOUT_FROM)
        if len(from_addresses) > 1 and not sender_addresses:
            combinations.append(
                UnexpectedHeaderCombination.MULTIPLE_FROM_WITHOUT_SENDER
            )
        if len(sender_addresses) > 1:
            combinations.append(UnexpectedHeaderCombination.MULTIPLE_SENDER_VALUES)
        if len(return_path_addresses) > 1:
            combinations.append(UnexpectedHeaderCombination.MULTIPLE_RETURN_PATH_VALUES)
        return tuple(combinations)
