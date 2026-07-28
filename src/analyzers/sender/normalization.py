"""Reusable canonical email-address normalization utilities.

The component normalizes presentation defects only. It does not perform
provider-specific mailbox transformations, enrichment, or security analysis.
"""

from __future__ import annotations

from email.utils import parseaddr
from typing import Protocol, runtime_checkable

from src.models.email_normalization import (
    MAX_CANONICAL_DOMAIN_LENGTH,
    MAX_CANONICAL_EMAIL_LENGTH,
    MAX_CANONICAL_USERNAME_LENGTH,
    MAX_NORMALIZATION_INPUT_LENGTH,
    AddressNormalizationAction,
    NormalizedEmailAddress,
)

MAILTO_PREFIX = "mailto:"
AT_SEPARATOR = "@"
DOT_SEPARATOR = "."
INVALID_MAILBOX_CHARACTERS = frozenset("<>,;()[]{}\\\"'")


@runtime_checkable
class EmailAddressNormalizer(Protocol):
    """Normalize a raw email-address value into canonical structured evidence."""

    def normalize(self, raw_address: str) -> NormalizedEmailAddress:
        """Return a safe canonical mailbox or an invalid normalization result."""


class CanonicalEmailAddressNormalizer:
    """Normalize standard mailbox syntax without mailbox-provider assumptions."""

    def normalize(self, raw_address: str) -> NormalizedEmailAddress:
        """Normalize an address and preserve invalid input as structured evidence.

        Args:
            raw_address: A single raw mailbox value, optionally with display text.

        Returns:
            Canonical mailbox components when safely recoverable; otherwise an
            invalid result containing only the original bounded input.
        """
        raw_value = self._bounded(raw_address, MAX_NORMALIZATION_INPUT_LENGTH)
        candidate = raw_value
        actions: list[AddressNormalizationAction] = []

        candidate = self._trim_outer_whitespace(candidate, actions)
        candidate = self._remove_mailto_prefix(candidate, actions)
        candidate = self._extract_mailbox(candidate, actions)
        candidate = self._remove_internal_whitespace(candidate, actions)
        candidate = self._collapse_repeated_separators(candidate, actions)

        username, domain = self._split_candidate(candidate)
        if username is None or domain is None:
            return NormalizedEmailAddress(
                raw_value=raw_value,
                is_valid=False,
                actions=tuple(actions),
            )

        normalized_username = username.casefold()
        normalized_domain = self._normalize_domain(domain, actions)
        if normalized_domain is None:
            return NormalizedEmailAddress(
                raw_value=raw_value,
                is_valid=False,
                actions=tuple(actions),
            )

        if normalized_username != username or normalized_domain != domain:
            actions.append(AddressNormalizationAction.CASE_NORMALIZED)

        canonical_email = f"{normalized_username}{AT_SEPARATOR}{normalized_domain}"
        if not self._is_valid_mailbox(
            normalized_username,
            normalized_domain,
            canonical_email,
        ):
            return NormalizedEmailAddress(
                raw_value=raw_value,
                is_valid=False,
                actions=tuple(actions),
            )

        return NormalizedEmailAddress(
            raw_value=raw_value,
            canonical_email=canonical_email,
            username=normalized_username,
            domain=normalized_domain,
            is_valid=True,
            actions=tuple(actions),
        )

    @staticmethod
    def _bounded(value: str, maximum_length: int) -> str:
        """Bound retained raw input before it reaches the output model."""
        return value[:maximum_length]

    @staticmethod
    def _trim_outer_whitespace(
        candidate: str,
        actions: list[AddressNormalizationAction],
    ) -> str:
        """Remove presentation whitespace surrounding a candidate mailbox."""
        trimmed = candidate.strip()
        if trimmed != candidate:
            actions.append(
                AddressNormalizationAction.LEADING_OR_TRAILING_WHITESPACE_REMOVED
            )
        return trimmed

    @staticmethod
    def _extract_mailbox(
        candidate: str,
        actions: list[AddressNormalizationAction],
    ) -> str:
        """Extract a mailbox from a display-name or angle-bracket presentation."""
        opening_bracket = candidate.find("<")
        closing_bracket = candidate.rfind(">")
        if 0 <= opening_bracket < closing_bracket:
            actions.append(AddressNormalizationAction.DISPLAY_WRAPPER_REMOVED)
            return candidate[opening_bracket + 1 : closing_bracket]

        try:
            _, parsed_address = parseaddr(candidate, strict=False)
        except (TypeError, ValueError):
            return candidate

        if parsed_address and parsed_address != candidate:
            actions.append(AddressNormalizationAction.DISPLAY_WRAPPER_REMOVED)
            return parsed_address
        return candidate.removeprefix("<").removesuffix(">")

    @staticmethod
    def _remove_mailto_prefix(
        candidate: str,
        actions: list[AddressNormalizationAction],
    ) -> str:
        """Remove a case-insensitive mailto URI prefix from a mailbox value."""
        if candidate.casefold().startswith(MAILTO_PREFIX):
            actions.append(AddressNormalizationAction.MAILTO_PREFIX_REMOVED)
            return candidate[len(MAILTO_PREFIX) :]
        return candidate

    @staticmethod
    def _remove_internal_whitespace(
        candidate: str,
        actions: list[AddressNormalizationAction],
    ) -> str:
        """Remove invalid whitespace embedded in an unquoted mailbox value."""
        normalized = "".join(candidate.split())
        if normalized != candidate:
            actions.append(AddressNormalizationAction.INTERNAL_WHITESPACE_REMOVED)
        return normalized

    @staticmethod
    def _collapse_repeated_separators(
        candidate: str,
        actions: list[AddressNormalizationAction],
    ) -> str:
        """Collapse repeated mailbox separators produced by formatting defects."""
        collapsed_at = CanonicalEmailAddressNormalizer._collapse_runs(
            candidate,
            AT_SEPARATOR,
        )
        if collapsed_at != candidate:
            actions.append(AddressNormalizationAction.REPEATED_AT_SEPARATOR_COLLAPSED)

        collapsed_dots = CanonicalEmailAddressNormalizer._collapse_runs(
            collapsed_at,
            DOT_SEPARATOR,
        )
        if collapsed_dots != collapsed_at:
            actions.append(AddressNormalizationAction.REPEATED_DOT_SEPARATOR_COLLAPSED)
        return collapsed_dots

    @staticmethod
    def _collapse_runs(value: str, separator: str) -> str:
        """Replace each repeated separator run with one separator."""
        repeated = separator + separator
        while repeated in value:
            value = value.replace(repeated, separator)
        return value

    @staticmethod
    def _split_candidate(candidate: str) -> tuple[str | None, str | None]:
        """Split a candidate only when it contains exactly one at separator."""
        if candidate.count(AT_SEPARATOR) != 1:
            return None, None
        username, domain = candidate.split(AT_SEPARATOR)
        if not username or not domain:
            return None, None
        return username, domain

    @staticmethod
    def _normalize_domain(
        domain: str,
        actions: list[AddressNormalizationAction],
    ) -> str | None:
        """Case-normalize and IDNA-encode a mailbox domain when possible."""
        casefolded_domain = domain.casefold()
        try:
            normalized_domain = casefolded_domain.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if normalized_domain != casefolded_domain:
            actions.append(AddressNormalizationAction.DOMAIN_IDNA_ENCODED)
        return normalized_domain

    @staticmethod
    def _is_valid_mailbox(username: str, domain: str, email: str) -> bool:
        """Apply bounded, provider-neutral validation to canonical components."""
        if (
            len(username) > MAX_CANONICAL_USERNAME_LENGTH
            or len(domain) > MAX_CANONICAL_DOMAIN_LENGTH
            or len(email) > MAX_CANONICAL_EMAIL_LENGTH
            or username.startswith(DOT_SEPARATOR)
            or username.endswith(DOT_SEPARATOR)
            or domain.startswith(DOT_SEPARATOR)
            or domain.endswith(DOT_SEPARATOR)
        ):
            return False
        return not any(
            character.isspace()
            or not character.isprintable()
            or character in INVALID_MAILBOX_CHARACTERS
            for character in email
        )
