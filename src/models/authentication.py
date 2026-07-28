"""Reusable email-authentication evidence data contracts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictStr

MAX_AUTHENTICATION_HEADER_VALUE_LENGTH = 8_192


class AuthenticationStatus(StrEnum):
    """Normalized status for an observed email-authentication mechanism."""

    PASS = "PASS"
    FAIL = "FAIL"
    SOFTFAIL = "SOFTFAIL"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class AuthenticationMechanism(StrEnum):
    """Identify an email-authentication mechanism."""

    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"
    ARC = "arc"


class AuthenticationHeaderSource(StrEnum):
    """Identify the source header from which authentication evidence was read."""

    AUTHENTICATION_RESULTS = "authentication_results"
    RECEIVED_SPF = "received_spf"
    DKIM_SIGNATURE = "dkim_signature"
    ARC_AUTHENTICATION_RESULTS = "arc_authentication_results"
    ARC_SEAL = "arc_seal"


class AuthenticationMechanismResult(BaseModel):
    """Contain normalized evidence for one authentication mechanism."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    mechanism: AuthenticationMechanism
    status: AuthenticationStatus
    observed_statuses: tuple[AuthenticationStatus, ...] = Field(default=())
    header_sources: tuple[AuthenticationHeaderSource, ...] = Field(default=())
    raw_header_values: tuple[StrictStr, ...] = Field(default=())


class AuthenticationAnalysisResult(BaseModel):
    """Contain normalized SPF, DKIM, DMARC, ARC, and header evidence."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    spf: AuthenticationMechanismResult
    dkim: AuthenticationMechanismResult
    dmarc: AuthenticationMechanismResult
    arc: AuthenticationMechanismResult
    authentication_results: tuple[StrictStr, ...] = Field(default=())
