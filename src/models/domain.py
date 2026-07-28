"""Structured domain parsing data contracts."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

MAX_DOMAIN_INPUT_LENGTH = 8_192
MAX_FQDN_LENGTH = 253
MAX_DNS_LABEL_LENGTH = 63


class DomainParseResult(BaseModel):
    """Contain normalized domain components without security assessment."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    raw_value: StrictStr = Field(max_length=MAX_DOMAIN_INPUT_LENGTH)
    normalized_domain: StrictStr | None = Field(
        default=None, max_length=MAX_FQDN_LENGTH
    )
    subdomain: StrictStr | None = Field(default=None, max_length=MAX_FQDN_LENGTH)
    root_domain: StrictStr | None = Field(default=None, max_length=MAX_FQDN_LENGTH)
    second_level_domain: StrictStr | None = Field(
        default=None,
        max_length=MAX_DNS_LABEL_LENGTH,
    )
    tld: StrictStr | None = Field(default=None, max_length=MAX_FQDN_LENGTH)
    is_valid: StrictBool
    is_localhost: StrictBool = False
    is_idn: StrictBool = False
    has_known_public_suffix: StrictBool = False
