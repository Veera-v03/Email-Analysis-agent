"""Strict email input contracts for future application use cases."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr


class EmailAttachment(BaseModel):
    """Describe an attachment supplied with an email message."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    filename: StrictStr = Field(min_length=1, max_length=255)
    content_type: StrictStr = Field(min_length=1, max_length=127)
    size_bytes: StrictInt = Field(ge=0)


class EmailHeader(BaseModel):
    """Represent validated message metadata supplied by the mail source."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    message_id: StrictStr = Field(min_length=1, max_length=998)
    sender: StrictStr = Field(min_length=3, max_length=320)
    recipients: list[StrictStr] = Field(min_length=1)
    subject: StrictStr = Field(min_length=1, max_length=998)
    sent_at: StrictStr = Field(min_length=1, max_length=64)
    reply_to: StrictStr | None = Field(default=None, max_length=320)


class EmailInput(BaseModel):
    """Represent the complete validated input of an email message.

    The model deliberately describes only message structure. It makes no
    security judgement and exposes no analysis output.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    header: EmailHeader
    body_text: StrictStr = Field(min_length=1, max_length=2_000_000)
    attachments: list[EmailAttachment] = Field(default_factory=list)
