from dataclasses import dataclass, field


@dataclass(frozen=True)
class AttachmentMetadata:
    """Metadata describing an email attachment."""

    filename: str | None = None
    content_type: str = "application/octet-stream"
    size: int = 0
    content_disposition: str | None = None


@dataclass(frozen=True)
class EmailMessageData:
    """Normalized structured representation of an incoming email."""

    sender: str | None = None
    recipients: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    reply_to: list[str] = field(default_factory=list)
    return_path: str | None = None

    subject: str | None = None
    date: str | None = None
    message_id: str | None = None

    received: list[str] = field(default_factory=list)
    authentication_headers: dict[str, list[str]] = field(default_factory=dict)

    text_body: str | None = None
    html_body: str | None = None

    attachments: list[AttachmentMetadata] = field(default_factory=list)
