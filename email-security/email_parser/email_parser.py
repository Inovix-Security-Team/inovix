from __future__ import annotations

from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser, Parser
from email.utils import getaddresses
from pathlib import Path

from email_models.email_models import AttachmentMetadata, EmailMessageData


class EmailParser:
    """Parse raw RFC-compliant email data into a structured object."""

    AUTHENTICATION_HEADERS = (
        "Authentication-Results",
        "DKIM-Signature",
        "DomainKey-Signature",
        "ARC-Authentication-Results",
        "ARC-Seal",
        "ARC-Message-Signature",
    )

    def parse_raw(self, raw_email: str | bytes) -> EmailMessageData:
        """Parse a raw email represented as text or bytes."""

        if isinstance(raw_email, bytes):
            message = BytesParser(policy=policy.default).parsebytes(raw_email)
        elif isinstance(raw_email, str):
            message = Parser(policy=policy.default).parsestr(raw_email)
        else:
            raise TypeError("raw_email must be str or bytes")

        return self._build_structured_email(message)

    def parse_file(self, path: str | Path) -> EmailMessageData:
        """Parse an .eml file."""

        email_path = Path(path)

        with email_path.open("rb") as email_file:
            message = BytesParser(policy=policy.default).parse(email_file)

        return self._build_structured_email(message)

    def _build_structured_email(self, message: Message) -> EmailMessageData:
        return EmailMessageData(
            sender=self._get_address(message.get("From")),
            recipients=self._get_addresses(message.get_all("To", [])),
            cc=self._get_addresses(message.get_all("Cc", [])),
            reply_to=self._get_addresses(message.get_all("Reply-To", [])),
            return_path=self._decode_header(message.get("Return-Path")),
            subject=self._decode_header(message.get("Subject")),
            date=self._decode_header(message.get("Date")),
            message_id=self._decode_header(message.get("Message-ID")),
            received=[
                self._decode_header(value) or ""
                for value in message.get_all("Received", [])
            ],
            authentication_headers=self._get_authentication_headers(message),
            text_body=self._get_body(message, "text/plain"),
            html_body=self._get_body(message, "text/html"),
            attachments=self._get_attachments(message),
        )

    @staticmethod
    def _decode_header(value: object | None) -> str | None:
        if value is None:
            return None

        try:
            return str(make_header(decode_header(str(value))))
        except (UnicodeError, ValueError):
            return str(value)

    def _get_address(self, value: object | None) -> str | None:
        if value is None:
            return None

        addresses = getaddresses([self._decode_header(value) or ""])

        if not addresses:
            return self._decode_header(value)

        name, address = addresses[0]

        if name:
            return f"{name} <{address}>"

        return address or None

    def _get_addresses(self, values: list[object]) -> list[str]:
        if not values:
            return []

        decoded_values = [
            self._decode_header(value) or ""
            for value in values
        ]

        addresses = getaddresses(decoded_values)
        result: list[str] = []

        for name, address in addresses:
            if not address:
                continue

            if name:
                result.append(f"{name} <{address}>")
            else:
                result.append(address)

        return result

    def _get_authentication_headers(
        self,
        message: Message,
    ) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}

        for header_name in self.AUTHENTICATION_HEADERS:
            values = message.get_all(header_name, [])

            if values:
                result[header_name] = [
                    self._decode_header(value) or ""
                    for value in values
                ]

        return result

    def _get_body(
        self,
        message: Message,
        content_type: str,
    ) -> str | None:
        parts = message.walk()

        for part in parts:
            if part.is_multipart():
                continue

            if part.get_content_type() != content_type:
                continue

            disposition = part.get_content_disposition()

            if disposition == "attachment":
                continue

            try:
                content = part.get_content()
            except (UnicodeError, LookupError, ValueError):
                try:
                    payload = part.get_payload(decode=True)

                    if payload is None:
                        return None

                    charset = part.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace")
                except (UnicodeError, LookupError, ValueError):
                    return None

            if isinstance(content, str):
                return content

            if content is not None:
                return str(content)

        return None

    def _get_attachments(
        self,
        message: Message,
    ) -> list[AttachmentMetadata]:
        attachments: list[AttachmentMetadata] = []

        for part in message.walk():
            if part.is_multipart():
                continue

            disposition = part.get_content_disposition()
            filename = part.get_filename()

            if disposition != "attachment" and not filename:
                continue

            try:
                payload = part.get_payload(decode=True)
                size = len(payload) if payload is not None else 0
            except (TypeError, ValueError):
                size = 0

            attachments.append(
                AttachmentMetadata(
                    filename=self._decode_header(filename),
                    content_type=part.get_content_type(),
                    size=size,
                    content_disposition=disposition,
                )
            )

        return attachments
