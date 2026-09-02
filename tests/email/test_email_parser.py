from pathlib import Path

import pytest


from email_security.gateway.ingestion import EmailIngestion
from email_security.email_models.email_models import AttachmentMetadata, EmailMessageData
from email_security.email_parser.email_parser import EmailParser


FIXTURE = Path(__file__).parent / "fixtures" / "suspicious_email.eml"


def test_parse_raw_plain_text_email() -> None:
    raw_email = """\
From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Tue, 1 Sep 2026 10:00:00 +0000
Message-ID: <test@example.com>
Content-Type: text/plain; charset="utf-8"

Hello from Inovix.
"""

    result = EmailParser().parse_raw(raw_email)

    assert isinstance(result, EmailMessageData)
    assert result.sender == "sender@example.com"
    assert result.recipients == ["recipient@example.com"]
    assert result.subject == "Test Email"
    assert result.text_body == "Hello from Inovix.\n"
    assert result.html_body is None


def test_parse_raw_html_email() -> None:
    raw_email = """\
From: sender@example.com
To: recipient@example.com
Subject: HTML Test
Content-Type: text/html; charset="utf-8"

<html><body><h1>Hello</h1></body></html>
"""

    result = EmailParser().parse_raw(raw_email)

    assert result.html_body == (
        "<html><body><h1>Hello</h1></body></html>\n"
    )
    assert result.text_body is None


def test_parse_multipart_email() -> None:
    raw_email = """\
From: sender@example.com
To: recipient@example.com
Subject: Multipart Test
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="abc"

--abc
Content-Type: text/plain; charset="utf-8"

Plain body

--abc
Content-Type: text/html; charset="utf-8"

<html><body>HTML body</body></html>

--abc--
"""

    result = EmailParser().parse_raw(raw_email)

    assert result.text_body == "Plain body\n"
    assert result.html_body == (
        "<html><body>HTML body</body></html>\n"
    )


def test_parse_attachment_metadata() -> None:
    result = EmailParser().parse_file(FIXTURE)

    assert len(result.attachments) == 1

    attachment = result.attachments[0]

    assert isinstance(attachment, AttachmentMetadata)
    assert attachment.filename == "invoice.pdf"
    assert attachment.content_type == "application/pdf"
    assert attachment.content_disposition == "attachment"
    assert attachment.size > 0


def test_parse_file_fixture() -> None:
    result = EmailParser().parse_file(FIXTURE)

    assert result.sender == 'Microsoft Security <security@example.com>'
    assert result.recipients == ["victim@example.org"]
    assert result.cc == ["admin@example.org"]
    assert result.reply_to == ["attacker@evil.example"]
    assert result.return_path == "<bounce@evil.example>"
    assert result.subject == "Urgent Account Verification"
    assert result.message_id == "<suspicious-001@example.com>"

    assert len(result.received) == 2

    assert "Authentication-Results" in result.authentication_headers
    assert "DKIM-Signature" in result.authentication_headers

    assert result.text_body is not None
    assert "immediate verification" in result.text_body

    assert result.html_body is not None
    assert "evil.example/login" in result.html_body


def test_missing_optional_headers_are_safe() -> None:
    raw_email = """\
From: sender@example.com
To: recipient@example.com
Subject: Minimal Email

Hello.
"""

    result = EmailParser().parse_raw(raw_email)

    assert result.sender == "sender@example.com"
    assert result.recipients == ["recipient@example.com"]
    assert result.cc == []
    assert result.reply_to == []
    assert result.return_path is None
    assert result.date is None
    assert result.message_id is None
    assert result.received == []
    assert result.authentication_headers == {}
    assert result.text_body == "Hello.\n"
    assert result.html_body is None
    assert result.attachments == []


def test_malformed_email_is_handled_safely() -> None:
    malformed = (
        b"From sender@example.com\n"
        b"To recipient@example.com\n"
        b"Subject: \xff\xfe\xfd\n"
        b"\n"
        b"Malformed body"
    )

    result = EmailParser().parse_raw(malformed)

    assert isinstance(result, EmailMessageData)
    assert result.text_body is not None
    assert "Malformed body" in result.text_body


def test_raw_bytes_are_supported() -> None:
    raw_email = b"""\
From: sender@example.com
To: recipient@example.com
Subject: Byte Test
Content-Type: text/plain; charset="utf-8"

Byte body
"""

    result = EmailParser().parse_raw(raw_email)

    assert result.sender == "sender@example.com"
    assert result.subject == "Byte Test"
    assert result.text_body == "Byte body\n"


def test_gateway_ingests_raw_and_file() -> None:
    gateway = EmailIngestion()

    raw_result = gateway.ingest_raw(
        """\
From: sender@example.com
To: recipient@example.com
Subject: Gateway Test

Gateway body
"""
    )

    file_result = gateway.ingest_file(FIXTURE)

    assert raw_result.subject == "Gateway Test"
    assert raw_result.text_body == "Gateway body\n"
    assert file_result.subject == "Urgent Account Verification"


def test_invalid_input_type_is_rejected() -> None:
    with pytest.raises(TypeError):
        EmailParser().parse_raw(12345)  # type: ignore[arg-type]

def test_non_eml_file_is_rejected(tmp_path) -> None:
    file_path = tmp_path / "email.txt"
    file_path.write_text(
        "From: sender@example.com\n"
        "To: recipient@example.com\n"
        "Subject: Test\n\n"
        "Test body"
    )

    with pytest.raises(ValueError, match=r"\.eml"):
        EmailParser().parse_file(file_path)
