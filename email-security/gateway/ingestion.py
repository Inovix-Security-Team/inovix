from __future__ import annotations

from pathlib import Path

from email_models.email_models import EmailMessageData
from email_parser.email_parser import EmailParser


class EmailIngestion:
    """Entry point for incoming email data."""

    def __init__(self, parser: EmailParser | None = None) -> None:
        self.parser = parser or EmailParser()

    def ingest_raw(self, raw_email: str | bytes) -> EmailMessageData:
        """Ingest raw email text or bytes."""

        return self.parser.parse_raw(raw_email)

    def ingest_file(self, path: str | Path) -> EmailMessageData:
        """Ingest an .eml file."""

        return self.parser.parse_file(path)
