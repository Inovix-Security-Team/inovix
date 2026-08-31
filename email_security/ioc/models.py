from dataclasses import dataclass, field
from enum import Enum

from security_engine.threat_intelligence.models import IOCType


class IOCSource(str, Enum):
    """Supported email evidence sources."""

    FROM = "from_header"
    REPLY_TO = "reply_to_header"
    RETURN_PATH = "return_path_header"
    SUBJECT = "subject"
    RECEIVED = "received_header"
    MESSAGE_ID = "message_id"
    BODY = "email_body"
    FORENSIC_EVIDENCE = "forensic_evidence"


class ExtractionConfidence(str, Enum):
    """Confidence that a value was syntactically extracted as an IOC."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class IOCOccurrence:
    """One occurrence of an IOC within email evidence."""

    source: IOCSource
    location: str
    context: str = ""
    raw_value: str = ""


@dataclass(frozen=True)
class EmailIOC:
    """An IOC extracted from an email with preserved provenance.

    Extraction confidence describes the reliability of the syntactic
    extraction only. It does not represent maliciousness or reputation.
    """

    value: str
    ioc_type: IOCType
    confidence: ExtractionConfidence
    occurrences: tuple[IOCOccurrence, ...] = field(default_factory=tuple)

    @property
    def sources(self) -> tuple[IOCSource, ...]:
        """Return unique evidence sources for this IOC."""

        return tuple(dict.fromkeys(item.source for item in self.occurrences))

    @property
    def locations(self) -> tuple[str, ...]:
        """Return unique evidence locations for this IOC."""

        return tuple(dict.fromkeys(item.location for item in self.occurrences))


@dataclass(frozen=True)
class EmailIOCExtractionResult:
    """Collection of deduplicated IOCs extracted from an email."""

    iocs: tuple[EmailIOC, ...] = field(default_factory=tuple)

    @property
    def count(self) -> int:
        """Return the number of unique extracted IOCs."""

        return len(self.iocs)
