from collections import OrderedDict
from collections.abc import Iterable

from email_security.email_forensics.models import EmailForensicResult
from email_security.email_models.email_models import EmailMessageData
from security_engine.threat_intelligence.models import IOCType

from .models import (
    EmailIOC,
    EmailIOCExtractionResult,
    ExtractionConfidence,
    IOCOccurrence,
    IOCSource,
)
from .patterns import (
    DOMAIN_PATTERN,
    EMAIL_PATTERN,
    IPV4_PATTERN,
    IPV6_PATTERN,
    MD5_PATTERN,
    SHA1_PATTERN,
    SHA256_PATTERN,
    URL_PATTERN,
    is_valid_ip,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ip,
    normalize_url,
)


class EmailIOCExtractor:
    """Passively extract security-relevant IOCs from parsed email data."""

    def extract(
        self,
        email: EmailMessageData,
        forensic_result: EmailForensicResult | None = None,
    ) -> EmailIOCExtractionResult:
        """Extract and deduplicate IOCs while preserving provenance."""

        occurrences: OrderedDict[
            tuple[IOCType, str],
            list[IOCOccurrence],
        ] = OrderedDict()

        for source, location, value in self._iter_sources(email):
            self._extract_from_text(
                value,
                source,
                location,
                occurrences,
            )

        if forensic_result is not None:
            self._extract_forensic_evidence(
                forensic_result,
                occurrences,
            )

        iocs = tuple(
            EmailIOC(
                value=value,
                ioc_type=ioc_type,
                confidence=self._confidence_for(ioc_type),
                occurrences=tuple(items),
            )
            for (ioc_type, value), items in occurrences.items()
        )

        return EmailIOCExtractionResult(iocs=iocs)

    @staticmethod
    def _iter_sources(
        email: EmailMessageData,
    ) -> Iterable[tuple[IOCSource, str, str]]:
        """Yield supported email evidence sources."""

        if email.sender:
            yield IOCSource.FROM, "from_header", email.sender

        for index, address in enumerate(email.reply_to):
            if address:
                yield (
                    IOCSource.REPLY_TO,
                    f"reply_to_header[{index}]",
                    address,
                )

        if email.return_path:
            yield (
                IOCSource.RETURN_PATH,
                "return_path_header",
                email.return_path,
            )

        if email.subject:
            yield IOCSource.SUBJECT, "subject", email.subject

        for index, received in enumerate(email.received):
            if received:
                yield (
                    IOCSource.RECEIVED,
                    f"received_header[{index}]",
                    received,
                )

        if email.message_id:
            yield IOCSource.MESSAGE_ID, "message_id", email.message_id

        if email.text_body:
            yield IOCSource.BODY, "email_body.text", email.text_body

        if email.html_body:
            yield IOCSource.BODY, "email_body.html", email.html_body

    @staticmethod
    def _extract_from_text(
        text: str,
        source: IOCSource,
        location: str,
        occurrences: OrderedDict[
            tuple[IOCType, str],
            list[IOCOccurrence],
        ],
        context_prefix: str = "",
    ) -> None:
        """Extract all supported IOC types from one evidence value."""

        if not text:
            return

        patterns = (
            (URL_PATTERN, IOCType.URL),
            (EMAIL_PATTERN, IOCType.EMAIL),
            (DOMAIN_PATTERN, IOCType.DOMAIN),
            (IPV4_PATTERN, IOCType.IP),
            (IPV6_PATTERN, IOCType.IP),
            (MD5_PATTERN, IOCType.HASH),
            (SHA1_PATTERN, IOCType.HASH),
            (SHA256_PATTERN, IOCType.HASH),
        )

        for pattern, ioc_type in patterns:
            for match in pattern.finditer(text):
                raw_value = match.group(0)

                if ioc_type == IOCType.EMAIL:
                    value = normalize_email(raw_value)

                elif ioc_type == IOCType.DOMAIN:
                    # Domains embedded inside an email address are represented
                    # by the EMAIL IOC and are not duplicated as DOMAIN IOCs.
                    if "@" in raw_value:
                        continue
                    value = normalize_domain(raw_value)

                elif ioc_type == IOCType.IP:
                    if not is_valid_ip(raw_value):
                        continue
                    value = normalize_ip(raw_value)

                elif ioc_type == IOCType.URL:
                    value = normalize_url(raw_value)

                else:
                    value = normalize_hash(raw_value)

                if not value:
                    continue

                context = _build_context(
                    text,
                    match.start(),
                    match.end(),
                )

                if context_prefix:
                    context = f"{context_prefix} Evidence: {context}"

                occurrence = IOCOccurrence(
                    source=source,
                    location=location,
                    context=context,
                    raw_value=raw_value,
                )

                key = (ioc_type, value)
                occurrences.setdefault(key, []).append(occurrence)

    @staticmethod
    def _extract_forensic_evidence(
        forensic_result: EmailForensicResult,
        occurrences: OrderedDict[
            tuple[IOCType, str],
            list[IOCOccurrence],
        ],
    ) -> None:
        """Map existing forensic evidence into IOC provenance."""

        candidate_ip = forensic_result.candidate_origin_ip

        if candidate_ip and is_valid_ip(candidate_ip):
            normalized = normalize_ip(candidate_ip)

            occurrence = IOCOccurrence(
                source=IOCSource.FORENSIC_EVIDENCE,
                location="candidate_origin_ip",
                context=(
                    "Candidate origin IP identified by email header "
                    "forensics."
                ),
                raw_value=candidate_ip,
            )

            occurrences.setdefault(
                (IOCType.IP, normalized),
                [],
            ).append(occurrence)

        for evidence in forensic_result.evidence:
            if not evidence.raw_value:
                continue

            location = f"forensic.{evidence.source}"

            EmailIOCExtractor._extract_from_text(
                evidence.raw_value,
                IOCSource.FORENSIC_EVIDENCE,
                location,
                occurrences,
                context_prefix=evidence.reason,
            )

            if evidence.parsed_value:
                EmailIOCExtractor._extract_from_text(
                    evidence.parsed_value,
                    IOCSource.FORENSIC_EVIDENCE,
                    f"{location}.parsed",
                    occurrences,
                    context_prefix=evidence.reason,
                )

    @staticmethod
    def _confidence_for(
        ioc_type: IOCType,
    ) -> ExtractionConfidence:
        """Return extraction confidence based on syntactic certainty."""

        if ioc_type in {
            IOCType.IP,
            IOCType.EMAIL,
            IOCType.URL,
            IOCType.HASH,
        }:
            return ExtractionConfidence.HIGH

        return ExtractionConfidence.MEDIUM


def _build_context(
    text: str,
    start: int,
    end: int,
    radius: int = 80,
) -> str:
    """Return a bounded context window around an extracted IOC."""

    context_start = max(0, start - radius)
    context_end = min(len(text), end + radius)

    return text[context_start:context_end].strip()
def _build_context(
    text: str,
    start: int,
    end: int,
    radius: int = 80,
) -> str:
    """Return a bounded context window around an extracted IOC."""

    context_start = max(0, start - radius)
    context_end = min(len(text), end + radius)

    return text[context_start:context_end].strip()



