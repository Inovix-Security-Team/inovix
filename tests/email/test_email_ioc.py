from email_security.email_models.email_models import EmailMessageData
from email_security.email_forensics.models import EmailForensicResult
from email_security.ioc import (
    EmailIOCExtractor,
    ExtractionConfidence,
    IOCSource,
)
from security_engine.threat_intelligence.models import IOCType


def _ioc(result, value, ioc_type):
    matches = [
        item
        for item in result.iocs
        if item.value == value and item.ioc_type == ioc_type
    ]
    assert len(matches) == 1
    return matches[0]


def test_extracts_ip_domain_url_email_and_hashes():
    message = EmailMessageData(
        sender="attacker@evil.example",
        subject=(
            "Visit https://phish.example/login from 203.0.113.10 "
            "hash "
            "d41d8cd98f00b204e9800998ecf8427e"
        ),
        text_body=(
            "Contact victim@example.net. "
            "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709 "
            "SHA256: "
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. "
            "Also visit https://evil.example/path."
        ),
    )

    result = EmailIOCExtractor().extract(message)

    assert _ioc(result, "203.0.113.10", IOCType.IP)
    assert _ioc(result, "phish.example", IOCType.DOMAIN)
    assert _ioc(result, "https://phish.example/login", IOCType.URL)
    assert _ioc(result, "evil.example", IOCType.DOMAIN)
    assert _ioc(result, "https://evil.example/path", IOCType.URL)
    assert _ioc(result, "attacker@evil.example", IOCType.EMAIL)
    assert _ioc(result, "victim@example.net", IOCType.EMAIL)
    assert _ioc(
        result,
        "d41d8cd98f00b204e9800998ecf8427e",
        IOCType.HASH,
    )
    assert _ioc(
        result,
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        IOCType.HASH,
    )
    assert _ioc(
        result,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        IOCType.HASH,
    )


def test_extracts_all_required_header_sources():
    message = EmailMessageData(
        sender="from@sender.example",
        reply_to=["reply@reply.example"],
        return_path="bounce@return.example",
        subject="Contact admin@subject.example",
        received=[
            "from mail.example (203.0.113.20) by mx.example",
        ],
        message_id="<message@message.example>",
    )

    result = EmailIOCExtractor().extract(message)

    assert _ioc(result, "from@sender.example", IOCType.EMAIL).sources == (
        IOCSource.FROM,
    )
    assert _ioc(result, "reply@reply.example", IOCType.EMAIL).sources == (
        IOCSource.REPLY_TO,
    )
    assert _ioc(
        result,
        "bounce@return.example",
        IOCType.EMAIL,
    ).sources == (IOCSource.RETURN_PATH,)

    assert _ioc(
        result,
        "admin@subject.example",
        IOCType.EMAIL,
    ).sources == (IOCSource.SUBJECT,)

    received_ip = _ioc(result, "203.0.113.20", IOCType.IP)
    assert received_ip.sources == (IOCSource.RECEIVED,)

    message_email = _ioc(result, "message@message.example", IOCType.EMAIL)
    assert message_email.sources == (IOCSource.MESSAGE_ID,)


def test_body_text_and_html_are_separate_provenance_locations():
    message = EmailMessageData(
        text_body="Visit https://shared.example/path",
        html_body="<a href='https://shared.example/path'>link</a>",
    )

    result = EmailIOCExtractor().extract(message)

    url = _ioc(result, "https://shared.example/path", IOCType.URL)

    assert url.sources == (IOCSource.BODY,)
    assert "email_body.text" in url.locations
    assert "email_body.html" in url.locations
    assert len(url.occurrences) == 2


def test_repeated_ioc_is_deduplicated_but_occurrences_are_preserved():
    message = EmailMessageData(
        sender="attacker@evil.example",
        reply_to=["attacker@evil.example"],
        subject="attacker@evil.example",
        text_body=(
            "attacker@evil.example "
            "https://evil.example/login "
            "https://evil.example/login"
        ),
    )

    result = EmailIOCExtractor().extract(message)

    email_ioc = _ioc(result, "attacker@evil.example", IOCType.EMAIL)
    url_ioc = _ioc(result, "https://evil.example/login", IOCType.URL)

    assert len(email_ioc.occurrences) == 4
    assert email_ioc.sources == (
        IOCSource.FROM,
        IOCSource.REPLY_TO,
        IOCSource.SUBJECT,
        IOCSource.BODY,
    )

    assert len(url_ioc.occurrences) == 2
    assert url_ioc.sources == (IOCSource.BODY,)


def test_extracts_ipv6():
    message = EmailMessageData(
        received=["from [2001:db8::10] by mx.example"],
        text_body="Connection from 2001:db8:85a3::8a2e:370:7334",
    )

    result = EmailIOCExtractor().extract(message)

    assert _ioc(result, "2001:db8::10", IOCType.IP)
    assert _ioc(
        result,
        "2001:db8:85a3::8a2e:370:7334",
        IOCType.IP,
    )


def test_malformed_ipv4_is_not_extracted():
    message = EmailMessageData(
        text_body=(
            "Invalid addresses 999.999.999.999 and "
            "300.1.2.3 should not become IOCs."
        )
    )

    result = EmailIOCExtractor().extract(message)

    assert not any(
        item.ioc_type == IOCType.IP
        for item in result.iocs
    )


def test_false_positive_resistance_for_plain_text():
    message = EmailMessageData(
        text_body=(
            "hello world "
            "123.456 "
            "abcdef "
            "not-a-domain "
            "user@localhost "
            "http-not-a-url"
        )
    )

    result = EmailIOCExtractor().extract(message)

    assert result.count == 0


def test_extraction_confidence_is_not_threat_status():
    message = EmailMessageData(
        text_body="https://example.com and 203.0.113.50"
    )

    result = EmailIOCExtractor().extract(message)

    url = _ioc(result, "https://example.com", IOCType.URL)
    ip = _ioc(result, "203.0.113.50", IOCType.IP)

    assert url.confidence == ExtractionConfidence.HIGH
    assert ip.confidence == ExtractionConfidence.HIGH

    # The extraction model contains no malicious/safe/suspicious verdict.
    assert not hasattr(url, "status")
    assert not hasattr(ip, "status")


def test_forensic_candidate_origin_ip_is_mapped_to_evidence():
    message = EmailMessageData()

    forensic = EmailForensicResult(
        candidate_origin_ip="198.51.100.77",
    )

    result = EmailIOCExtractor().extract(
        message,
        forensic_result=forensic,
    )

    ip = _ioc(result, "198.51.100.77", IOCType.IP)

    assert ip.sources == (IOCSource.FORENSIC_EVIDENCE,)
    assert ip.locations == ("candidate_origin_ip",)
    assert len(ip.occurrences) == 1


def test_forensic_evidence_and_received_header_are_deduplicated():
    message = EmailMessageData(
        received=["from gateway (198.51.100.77) by mx.example"],
    )

    forensic = EmailForensicResult(
        candidate_origin_ip="198.51.100.77",
    )

    result = EmailIOCExtractor().extract(
        message,
        forensic_result=forensic,
    )

    ip = _ioc(result, "198.51.100.77", IOCType.IP)

    assert len(ip.occurrences) == 2
    assert ip.sources == (
        IOCSource.RECEIVED,
        IOCSource.FORENSIC_EVIDENCE,
    )


def test_none_and_empty_fields_are_safe():
    message = EmailMessageData(
        sender=None,
        reply_to=[],
        return_path=None,
        subject=None,
        received=[],
        message_id=None,
        text_body=None,
        html_body=None,
    )

    result = EmailIOCExtractor().extract(message)

    assert result.iocs == ()
    assert result.count == 0


def test_context_is_preserved_for_extracted_ioc():
    message = EmailMessageData(
        text_body="Security alert: visit https://danger.example/reset immediately."
    )

    result = EmailIOCExtractor().extract(message)

    url = _ioc(result, "https://danger.example/reset", IOCType.URL)

    assert url.occurrences
    occurrence = url.occurrences[0]

    assert occurrence.source == IOCSource.BODY
    assert occurrence.location == "email_body.text"
    assert occurrence.raw_value == "https://danger.example/reset"
    assert "Security alert" in occurrence.context
    assert "immediately" in occurrence.context




def test_forensic_evidence_is_mapped_with_provenance():
    from email_security.email_forensics.models import ForensicEvidence

    message = EmailMessageData()

    forensic = EmailForensicResult(
        evidence=(
            ForensicEvidence(
                source="From",
                raw_value="attacker@evil.example",
                parsed_value="evil.example",
                reason="Extracted sender address and domain.",
            ),
            ForensicEvidence(
                source="Received[0]",
                raw_value="from relay (203.0.113.44) by mx.example",
                parsed_value="hostname=relay, ip=203.0.113.44",
                reason=(
                    "Preserved Received header for hop-level "
                    "forensic analysis."
                ),
            ),
        ),
    )

    result = EmailIOCExtractor().extract(
        message,
        forensic_result=forensic,
    )

    email_ioc = _ioc(
        result,
        "attacker@evil.example",
        IOCType.EMAIL,
    )

    ip_ioc = _ioc(
        result,
        "203.0.113.44",
        IOCType.IP,
    )

    assert IOCSource.FORENSIC_EVIDENCE in email_ioc.sources
    assert IOCSource.FORENSIC_EVIDENCE in ip_ioc.sources

    assert any(
        occurrence.location == "forensic.From"
        for occurrence in email_ioc.occurrences
    )

    assert any(
        occurrence.location == "forensic.Received[0]"
        for occurrence in ip_ioc.occurrences
    )

    assert any(
        "Extracted sender address and domain."
        in occurrence.context
        for occurrence in email_ioc.occurrences
    )
