from __future__ import annotations

from email_security.email_models.email_models import EmailMessageData
from email_security.intelligence import EmailIntelligenceService


def make_email(
    *,
    sender: str = "alice@example.com",
    reply_to: list[str] | None = None,
    return_path: str | None = None,
    subject: str = "Hello",
    text_body: str = "This is a normal message.",
    received: list[str] | None = None,
    authentication_headers: dict[str, list[str]] | None = None,
) -> EmailMessageData:
    return EmailMessageData(
        sender=sender,
        recipients=["recipient@example.com"],
        cc=[],
        reply_to=reply_to or [],
        return_path=return_path,
        subject=subject,
        date="Fri, 04 Sep 2026 10:00:00 +0000",
        message_id="<test@example.com>",
        received=received or [],
        authentication_headers=authentication_headers or {},
        text_body=text_body,
        html_body=None,
        attachments=[],
    )


def test_safe_email_produces_low_risk_result():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email()
    )

    assert result.verdict == "SAFE"
    assert result.risk_score == 0
    assert result.findings == []
    assert result.correlations == []
    assert result.provenance.forensics_used is True
    assert result.provenance.ioc_extraction_used is True
    assert result.provenance.threat_detection_used is True


def test_phishing_email_produces_multiple_findings():
    service = EmailIntelligenceService()

    email = make_email(
        subject="URGENT account verification",
        text_body=(
            "Act now. Verify your account immediately. "
            "Send your password and verification code."
        ),
    )

    result = service.analyze(email)

    rule_ids = {
        finding.rule_id
        for finding in result.findings
    }

    assert "PHISHING_URGENT_LANGUAGE" in rule_ids
    assert "CREDENTIAL_REQUEST" in rule_ids
    assert result.risk_score > 0


def test_impersonation_language_is_detected():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            text_body=(
                "I am from your bank. "
                "Please contact bank support immediately."
            )
        )
    )

    rule_ids = {
        finding.rule_id
        for finding in result.findings
    }

    assert "IMPERSONATION_LANGUAGE" in rule_ids


def test_financial_request_is_detected():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            subject="Urgent payment",
            text_body=(
                "Please make payment immediately. "
                "Send the funds today."
            ),
        )
    )

    rule_ids = {
        finding.rule_id
        for finding in result.findings
    }

    assert "FINANCIAL_REQUEST" in rule_ids
    assert "PHISHING_URGENT_LANGUAGE" in rule_ids


def test_suspicious_url_is_correlated_with_ioc():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            subject="Urgent verification",
            text_body=(
                "Urgent. Verify your account immediately: "
                "https://bit.ly/account-login"
            ),
        )
    )

    rule_ids = {
        finding.rule_id
        for finding in result.findings
    }

    assert "PHISHING_URGENT_LANGUAGE" in rule_ids

    assert any(
        ioc.value == "https://bit.ly/account-login"
        for ioc in service.ioc_extractor.extract(
            make_email(
                text_body=(
                    "https://bit.ly/account-login"
                )
            )
        ).iocs
    )


def test_sender_reply_to_mismatch_is_detected():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            sender="security@example.com",
            reply_to=["attacker@evil.example"],
        )
    )

    rule_ids = {
        finding.rule_id
        for finding in result.findings
    }

    assert "REPLY_TO_MISMATCH" in rule_ids


def test_sender_return_path_mismatch_is_detected():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            sender="security@example.com",
            return_path="<attacker@evil.example>",
        )
    )

    rule_ids = {
        finding.rule_id
        for finding in result.findings
    }

    assert "RETURN_PATH_MISMATCH" in rule_ids


def test_identity_and_authentication_correlation():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            sender="security@example.com",
            reply_to=["attacker@evil.example"],
            authentication_headers={
                "Authentication-Results": [
                    "mx.example; spf=fail "
                    "dkim=fail dmarc=fail"
                ]
            },
        )
    )

    assert any(
        correlation.rule_id
        == "IDENTITY_AUTH_ANOMALY"
        for correlation in result.correlations
    )


def test_raw_email_end_to_end():
    service = EmailIntelligenceService()

    raw_email = """From: security@example.com
To: victim@example.com
Reply-To: attacker@evil.example
Return-Path: <attacker@evil.example>
Subject: URGENT account verification
Message-ID: <abc@example.com>
Date: Fri, 04 Sep 2026 10:00:00 +0000
Authentication-Results: mx.example; spf=fail dkim=fail dmarc=fail
Content-Type: text/plain

Urgent. Act now and verify your account immediately.
Send your password and verification code.
Visit https://bit.ly/account-login
"""

    result = service.analyze_raw(raw_email)

    assert result.provenance.parser_used is True
    assert result.provenance.forensics_used is True
    assert result.provenance.ioc_extraction_used is True
    assert result.provenance.threat_detection_used is True

    assert result.risk_score > 0
    assert len(result.findings) > 0
    assert len(result.evidence) > 0


def test_empty_raw_email_is_rejected():
    service = EmailIntelligenceService()

    try:
        service.analyze_raw("")
    except ValueError as exc:
        assert "empty" in str(exc).lower()
    else:
        raise AssertionError(
            "Expected ValueError for empty email"
        )


def test_invalid_raw_email_type_is_rejected():
    service = EmailIntelligenceService()

    try:
        service.analyze_raw(123)  # type: ignore[arg-type]
    except TypeError as exc:
        assert "str or bytes" in str(exc)
    else:
        raise AssertionError(
            "Expected TypeError for invalid input"
        )


def test_provenance_contains_pipeline_stages():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email()
    )

    assert result.provenance.stages == [
        "forensics",
        "ioc_extraction",
        "threat_detection",
        "correlation",
    ]


def test_evidence_has_provenance_fields():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            text_body=(
                "Urgent. Please send your password immediately."
            )
        )
    )

    assert result.evidence

    for item in result.evidence:
        assert item.evidence_id
        assert item.source
        assert item.category
        assert item.description
        assert 0.0 <= item.confidence <= 1.0


def test_confidence_is_separate_from_risk_score():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            text_body=(
                "Urgent. Please send your password."
            )
        )
    )

    assert 0.0 <= result.confidence <= 1.0
    assert result.risk_score >= 0


def test_no_ioc_email_still_analyzes():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            text_body="Urgent action required."
        )
    )

    assert result is not None
    assert result.provenance.threat_detection_used is True


def test_no_forensic_input_is_generated_automatically():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email()
    )

    assert result.provenance.forensics_used is True


def test_duplicate_ioc_values_do_not_create_duplicate_indicators():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            text_body=(
                "Visit https://bit.ly/test and again "
                "https://bit.ly/test"
            )
        )
    )

    assert len(result.indicators) == len(
        set(result.indicators)
    )

def test_unified_result_persists_through_database_service():
    import sqlite3

    from database.schema import initialize_schema
    from database.service import DatabaseService

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    initialize_schema(connection)

    database = DatabaseService(connection)
    service = EmailIntelligenceService()

    email = make_email(
        subject="URGENT account verification",
        text_body=(
            "Urgent. Verify your account immediately. "
            "Send your password and verification code."
        ),
    )

    result = service.analyze(email)

    saved = service.persist(
        result,
        database,
        event_id="email-int-007-test-001",
        email=email,
    )

    assert saved["event"].id == "email-int-007-test-001"
    assert saved["risk"].event_id == "email-int-007-test-001"
    assert saved["risk"].score == result.risk_score
    assert saved["risk"].verdict == result.verdict

    restored = database.get_analysis(
        "email-int-007-test-001"
    )

    assert restored is not None
    assert restored["event"].metadata["intelligence_version"] == "EMAIL-INT-007"
    assert restored["event"].metadata["confidence"] == result.confidence
    assert len(restored["event"].metadata["evidence"]) == len(
        result.evidence
    )
    assert len(restored["event"].metadata["correlations"]) == len(
        result.correlations
    )

    connection.close()
def test_real_eml_end_to_end_through_persistence():
    import sqlite3
    from pathlib import Path

    from database.schema import initialize_schema
    from database.service import DatabaseService

    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "suspicious_email.eml"
    )

    raw_email = fixture.read_bytes()

    service = EmailIntelligenceService()

    # Full pipeline:
    # raw .eml
    # -> parser
    # -> forensics
    # -> IOC extraction
    # -> threat detection
    # -> correlation
    # -> risk scoring
    # -> verdict
    result = service.analyze_raw(raw_email)

    # Parser / provenance
    assert result.provenance.parser_used is True
    assert result.provenance.input_type == "raw_eml"
    assert result.provenance.stages == [
        "parser",
        "forensics",
        "ioc_extraction",
        "threat_detection",
        "correlation",
    ]

    # Forensics
    assert result.provenance.forensics_used is True
    assert any(
        finding.rule_id == "REPLY_TO_MISMATCH"
        or finding.rule_id == "FROM_REPLY_TO_MISMATCH"
        for finding in result.findings
    )

    # IOC extraction
    assert result.provenance.ioc_extraction_used is True
    assert "https://evil.example/login" in result.indicators

    # Threat detection
    assert result.provenance.threat_detection_used is True
    assert result.findings

    # Correlation
    assert result.provenance.correlation_used is True
    correlation_rule_ids = {
        correlation.rule_id
        for correlation in result.correlations
    }

    assert (
        "SUSPICIOUS_URL_IOC" in correlation_rule_ids
        or "PHISHING_CAMPAIGN_PATTERN" in correlation_rule_ids
        or "IDENTITY_AUTH_ANOMALY" in correlation_rule_ids
    )

    # Correlations must affect the final risk/verdict.
    assert result.risk_score > 0
    assert result.verdict in {
        "SUSPICIOUS",
        "MALICIOUS",
    }

    # Unified evidence must be present.
    assert result.evidence

    evidence_ids = {
        item.evidence_id
        for item in result.evidence
    }

    assert len(evidence_ids) == len(result.evidence)

    # Every correlation must reference evidence that actually exists.
    for correlation in result.correlations:
        assert correlation.evidence_ids
        assert set(correlation.evidence_ids).issubset(
            evidence_ids
        )

    # Confidence is independent from risk.
    assert 0.0 <= result.confidence <= 1.0

    # Persist through the existing DatabaseService.
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    initialize_schema(connection)

    database = DatabaseService(connection)

    parsed_email = service.parser.parse_raw(raw_email)

    saved = service.persist(
        result,
        database,
        event_id="email-int-007-real-e2e",
        email=parsed_email,
    )

    assert saved["event"].id == "email-int-007-real-e2e"
    assert saved["risk"].event_id == "email-int-007-real-e2e"
    assert saved["risk"].score == result.risk_score
    assert saved["risk"].verdict == result.verdict

    # Reload from the database and verify the unified intelligence
    # metadata survived persistence.
    restored = database.get_analysis(
        "email-int-007-real-e2e"
    )

    assert restored is not None

    metadata = restored["event"].metadata

    assert metadata["intelligence_version"] == "EMAIL-INT-007"
    assert metadata["confidence"] == result.confidence
    assert metadata["indicators"] == result.indicators
    assert metadata["reasons"] == result.reasons
    assert metadata["provenance"] == (
        result.provenance.to_dict()
    )
    assert metadata["evidence"] == [
        item.to_dict()
        for item in result.evidence
    ]
    assert metadata["correlations"] == [
        item.to_dict()
        for item in result.correlations
    ]

    connection.close()
def test_phishing_correlation_contributes_to_risk_and_verdict():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            subject="URGENT account verification",
            text_body=(
                "Urgent. Verify your account immediately. "
                "Send your password and verification code. "
                "Visit https://bit.ly/account-login"
            ),
        )
    )

    assert any(
        correlation.rule_id == "PHISHING_CAMPAIGN_PATTERN"
        for correlation in result.correlations
    )

    assert result.risk_score >= 80
    assert result.verdict == "MALICIOUS"


def test_identity_auth_correlation_contributes_to_risk_and_verdict():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            sender="security@example.com",
            reply_to=["attacker@evil.example"],
            authentication_headers={
                "Authentication-Results": [
                    "mx.example; spf=fail "
                    "dkim=fail dmarc=fail"
                ]
            },
        )
    )

    assert any(
        correlation.rule_id == "IDENTITY_AUTH_ANOMALY"
        for correlation in result.correlations
    )

    assert result.risk_score >= 80
    assert result.verdict == "MALICIOUS"


def test_financial_social_engineering_correlation_contributes_to_risk():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            sender="finance@example.com",
            reply_to=["attacker@evil.example"],
            subject="Urgent payment required",
            text_body=(
                "Urgent action required. "
                "Please make payment immediately. "
                "Send the funds today."
            ),
        )
    )

    assert any(
        correlation.rule_id
        == "FINANCIAL_SOCIAL_ENGINEERING_PATTERN"
        for correlation in result.correlations
    )

    assert result.risk_score >= 80
    assert result.verdict == "MALICIOUS"


def test_exact_suspicious_url_ioc_correlation_contributes_to_risk():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            subject="Urgent verification",
            text_body=(
                "Urgent. Verify your account immediately: "
                "https://bit.ly/account-login"
            ),
        )
    )

    assert any(
        correlation.rule_id == "SUSPICIOUS_URL_IOC"
        for correlation in result.correlations
    )

    assert result.risk_score >= 80
    assert result.verdict == "MALICIOUS"
def test_correlations_reference_only_existing_evidence():
    service = EmailIntelligenceService()

    result = service.analyze(
        make_email(
            subject="URGENT account verification",
            text_body=(
                "Urgent. Verify your account immediately. "
                "Send your password and verification code. "
                "Visit https://bit.ly/account-login"
            ),
            sender="security@example.com",
            reply_to=["attacker@evil.example"],
            authentication_headers={
                "Authentication-Results": [
                    "mx.example; spf=fail dkim=fail dmarc=fail"
                ]
            },
        )
    )

    evidence_ids = {
        item.evidence_id
        for item in result.evidence
    }

    assert evidence_ids

    for correlation in result.correlations:
        assert correlation.evidence_ids
        assert set(correlation.evidence_ids).issubset(
            evidence_ids
        )
