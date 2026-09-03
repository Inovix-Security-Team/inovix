from __future__ import annotations

from email_security.email_forensics.models import (
    EmailForensicResult,
    IdentityAnalysis,
)
from email_security.email_models.email_models import EmailMessageData
from email_security.ioc.models import (
    EmailIOC,
    EmailIOCExtractionResult,
    ExtractionConfidence,
)
from security_engine.threat_intelligence.models import IOCType
from email_security.threat_detection import EmailThreatAnalyzer


def _email(
    subject: str | None = None,
    body: str | None = None,
    sender: str | None = None,
    reply_to: list[str] | None = None,
    return_path: str | None = None,
) -> EmailMessageData:
    return EmailMessageData(
        sender=sender,
        reply_to=reply_to or [],
        return_path=return_path,
        subject=subject,
        text_body=body,
    )


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def test_phishing_urgent_language_detection() -> None:
    analyzer = EmailThreatAnalyzer()

    findings = analyzer.analyze(
        _email(
            subject="Urgent account verification",
            body="Act now and verify your account immediately.",
        )
    )

    assert "PHISHING_URGENT_LANGUAGE" in _rule_ids(findings)


def test_credential_theft_detection() -> None:
    analyzer = EmailThreatAnalyzer()

    findings = analyzer.analyze(
        _email(
            subject="Security verification required",
            body="Please provide your password and OTP.",
        )
    )

    assert "CREDENTIAL_REQUEST" in _rule_ids(findings)


def test_financial_fraud_detection() -> None:
    analyzer = EmailThreatAnalyzer()

    findings = analyzer.analyze(
        _email(
            subject="Urgent payment request",
            body="Please complete the bank transfer immediately.",
        )
    )

    assert "FINANCIAL_REQUEST" in _rule_ids(findings)


def test_social_engineering_detection() -> None:
    analyzer = EmailThreatAnalyzer()

    findings = analyzer.analyze(
        _email(
            subject="Confidential action required",
            body="Keep this secret and take action immediately.",
        )
    )

    assert "SOCIAL_ENGINEERING" in _rule_ids(findings)


def test_impersonation_detection() -> None:
    analyzer = EmailThreatAnalyzer()

    findings = analyzer.analyze(
        _email(
            subject="Bank security",
            body="I am from your bank. Please verify your account.",
        )
    )

    assert "IMPERSONATION_LANGUAGE" in _rule_ids(findings)


def test_reply_to_mismatch_uses_forensic_result() -> None:
    analyzer = EmailThreatAnalyzer()

    forensic = EmailForensicResult(
        identity_analysis=IdentityAnalysis(
            from_address="security@example.com",
            from_domain="example.com",
            reply_to_addresses=("attacker@evil.example",),
            reply_to_domains=("evil.example",),
            reply_to_domain_match=False,
        )
    )

    findings = analyzer.analyze(
        _email(
            subject="Account notice",
            body="Please review this message.",
        ),
        forensic_result=forensic,
    )

    mismatch = next(
        finding
        for finding in findings
        if finding.rule_id == "REPLY_TO_MISMATCH"
    )

    assert mismatch.severity == "HIGH"
    assert mismatch.value == "attacker@evil.example"


def test_return_path_mismatch_uses_forensic_result() -> None:
    analyzer = EmailThreatAnalyzer()

    forensic = EmailForensicResult(
        identity_analysis=IdentityAnalysis(
            from_address="security@example.com",
            from_domain="example.com",
            return_path="mailer@evil.example",
            return_path_domain="evil.example",
            return_path_domain_match=False,
        )
    )

    findings = analyzer.analyze(
        _email(
            subject="Account notice",
            body="Please review this message.",
        ),
        forensic_result=forensic,
    )

    mismatch = next(
        finding
        for finding in findings
        if finding.rule_id == "RETURN_PATH_MISMATCH"
    )

    assert mismatch.severity == "HIGH"
    assert mismatch.value == "mailer@evil.example"


def test_suspicious_url_uses_existing_ioc_result() -> None:
    analyzer = EmailThreatAnalyzer()

    ioc_result = EmailIOCExtractionResult(
        iocs=(
            EmailIOC(
                value="https://bit.ly/login",
                ioc_type=IOCType.URL,
                confidence=ExtractionConfidence.HIGH,
            ),
        )
    )

    findings = analyzer.analyze(
        _email(
            subject="Login",
            body="Open the link.",
        ),
        ioc_result=ioc_result,
    )

    suspicious = next(
        finding
        for finding in findings
        if finding.rule_id == "SUSPICIOUS_URL"
    )

    assert suspicious.value == "https://bit.ly/login"


def test_normal_url_is_not_marked_suspicious() -> None:
    analyzer = EmailThreatAnalyzer()

    ioc_result = EmailIOCExtractionResult(
        iocs=(
            EmailIOC(
                value="https://example.com/login",
                ioc_type=IOCType.URL,
                confidence=ExtractionConfidence.HIGH,
            ),
        )
    )

    findings = analyzer.analyze(
        _email(
            subject="Company portal",
            body="Please visit the company portal.",
        ),
        ioc_result=ioc_result,
    )

    assert "SUSPICIOUS_URL" not in _rule_ids(findings)


def test_ip_based_url_is_correlated_from_ioc_result() -> None:
    analyzer = EmailThreatAnalyzer()

    ioc_result = EmailIOCExtractionResult(
        iocs=(
            EmailIOC(
                value="http://192.0.2.10/login",
                ioc_type=IOCType.URL,
                confidence=ExtractionConfidence.HIGH,
            ),
        )
    )

    findings = analyzer.analyze(
        _email(body="Please login using the link."),
        ioc_result=ioc_result,
    )

    assert "SUSPICIOUS_URL" in _rule_ids(findings)


def test_multiple_findings_are_returned() -> None:
    analyzer = EmailThreatAnalyzer()

    findings = analyzer.analyze(
        _email(
            subject="URGENT bank verification",
            body=(
                "I am from your bank. "
                "Your account will be suspended. "
                "Please send your password and transfer money immediately."
            ),
        )
    )

    rule_ids = _rule_ids(findings)

    assert "PHISHING_URGENT_LANGUAGE" in rule_ids
    assert "CREDENTIAL_REQUEST" in rule_ids
    assert "FINANCIAL_REQUEST" in rule_ids
    assert "SOCIAL_ENGINEERING" in rule_ids
    assert "IMPERSONATION_LANGUAGE" in rule_ids


def test_benign_email_has_no_findings() -> None:
    analyzer = EmailThreatAnalyzer()

    findings = analyzer.analyze(
        _email(
            subject="Team meeting tomorrow",
            body="Hi team, the meeting is scheduled for tomorrow at 10 AM.",
        )
    )

    assert findings == []


def test_empty_email_has_no_findings() -> None:
    analyzer = EmailThreatAnalyzer()

    findings = analyzer.analyze(EmailMessageData())

    assert findings == []


def test_credential_reference_without_request_is_not_credential_theft() -> None:
    analyzer = EmailThreatAnalyzer()

    findings = analyzer.analyze(
        _email(
            subject="Password reset documentation",
            body="This document explains our password reset procedure.",
        )
    )

    assert "CREDENTIAL_REQUEST" not in _rule_ids(findings)

def test_financial_reference_without_request_is_not_financial_fraud() -> None:
    analyzer = EmailThreatAnalyzer()

    findings = analyzer.analyze(
        _email(
            subject="Finance department report",
            body=(
                "The finance department published the quarterly "
                "payment report for internal review."
            ),
        )
    )

    assert "FINANCIAL_REQUEST" not in _rule_ids(findings)


def test_unrelated_financial_word_does_not_create_financial_request() -> None:
    analyzer = EmailThreatAnalyzer()

    findings = analyzer.analyze(
        _email(
            subject="Quarterly report",
            body="The finance team published the quarterly report.",
        )
    )

    assert "FINANCIAL_REQUEST" not in _rule_ids(findings)


def test_ioc_result_is_consumed_without_reextraction() -> None:
    analyzer = EmailThreatAnalyzer()

    ioc_result = EmailIOCExtractionResult(
        iocs=(
            EmailIOC(
                value="https://bit.ly/login",
                ioc_type=IOCType.URL,
                confidence=ExtractionConfidence.HIGH,
            ),
        )
    )

    findings = analyzer.analyze(
        _email(body="No URL is present in this body."),
        ioc_result=ioc_result,
    )

    suspicious = [
        finding
        for finding in findings
        if finding.rule_id == "SUSPICIOUS_URL"
    ]

    assert len(suspicious) == 1
    assert suspicious[0].value == "https://bit.ly/login"


def test_forensic_result_is_consumed_without_reanalysis() -> None:
    analyzer = EmailThreatAnalyzer()

    forensic = EmailForensicResult(
        identity_analysis=IdentityAnalysis(
            from_domain="example.com",
            reply_to_addresses=("attacker@evil.example",),
            reply_to_domains=("evil.example",),
            reply_to_domain_match=False,
        )
    )

    findings = analyzer.analyze(
        _email(body="This body contains no header mismatch information."),
        forensic_result=forensic,
    )

    assert "REPLY_TO_MISMATCH" in _rule_ids(findings)

def test_service_returns_security_result_for_malicious_email() -> None:
    from email_security.threat_detection import EmailThreatDetectionService

    service = EmailThreatDetectionService()

    result = service.analyze(
        _email(
            subject="Urgent bank verification",
            body=(
                "Please provide your password and OTP "
                "and complete the bank transfer immediately."
            ),
        )
    )

    assert result.verdict == "MALICIOUS"
    assert result.risk_score == 100
    assert "CREDENTIAL_REQUEST" in _rule_ids(result.findings)
    assert "FINANCIAL_REQUEST" in _rule_ids(result.findings)
    assert result.risk is not None
    assert result.risk.score == 100


def test_service_returns_safe_for_benign_email() -> None:
    from email_security.threat_detection import EmailThreatDetectionService

    service = EmailThreatDetectionService()

    result = service.analyze(
        _email(
            subject="Project meeting",
            body="The project meeting is scheduled for tomorrow at 10 AM.",
        )
    )

    assert result.verdict == "SAFE"
    assert result.risk_score == 0
    assert result.findings == []


def test_service_reuses_supplied_ioc_and_forensic_results() -> None:
    from email_security.threat_detection import EmailThreatDetectionService

    forensic = EmailForensicResult(
        identity_analysis=IdentityAnalysis(
            from_address="security@example.com",
            from_domain="example.com",
            reply_to_addresses=("attacker@evil.example",),
            reply_to_domains=("evil.example",),
            reply_to_domain_match=False,
        )
    )

    ioc_result = EmailIOCExtractionResult(
        iocs=(
            EmailIOC(
                value="https://bit.ly/login",
                ioc_type=IOCType.URL,
                confidence=ExtractionConfidence.HIGH,
            ),
        )
    )

    service = EmailThreatDetectionService()

    result = service.analyze(
        _email(body="This email contains no IOC text."),
        forensic_result=forensic,
        ioc_result=ioc_result,
    )

    rule_ids = _rule_ids(result.findings)

    assert "REPLY_TO_MISMATCH" in rule_ids
    assert "SUSPICIOUS_URL" in rule_ids
    assert result.risk_score == 100
    assert result.verdict == "MALICIOUS"


def test_service_analyze_raw_uses_existing_parser() -> None:
    from email_security.threat_detection import EmailThreatDetectionService

    raw_email = (
        "From: security@example.com\n"
        "To: user@example.com\n"
        "Subject: Urgent account verification\n"
        "\n"
        "Please provide your password immediately.\n"
    )

    service = EmailThreatDetectionService()

    result = service.analyze_raw(raw_email)

    assert result.verdict == "MALICIOUS"
    assert "CREDENTIAL_REQUEST" in _rule_ids(result.findings)
