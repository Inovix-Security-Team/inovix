from analyzers.basic import BasicAnalyzer
from detectors.rules import RuleBasedDetector


def analyze_text(text: str) -> list:
    analyzer = BasicAnalyzer()
    detector = RuleBasedDetector()

    analysis = analyzer.analyze(
        type(
            "AnalysisInput",
            (),
            {"content": text},
        )()
    )

    return detector.detect(analysis)


def test_detection_safe_event():
    findings = analyze_text("User completed a normal login successfully.")

    assert findings == []


def test_detection_url():
    findings = analyze_text(
        "Please visit https://example.com to continue."
    )

    assert any(
        finding.rule_id == "URL_PRESENT"
        for finding in findings
    )


def test_detection_credential_request():
    findings = analyze_text(
        "Please send your password and OTP."
    )

    assert any(
        finding.rule_id == "CREDENTIAL_REQUEST"
        for finding in findings
    )


def test_detection_financial_request():
    findings = analyze_text(
        "Please complete the bank transfer immediately."
    )

    assert any(
        finding.rule_id == "FINANCIAL_REQUEST"
        for finding in findings
    )


def test_detection_impersonation():
    findings = analyze_text(
        "I am from your bank. Please verify your account."
    )

    assert any(
        finding.rule_id == "IMPERSONATION_LANGUAGE"
        for finding in findings
    )


def test_detection_multiple_findings():
    findings = analyze_text(
        "Urgent action required. Send your password "
        "and bank transfer details to https://example.com."
    )

    rule_ids = {finding.rule_id for finding in findings}

    assert "SUSPICIOUS_LANGUAGE" in rule_ids
    assert "URL_PRESENT" in rule_ids
    assert "CREDENTIAL_REQUEST" in rule_ids
    assert "FINANCIAL_REQUEST" in rule_ids

    assert len(findings) >= 4
