from email_security.email_forensics import EmailForensicsAnalyzer
from email_security.email_models.email_models import EmailMessageData


def make_email(
    *,
    sender="Alice <alice@example.com>",
    reply_to=None,
    return_path="<alice@example.com>",
    received=None,
    authentication_headers=None,
):
    return EmailMessageData(
        sender=sender,
        recipients=["victim@example.net"],
        cc=[],
        reply_to=reply_to or [],
        return_path=return_path,
        subject="Synthetic forensic test",
        date=None,
        message_id="<test@example.com>",
        received=received or [],
        authentication_headers=authentication_headers or {},
        text_body="Test body",
        html_body=None,
        attachments=[],
    )


def auth(
    *,
    spf=None,
    dkim=None,
    dmarc=None,
    mailfrom=None,
    header_from=None,
    policy=None,
):
    parts = ["mx.example.net"]

    if spf:
        parts.append(f"spf={spf}")

    if mailfrom:
        parts.append(f"smtp.mailfrom={mailfrom}")

    if dkim:
        parts.append(f"dkim={dkim}")

    if dmarc:
        parts.append(f"dmarc={dmarc}")

    if header_from:
        parts.append(f"header.from={header_from}")

    if policy:
        parts.append(f"policy={policy}")

    return {
        "Authentication-Results": "; ".join(parts),
    }


def codes(result):
    return {indicator.code for indicator in result.anomalies}


# ---------------------------------------------------------------------
# Received headers
# ---------------------------------------------------------------------


def test_received_single_header():
    email = make_email(
        received=[
            "from mail.example.com (mail.example.com [198.51.100.20]) "
            "by mx.example.net"
        ]
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert len(result.received_hops) == 1
    assert result.received_hops[0].hostname == "mail.example.com"
    assert result.received_hops[0].ip_address == "198.51.100.20"


def test_received_multiple_headers_preserve_order():
    email = make_email(
        received=[
            "from first.example.com [198.51.100.10] by second.example.net",
            "from second.example.net [203.0.113.20] by mx.example.net",
        ]
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert len(result.received_hops) == 2
    assert result.received_hops[0].hostname == "first.example.com"
    assert result.received_hops[1].hostname == "second.example.net"


def test_received_ipv4_extraction():
    email = make_email(
        received=[
            "from relay.example.com [192.0.2.44] by mx.example.net"
        ]
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.received_hops[0].ip_address == "192.0.2.44"


def test_received_ipv6_extraction():
    email = make_email(
        received=[
            "from relay.example.com [2001:db8::42] by mx.example.net"
        ]
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.received_hops[0].ip_address == "2001:db8::42"


def test_candidate_origin_uses_oldest_usable_ip():
    email = make_email(
        received=[
            "from edge.example.net [198.51.100.55] by mx.example.net",
            "from origin.example.com [8.8.8.8] by edge.example.net",
        ]
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.candidate_origin_ip == "8.8.8.8"


def test_candidate_origin_is_none_when_no_ip_exists():
    email = make_email(
        received=[
            "from relay.example.com by mx.example.net",
        ]
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.candidate_origin_ip is None


def test_private_received_ip_is_detected():
    email = make_email(
        received=[
            "from workstation.example [192.168.1.10] by mx.example.net"
        ]
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.received_hops[0].is_private_or_reserved is True
    assert "PRIVATE_OR_RESERVED_RECEIVED_IP" in codes(result)


def test_malformed_received_header_is_safe():
    email = make_email(
        received=[
            "this is not a meaningful received header",
        ]
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.received_hops[0].parse_successful is False
    assert "MALFORMED_RECEIVED_HEADER" in codes(result)


# ---------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------


def test_spf_pass_is_parsed():
    email = make_email(
        authentication_headers=auth(
            spf="pass",
            mailfrom="alice@example.com",
        )
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.spf.result == "pass"
    assert result.spf.mail_from == "alice@example.com"


def test_spf_fail_creates_indicator():
    email = make_email(
        authentication_headers=auth(spf="fail")
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.spf.result == "fail"
    assert "SPF_FAILURE" in codes(result)


def test_spf_softfail_is_supported():
    email = make_email(
        authentication_headers=auth(spf="softfail")
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.spf.result == "softfail"


def test_spf_none_is_supported():
    email = make_email(
        authentication_headers=auth(spf="none")
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.spf.result == "none"


# ---------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------


def test_dkim_pass_signing_domain_and_selector():
    email = make_email(
        authentication_headers={
            "Authentication-Results": (
                "mx.example.net; dkim=pass; header.from=example.com"
            ),
            "DKIM-Signature": (
                "v=1; a=rsa-sha256; d=example.com; s=selector1; "
                "bh=abc; b=xyz"
            ),
        }
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.dkim.result == "pass"
    assert result.dkim.signing_domain == "example.com"
    assert result.dkim.selector == "selector1"


def test_dkim_fail_creates_indicator():
    email = make_email(
        authentication_headers={
            "Authentication-Results": "mx.example.net; dkim=fail",
            "DKIM-Signature": "v=1; d=example.com; s=selector1",
        }
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.dkim.result == "fail"
    assert "DKIM_FAILURE" in codes(result)


def test_missing_dkim_evidence_is_safe():
    email = make_email(
        authentication_headers=auth(spf="pass")
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.dkim.result is None
    assert result.dkim.signing_domain is None
    assert result.dkim.selector is None


# ---------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------


def test_dmarc_pass_header_from_and_policy():
    email = make_email(
        authentication_headers=auth(
            dmarc="pass",
            header_from="example.com",
            policy="none",
        )
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.dmarc.result == "pass"
    assert result.dmarc.header_from == "example.com"
    assert result.dmarc.policy == "none"


def test_dmarc_fail_creates_indicator():
    email = make_email(
        authentication_headers=auth(dmarc="fail")
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.dmarc.result == "fail"
    assert "DMARC_FAILURE" in codes(result)


def test_missing_dmarc_is_safe():
    email = make_email(
        authentication_headers=auth(spf="pass")
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.dmarc.result is None


# ---------------------------------------------------------------------
# Sender identity
# ---------------------------------------------------------------------


def test_matching_sender_identities():
    email = make_email(
        sender="Alice <alice@example.com>",
        reply_to=["Alice <alice@example.com>"],
        return_path="<alice@example.com>",
    )

    result = EmailForensicsAnalyzer().analyze(email)

    identity = result.identity_analysis

    assert identity.from_domain == "example.com"
    assert identity.reply_to_domain_match is True
    assert identity.return_path_domain_match is True

    assert "FROM_REPLY_TO_MISMATCH" not in codes(result)
    assert "FROM_RETURN_PATH_MISMATCH" not in codes(result)


def test_reply_to_domain_mismatch():
    email = make_email(
        sender="Alice <alice@example.com>",
        reply_to=["Support <support@attacker.test>"],
        return_path="<alice@example.com>",
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.identity_analysis.reply_to_domain_match is False
    assert "FROM_REPLY_TO_MISMATCH" in codes(result)


def test_return_path_domain_mismatch():
    email = make_email(
        sender="Alice <alice@example.com>",
        return_path="<bounce@other.test>",
    )

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.identity_analysis.return_path_domain_match is False
    assert "FROM_RETURN_PATH_MISMATCH" in codes(result)


# ---------------------------------------------------------------------
# Missing authentication
# ---------------------------------------------------------------------


def test_missing_authentication_evidence_is_informational():
    email = make_email()

    result = EmailForensicsAnalyzer().analyze(email)

    indicator = next(
        item
        for item in result.anomalies
        if item.code == "AUTHENTICATION_EVIDENCE_MISSING"
    )

    assert indicator.severity == "INFO"


# ---------------------------------------------------------------------
# Evidence preservation
# ---------------------------------------------------------------------


def test_received_raw_header_is_preserved():
    raw = (
        "from relay.example.com [8.8.8.8] "
        "by mx.example.net"
    )

    email = make_email(received=[raw])

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.received_hops[0].raw_header == raw
    assert any(
        evidence.raw_value == raw
        for evidence in result.evidence
    )


def test_anomaly_contains_explainable_evidence():
    email = make_email(
        authentication_headers=auth(spf="fail")
    )

    result = EmailForensicsAnalyzer().analyze(email)

    indicator = next(
        item for item in result.anomalies
        if item.code == "SPF_FAILURE"
    )

    assert indicator.evidence
    assert indicator.evidence[0].source == "SPF"
    assert indicator.evidence[0].reason


def test_no_authentication_headers_does_not_crash():
    email = make_email(authentication_headers={})

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.spf.result is None
    assert result.dkim.result is None
    assert result.dmarc.result is None


def test_empty_received_headers_are_supported():
    email = make_email(received=[])

    result = EmailForensicsAnalyzer().analyze(email)

    assert result.received_hops == ()
    assert result.candidate_origin_ip is None
