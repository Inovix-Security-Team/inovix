from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatRule:
    """Deterministic, explainable email threat rule."""

    rule_id: str
    severity: str
    reason: str
    patterns: tuple[str, ...]
    indicator: str


PHISHING_URGENT_LANGUAGE = ThreatRule(
    rule_id="PHISHING_URGENT_LANGUAGE",
    severity="MEDIUM",
    reason=(
        "Urgent language is used to pressure the recipient "
        "into immediate action."
    ),
    patterns=(
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bact now\b",
        r"\bright away\b",
        r"\bwithin\s+24\s+hours\b",
        r"\blimited time\b",
    ),
    indicator="phishing_urgent_language",
)

CREDENTIAL_REQUEST = ThreatRule(
    rule_id="CREDENTIAL_REQUEST",
    severity="HIGH",
    reason=(
        "The email requests credentials or authentication "
        "information."
    ),
    patterns=(
        r"\b(?:send|provide|share|submit|enter|give)\b"
        r".{0,60}"
        r"\b(?:password|passcode|credentials?|otp|one[- ]time password|"
        r"verification code|security verification|username|pin)\b",
        r"\b(?:password|passcode|credentials?|otp|one[- ]time password|"
        r"verification code|security verification|username|pin)\b"
        r".{0,60}"
        r"\b(?:send|provide|share|submit|enter|give)\b",
        r"\bverify\b.{0,60}\b(?:account|identity|login)\b"
        r".{0,60}"
        r"\b(?:code|otp|password|credentials?)\b",
        r"\b(?:account|login)\b.{0,60}\bverification\b"
        r".{0,60}\b(?:code|otp|password)\b",
    ),
    indicator="credential_request",
)

FINANCIAL_REQUEST = ThreatRule(
    rule_id="FINANCIAL_REQUEST",
    severity="HIGH",
    reason=(
        "The email requests money, payment, transfer, or "
        "financial account information."
    ),
    patterns=(
        r"\b(?:please\s+)?(?:make|complete|process|approve|submit)\b"
        r".{0,60}"
        r"\b(?:payment|bank transfer|wire transfer|money transfer|"
        r"fund transfer|invoice payment)\b",

        r"\b(?:send|transfer|wire)\b"
        r".{0,60}"
        r"\b(?:money|funds|payment|amount|cash)\b",

        r"\b(?:money|funds|payment|amount|cash)\b"
        r".{0,60}"
        r"\b(?:send|transfer|wire)\b",

        r"\b(?:update|change|replace|confirm|provide|send)\b"
        r".{0,60}"
        r"\b(?:bank account|account number|upi|upi id|card number|"
        r"credit card|debit card)\b",

        r"\b(?:gift card|bitcoin|cryptocurrency|crypto payment)\b"
        r".{0,60}"
        r"\b(?:buy|purchase|send|transfer|pay|provide)\b",

        r"\b(?:pay|payment|invoice)\b"
        r".{0,60}"
        r"\b(?:now|immediately|today|urgently|urgent)\b",
    ),
    indicator="financial_request",
)

SOCIAL_ENGINEERING = ThreatRule(
    rule_id="SOCIAL_ENGINEERING",
    severity="MEDIUM",
    reason=(
        "The email uses pressure, fear, secrecy, authority, "
        "or financial pressure consistent with social engineering."
    ),
    patterns=(
        r"\bdo not tell anyone\b",
        r"\bkeep this secret\b",
        r"\bconfidential\b",
        r"\bimmediately\b",
        r"\baction required\b",
        r"\baccount will be suspended\b",
        r"\byou will lose access\b",
        r"\blegal action\b",
        r"\bpolice action\b",
    ),
    indicator="social_engineering",
)

IMPERSONATION = ThreatRule(
    rule_id="IMPERSONATION_LANGUAGE",
    severity="CRITICAL",
    reason=(
        "The email contains language claiming to represent "
        "a trusted organization or authority."
    ),
    patterns=(
        r"\bi am from your bank\b",
        r"\bi'm from your bank\b",
        r"\bi am from the bank\b",
        r"\bi'm from the bank\b",
        r"\bfrom your bank\b",
        r"\bfrom the bank\b",
        r"\bbank support\b",
        r"\bbank representative\b",
        r"\bcustomer support\b",
        r"\bgovernment official\b",
        r"\bincome tax department\b",
        r"\bpolice department\b",
        r"\bdelivery service\b",
        r"\bpayment support\b",
    ),
    indicator="impersonation_language",
)


RULES = (
    PHISHING_URGENT_LANGUAGE,
    CREDENTIAL_REQUEST,
    FINANCIAL_REQUEST,
    SOCIAL_ENGINEERING,
    IMPERSONATION,
)


def contains_rule_pattern(text: str, rule: ThreatRule) -> bool:
    """Return whether any pattern belonging to a rule matches text."""

    normalized = text.casefold()

    return any(
        re.search(pattern, normalized, flags=re.IGNORECASE) is not None
        for pattern in rule.patterns
    )
