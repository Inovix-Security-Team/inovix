import re

from models import AnalysisInput
from analyzers.base import Analyzer


URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)
IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


class BasicAnalyzer(Analyzer):
    """Rule-based analyzer for security indicators."""

    def analyze(self, data: AnalysisInput) -> dict:
        content = data.content.lower()

        urls = URL_PATTERN.findall(data.content)
        ip_addresses = IP_PATTERN.findall(data.content)

        return {
            "content_length": len(data.content),

            # Extracted IOC values
            "urls": urls,
            "ip_addresses": ip_addresses,

            # URL / phishing indicators
            "contains_url": bool(urls),

            "contains_ip_url": any(
                re.search(
                    r"https?://(?:\d{1,3}\.){3}\d{1,3}(?:[/:]|$)",
                    url,
                    re.IGNORECASE,
                )
                for url in urls
            ),

            "contains_url_shortener": any(
                domain in content
                for domain in (
                    "bit.ly/",
                    "tinyurl.com/",
                    "t.co/",
                    "goo.gl/",
                    "is.gd/",
                    "cutt.ly/",
                )
            ),

            "contains_suspicious_tld": any(
                tld in content
                for tld in (
                    ".tk/",
                    ".top/",
                    ".xyz/",
                    ".click/",
                    ".gq/",
                    ".ml/",
                )
            ),

            # Existing social-engineering indicators
            "contains_suspicious_keyword": any(
                keyword in content
                for keyword in (
                    "verify account",
                    "urgent action",
                    "suspicious login",
                )
            ),

            "contains_urgency": any(
                phrase in content
                for phrase in (
                    "urgent",
                    "immediately",
                    "act now",
                    "right away",
                    "within 24 hours",
                    "limited time",
                )
            ),

            "contains_threat_language": any(
                phrase in content
                for phrase in (
                    "account will be suspended",
                    "account has been suspended",
                    "your account will be closed",
                    "legal action",
                    "police action",
                    "you will lose access",
                )
            ),

            "contains_reward_scam": any(
                phrase in content
                for phrase in (
                    "you won",
                    "you have won",
                    "claim your prize",
                    "free prize",
                    "lottery winner",
                    "reward",
                )
            ),

            # Credential phishing
            "contains_credential_request": any(
                keyword in content
                for keyword in (
                    "password",
                    "otp",
                    "one time password",
                    "one-time password",
                    "login credential",
                    "credentials",
                    "passcode",
                    "verification code",
                )
            ),

            # Financial fraud
            "contains_financial_request": any(
                keyword in content
                for keyword in (
                    "transfer money",
                    "send money",
                    "money transfer",
                    "upi account",
                    "upi id",
                    "bank transfer",
                    "payment",
                    "card number",
                    "credit card",
                    "debit card",
                    "crypto payment",
                    "cryptocurrency",
                    "bitcoin payment",
                )
            ),

            # Impersonation
            "contains_impersonation": any(
                phrase in content
                for phrase in (
                    "i am from your bank",
                    "i'm from your bank",
                    "i am from the bank",
                    "i'm from the bank",
                    "from your bank",
                    "from the bank",
                    "bank support",
                    "bank representative",
                    "customer support",
                    "government official",
                    "income tax department",
                    "police department",
                    "delivery service",
                    "payment support",
                )
            ),
        }
