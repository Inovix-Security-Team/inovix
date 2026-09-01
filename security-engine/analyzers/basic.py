import re

from security_engine.analyzers.base import Analyzer
from security_engine.models import AnalysisInput


class BasicAnalyzer(Analyzer):
    """Simple rule-based analyzer used for the security engine."""

    def analyze(self, data: AnalysisInput) -> dict:
        content = data.content.lower()

        return {
            "content_length": len(data.content),

            "contains_url": (
                "http://" in content
                or "https://" in content
            ),

            "contains_suspicious_keyword": any(
                keyword in content
                for keyword in (
                    "verify account",
                    "urgent action",
                    "suspicious login",
                )
            ),

            "contains_credential_request": any(
                keyword in content
                for keyword in (
                    "password",
                    "otp",
                    "one time password",
                    "one-time password",
                    "login credential",
                    "credentials",
                )
            ),

            "contains_financial_request": any(
                keyword in content
                for keyword in (
                    "transfer money",
                    "send money",
                    "money transfer",
                    "upi account",
                    "upi id",
                    "bank transfer",
                )
            ),

            "contains_impersonation": any(
                phrase in content
                for phrase in (
                    "i am from your bank",
                    "i'm from your bank",
                    "i am from the bank",
                    "i'm from the bank",
                    "from your bank",
                    "from the bank",
                )
            ),
        }
