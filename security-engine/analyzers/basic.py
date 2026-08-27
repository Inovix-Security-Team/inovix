from analyzers.base import Analyzer
from models import AnalysisInput


class BasicAnalyzer(Analyzer):
    """Simple rule-based analyzer used for the initial engine."""

    def analyze(self, data: AnalysisInput) -> dict:
        content = data.content.lower()

        return {
            "content_length": len(data.content),
            "contains_url": "http://" in content or "https://" in content,
            "contains_suspicious_keyword": any(
                keyword in content
                for keyword in (
                    "verify account",
                    "urgent action",
                    "suspicious login",
                )
            ),
        }