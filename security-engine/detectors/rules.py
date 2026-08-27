from detectors.base import Detector


class RuleBasedDetector(Detector):
    """Initial rule-based security detector."""

    def detect(self, analysis: dict) -> dict:
        risk_score = 0
        reasons = []
        indicators = []

        if analysis.get("contains_suspicious_keyword"):
            risk_score += 50
            reasons.append("Suspicious social-engineering language detected.")
            indicators.append("suspicious_keyword")

        if analysis.get("contains_url"):
            risk_score += 20
            reasons.append("URL detected in input.")
            indicators.append("url")

        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            status = "HIGH"
        elif risk_score >= 30:
            status = "MEDIUM"
        elif risk_score > 0:
            status = "LOW"
        else:
            status = "SAFE"

        return {
            "status": status,
            "risk_score": risk_score,
            "reasons": reasons,
            "indicators": indicators,
        }