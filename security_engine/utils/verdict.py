def generate_verdict(risk_score: int) -> str:
    """Convert a 0-100 risk score into a security verdict."""

    if risk_score < 0 or risk_score > 100:
        return "UNKNOWN"

    if risk_score == 0:
        return "SAFE"

    if risk_score < 80:
        return "SUSPICIOUS"

    return "MALICIOUS"