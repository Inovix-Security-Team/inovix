from backend.app.schemas.email_analysis import (
    AnalyzeEmailRequest,
    AnalyzeEmailResponse,
)
from email_security.email_parser.email_parser import EmailParser
from email_security.threat_detection.service import (
    EmailThreatDetectionService,
)


email_parser = EmailParser()
email_threat_service = EmailThreatDetectionService()


def analyze_email(
    request: AnalyzeEmailRequest,
) -> AnalyzeEmailResponse:
    """Parse and analyze a raw email."""

    email = email_parser.parse_raw(request.raw_email)

    result = email_threat_service.analyze(email)

    return AnalyzeEmailResponse(
        status="completed",
        sender=email.sender,
        recipients=email.recipients,
        subject=email.subject,
        risk_score=result.risk_score,
        verdict=result.verdict,
        findings=[
            finding.to_dict()
            for finding in result.findings
        ],
        reasons=result.reasons,
        indicators=result.indicators,
        risk=(
            result.risk.to_dict()
            if result.risk is not None
            else None
        ),
    )