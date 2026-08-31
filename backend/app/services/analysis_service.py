from app.schemas.analysis import AnalyzeRequest, AnalyzeResponse

from engine import SecurityEngine


security_engine = SecurityEngine()


def analyze_target(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze a target using the Security Engine."""

    result = security_engine.analyze(
        content=request.target,
    )

    return AnalyzeResponse(
        status=result.status,
        target=request.target,
        risk_score=result.risk_score,
        verdict=result.verdict,
        findings=[
            finding.to_dict()
            for finding in result.findings
        ],
        reasons=result.reasons,
        indicators=result.indicators,
        impact=(
            result.impact.to_dict()
            if result.impact is not None
            else None
        ),
        response=(
            result.response.to_dict()
            if result.response is not None
            else None
        ),
        verification=(
            result.verification.to_dict()
            if result.verification is not None
            else None
        ),
    )
