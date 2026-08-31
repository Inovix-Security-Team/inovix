from app.schemas.analysis import AnalyzeRequest, AnalyzeResponse

from security_engine.engine import SecurityEngine


security_engine = SecurityEngine()


def analyze_target(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze a target using the Security Engine."""

    result = security_engine.analyze(
        content=request.target,
    )

    return AnalyzeResponse(
        status="completed",
        target=request.target,
        risk_level=result.verdict.lower(),
        score=result.risk_score,
        message="Security analysis completed successfully.",
    )
