from app.schemas.analysis import AnalyzeRequest, AnalyzeResponse


def analyze_target(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Temporary mock analysis.

    This service layer is intentionally separated from the API endpoint
    so that the mock implementation can later be replaced by the
    Inovix security engine.
    """

    return AnalyzeResponse(
        status="completed",
        target=request.target,
        risk_level="low",
        score=10,
        message="Mock analysis completed successfully.",
    )