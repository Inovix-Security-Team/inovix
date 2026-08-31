from fastapi import APIRouter

from backend.app.schemas.analysis import AnalyzeRequest, AnalyzeResponse
from backend.app.services.analysis_service import analyze_target

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    return analyze_target(request)