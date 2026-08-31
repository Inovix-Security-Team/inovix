from fastapi import APIRouter

from backend.app.schemas.email_analysis import (
    AnalyzeEmailRequest,
    AnalyzeEmailResponse,
)
from backend.app.services.email_analysis_service import analyze_email

router = APIRouter()


@router.post(
    "/analyze-email",
    response_model=AnalyzeEmailResponse,
)
def analyze_email_endpoint(
    request: AnalyzeEmailRequest,
) -> AnalyzeEmailResponse:
    return analyze_email(request)