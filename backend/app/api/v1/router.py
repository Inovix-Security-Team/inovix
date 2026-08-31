from fastapi import APIRouter

from backend.app.api.v1.endpoints import (
    analyze,
    email_analysis,
    health,
)


api_router = APIRouter()

api_router.include_router(
    health.router,
    tags=["Health"],
)

api_router.include_router(
    analyze.router,
    tags=["Analysis"],
)

api_router.include_router(
    email_analysis.router,
    tags=["Email Analysis"],
)