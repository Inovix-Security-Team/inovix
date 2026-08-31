from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError

from backend.app.api.v1.router import api_router
from backend.app.core.config import settings
from backend.app.core.errors import validation_exception_handler


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Inovix Security Analysis API",
)

app.add_exception_handler(
    RequestValidationError,
    validation_exception_handler,
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/", tags=["Root"])
def root() -> dict[str, str]:
    return {"message": "Inovix API is running"}