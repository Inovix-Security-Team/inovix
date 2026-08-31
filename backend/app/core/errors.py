from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    details = []

    for error in exc.errors():
        error_detail = {
            "type": error.get("type"),
            "loc": error.get("loc"),
            "msg": error.get("msg"),
            "input": error.get("input"),
        }

        # Remove non-JSON-serializable context such as ValueError objects.
        if "ctx" in error:
            ctx = error["ctx"]

            serializable_ctx = {}

            for key, value in ctx.items():
                if isinstance(value, (str, int, float, bool)) or value is None:
                    serializable_ctx[key] = value
                else:
                    serializable_ctx[key] = str(value)

            error_detail["ctx"] = serializable_ctx

        details.append(error_detail)

    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_error",
            "message": "The request data is invalid.",
            "details": details,
        },
    )
