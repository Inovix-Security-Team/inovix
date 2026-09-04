from fastapi import FastAPI
from api.routes.email import router as email_router

app = FastAPI(title="INOVIX API")


app.include_router(
    email_router,
    prefix="/api/v1/email",
    tags=["Email Analysis"]
)


@app.get("/")
def home():
    return {
        "message": "INOVIX API is running"
    }
