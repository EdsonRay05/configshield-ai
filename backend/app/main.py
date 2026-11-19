"""Local API with health and supported Deployment parsing."""

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel
from app.routers.analysis import router as analysis_router

app = FastAPI(title="ConfigShield AI", version="0.1.0")
app.include_router(analysis_router)


class HealthResponse(BaseModel):
    """The basic service availability contract, not scanner readiness."""

    status: Literal["ok"]
    service: Literal["configshield-ai"]


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="configshield-ai")
