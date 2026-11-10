"""Message-analysis endpoint (Phase 5)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ..models.schemas import AnalysisReport
from ..pipeline.message import analyze_message
from .auth import CurrentUser

router = APIRouter(prefix="/api/v1", tags=["analysis"])


class AnalyzeMessageRequest(BaseModel):
    message: str = Field(
        min_length=8,
        max_length=20_000,
        description="Pasted email/SMS/chat text. Treated as untrusted data throughout.",
    )


@router.post("/analyze/message", response_model=AnalysisReport,
             summary="Analyse a pasted suspicious message (email/SMS/chat)")
async def analyze_message_endpoint(body: AnalyzeMessageRequest, request: Request,
                                   user: CurrentUser) -> AnalysisReport:
    settings = request.app.state.settings
    fetcher = getattr(request.app.state, "fetcher", None)
    try:
        return await analyze_message(body.message, settings, fetcher=fetcher,
                                     owner_id=user["id"] if user else None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"code": "invalid_message",
                                                     "message": str(exc)}) from exc
