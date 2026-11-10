"""Health check endpoint."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Request

router = APIRouter(tags=["health"])


@router.get("/health")
async def health(request: Request) -> dict:
    settings = getattr(request.app.state, "settings", None)
    return {
        "status": "ok",
        "app": settings.app_name if settings else "TrustLens",
        "version": settings.version if settings else "unknown",
        "time": datetime.now(timezone.utc).isoformat(),
    }
