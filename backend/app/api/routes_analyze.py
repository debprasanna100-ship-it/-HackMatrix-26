"""Analysis endpoints: submit a URL/message, read reports back, correlate.

Access control (Step 4): all routes take the CurrentUser dependency. When
TRUSTLENS_AUTH_REQUIRED is false (default demo mode) anonymous callers pass as
None and behaviour is unchanged. When true: analyze attaches the caller as
report owner; report reads are owner-or-public (404 hides foreign private
reports); DELETE is owner-only (403).
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..models.schemas import AnalyzeUrlRequest, AnalysisReport
from ..pipeline.correlation import build_matches, extract_indicators, tfidf_cosine
from ..pipeline.fetcher import SafeFetcher
from ..pipeline.normalizer import UrlNormalizationError
from ..pipeline.runner import analyze_url
from ..storage import repository
from .auth import CurrentUser, can_read_report, is_admin, require_owner

router = APIRouter(prefix="/api/v1", tags=["analysis"])


@router.post(
    "/analyze/url",
    response_model=AnalysisReport,
    responses={400: {"model": dict, "description": "Input could not be normalised as a URL"}},
    summary="Analyse a URL and return an evidence-backed risk report",
)
async def analyze_url_endpoint(body: AnalyzeUrlRequest, request: Request,
                               user: CurrentUser) -> AnalysisReport:
    settings = request.app.state.settings
    fetcher: SafeFetcher | None = getattr(request.app.state, "fetcher", None)
    try:
        report = await analyze_url(body.url, settings, fetcher=fetcher,
                                   owner_id=user["id"] if user else None)
    except UrlNormalizationError as exc:
        raise HTTPException(status_code=400, detail={"code": "invalid_url", "message": str(exc)}) from exc
    return report


@router.get("/reports/{report_id}", response_model=AnalysisReport)
async def get_report_endpoint(report_id: str, request: Request, user: CurrentUser) -> AnalysisReport:
    settings = request.app.state.settings
    meta = await asyncio.to_thread(repository.get_report_access_meta, report_id)
    if meta is None:
        raise HTTPException(status_code=404, detail={"code": "report_not_found",
                                                     "message": f"No report with id '{report_id}'."})
    # 404 (not 403) for foreign private reports: do not leak their existence.
    if not can_read_report(user, meta, settings):
        raise HTTPException(status_code=404, detail={"code": "report_not_found",
                                                     "message": f"No report with id '{report_id}'."})
    stored = await asyncio.to_thread(repository.get_report, report_id)
    if stored is None:
        raise HTTPException(status_code=404, detail={"code": "report_not_found",
                                                     "message": f"No report with id '{report_id}'."})
    return AnalysisReport.model_validate(stored)


class VisibilityRequest(BaseModel):
    is_public: bool


@router.patch("/reports/{report_id}", summary="Owner: toggle whether the report is publicly readable")
async def set_report_visibility(report_id: str, body: VisibilityRequest,
                                request: Request, user: CurrentUser) -> dict:
    settings = request.app.state.settings
    meta = await asyncio.to_thread(repository.get_report_access_meta, report_id)
    if meta is None:
        raise HTTPException(status_code=404, detail={"code": "report_not_found",
                                                     "message": f"No report with id '{report_id}'."})
    require_owner(user, meta, settings)
    ok = await asyncio.to_thread(repository.set_report_visibility, report_id, body.is_public)
    return {"report_id": report_id, "is_public": body.is_public, "updated": ok}


@router.delete("/reports/{report_id}", summary="Delete a stored report (owner-only in multi-tenant mode)")
async def delete_report_endpoint(report_id: str, request: Request, user: CurrentUser) -> dict:
    """Privacy control: in demo mode whoever holds the unguessable report ID can
    delete it; in multi-tenant mode only the owner (or an admin) can — 403
    otherwise. Deleting also removes the report's correlation indicators and
    chain-commitment record.
    """
    settings = request.app.state.settings
    meta = await asyncio.to_thread(repository.get_report_access_meta, report_id)
    if meta is None:
        raise HTTPException(status_code=404, detail={"code": "report_not_found",
                                                     "message": f"No report with id '{report_id}'."})
    require_owner(user, meta, settings)
    deleted = await asyncio.to_thread(repository.delete_report, report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail={"code": "report_not_found",
                                                     "message": f"No report with id '{report_id}'."})
    return {"deleted": True, "report_id": report_id}


@router.get("/reports")
async def list_reports_endpoint(request: Request, user: CurrentUser,
                                limit: int = 20, offset: int = 0) -> dict:
    settings = request.app.state.settings
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    include_all = (not settings.auth_required) or is_admin(user)
    owner_id = user["id"] if (user and not include_all) else None
    return await asyncio.to_thread(
        repository.list_reports, limit, offset, owner_id=owner_id, include_all=include_all
    )


@router.get("/correlate/{report_id}", summary="Rule-based correlation for a stored report")
async def correlate_endpoint(report_id: str, request: Request, user: CurrentUser) -> dict:
    settings = request.app.state.settings
    meta = await asyncio.to_thread(repository.get_report_access_meta, report_id)
    if meta is None or not can_read_report(user, meta, settings):
        raise HTTPException(status_code=404, detail={"code": "report_not_found",
                                                     "message": f"No report with id '{report_id}'."})
    stored = await asyncio.to_thread(repository.get_report, report_id)
    if stored is None:
        raise HTTPException(status_code=404, detail={"code": "report_not_found",
                                                     "message": f"No report with id '{report_id}'."})
    # Audit M-D: the indicator/text lookups scan shared tables — without a
    # visibility scope, any authenticated user could harvest FOREIGN PRIVATE
    # report IDs (capability addresses), classifications, and text similarity
    # from the matches. Scope to reports the caller may read (own + public);
    # demo mode and admins see everything, as elsewhere.
    correlation_visibility = None
    if settings.auth_required and user is not None and not is_admin(user):
        correlation_visibility = {"owner_id": user["id"]}
    report = AnalysisReport.model_validate(stored)
    indicators = extract_indicators(report)
    hits = await asyncio.to_thread(
        repository.find_indicator_hits, indicators, report_id, correlation_visibility
    )
    texts = await asyncio.to_thread(
        repository.get_report_texts, report_id, 100, correlation_visibility
    )
    similar = tfidf_cosine(report.raw_input, texts)
    payload = build_matches(report, hits, similar)
    payload["report_id"] = report_id
    return payload


@router.get("/meta", summary="Pipeline stages and integration availability")
async def meta_endpoint(request: Request) -> dict:
    from ..config import Settings as _Settings  # local import to avoid cycles
    from ..pipeline.intel import IntelRegistry
    from ..web3.registry import chain_enabled, registry_address_of

    settings: _Settings = request.app.state.settings
    registry_configured = chain_enabled(settings)
    # Audit C3: report the EFFECTIVE registry address — the explicit setting
    # or, when empty, the address auto-discovered from the deployment JSON
    # (docker-compose wiring). settings.registry_address alone is empty in
    # compose deployments even though chain features are fully configured.
    effective_registry_address = registry_address_of(settings)
    # Per-provider configuration status only ("active" | "unconfigured" |
    # "failed" | "rate_limited"). status() performs no network requests and
    # never includes key material.
    intel_status = IntelRegistry(settings).status()
    return {
        "pipeline_stages": ["url-normalisation", "domain-heuristics", "page-fetch",
                            "tls-analysis", "ct-history", "dns-records", "header-checks",
                            "threat-intel", "scoring", "correlation"],
        "intel_providers": intel_status,
        "integrations": {
            "threat_intel": "key-based providers (set TRUSTLENS_*_API_KEY to activate)",
            "tls_analysis": "active (Phase 2)",
            "scoring_engine": "active (Phase 2)",
            "web3_registry": (
                f"configured at {effective_registry_address}"
                if registry_configured
                else "not_configured (set TRUSTLENS_REGISTRY_ADDRESS)"
            ),
            "llm_explanations": (
                f"active ({settings.llm_model} via {settings.llm_base_url})"
                if settings.llm_api_key
                else "offline rule-based fallback (set TRUSTLENS_LLM_API_KEY for AI explanations)"
            ),
            "message_analysis": "active (Phase 5)",
            "dns_records": "active (passive A/MX/NS/TXT via dnspython; optional check)",
            "correlation": "active (rule-based, automatic on every persisted report)",
            "report_verification": (
                "active (report ID, raw 0x-hash, or supplied report JSON via POST /api/v1/verify/report)"
            ),
            "report_privacy": (
                "reports are capability-addressed (unguessable 128-bit IDs); extracted emails/phones "
                "are never stored; DELETE /api/v1/reports/{id} and TRUSTLENS_REPORT_RETENTION_DAYS "
                "provide deletion"
            ),
            "authentication": (
                "required (Bearer JWT or X-API-Key)"
                if settings.auth_required
                else "disabled (demo mode: set TRUSTLENS_AUTH_REQUIRED=true for multi-tenant auth)"
            ),
        },
    }
