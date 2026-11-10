"""Report-threat (on-chain commitment) and public verify endpoints (Phase 4).

Flow:
  1. An analysis produces a report; its canonical JSON SHA-256 is stored in
     `integrity.canonical_json_sha256`.
  2. POST /api/v1/reports/{id}/commit recomputes that hash from the stored
     report (tamper check against the stored integrity value), then sends
     submitReport(hash, "url-analysis") to ThreatRegistry. Only the hash and a
     fixed category tag go on-chain — never report content.
  3. GET /api/v1/verify/{report_id_or_0xhash} recomputes/looks up the hash and
     checks it against the chain — usable by anyone, no submission required.
  4. POST /api/v1/verify/report lets anyone verify a SUPPLIED report JSON:
     the server recomputes the canonical hash of the pasted/exported report
     and compares it with the report's own integrity field, an expected hash,
     and (optionally) the on-chain commitment. "The hash exists on-chain" and
     "this supplied report's contents produce that hash" are reported as two
     independent facts.
"""
from __future__ import annotations

import asyncio
import datetime
import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from ..models.schemas import AnalysisReport
from ..storage import repository
from ..web3.registry import (
    CATEGORY_MESSAGE_ANALYSIS,
    CATEGORY_URL_ANALYSIS,
    ChainUnavailableError,
    chain_enabled,
    parse_report_hash,
    recompute_report_hash,
    registry_address_of,
    run_chain,
)
from .auth import CurrentUser, require_owner

logger = logging.getLogger("trustlens.chain")

router = APIRouter(prefix="/api/v1", tags=["chain"])

_HEX32_PREFIX = "0x"
_MAX_VERIFY_REPORT_CHARS = 512_000  # bound the supplied-report payload before hashing


class VerifyReportRequest(BaseModel):
    report: dict[str, Any] = Field(description="A full TrustLens report JSON object (e.g. an exported report).")
    expected_hash: Optional[str] = Field(
        default=None,
        description="Optional 0x-prefixed 32-byte hash the supplied report's contents are compared against.",
    )


def _registry_client(request: Request):
    client = getattr(request.app.state, "registry_client", None)
    if client is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "chain_disabled",
                "message": (
                    "On-chain features are disabled: TRUSTLENS_REGISTRY_ADDRESS is not set "
                    "or the chain master switch is off."
                ),
            },
        )
    return client


def _commit_payload(request: Request, report_id: str, report_hash: str, receipt: dict) -> dict:
    settings = request.app.state.settings
    return {
        "report_id": report_id,
        "report_hash": "0x" + report_hash,
        "tx_hash": "0x" + receipt["tx_hash"] if not receipt["tx_hash"].startswith("0x") else receipt["tx_hash"],
        "contract_address": registry_address_of(settings),
        "chain_id": receipt.get("chain_id", 0),
        "block_number": receipt.get("block_number", 0),
        "gas_used": receipt.get("gas_used", 0),
        "committed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


@router.post(
    "/reports/{report_id}/commit",
    summary="Commit a report's canonical hash to the ThreatRegistry contract",
)
async def commit_report(report_id: str, request: Request, user: CurrentUser) -> dict:
    settings = request.app.state.settings

    stored = await asyncio.to_thread(repository.get_report, report_id)
    if stored is None:
        raise HTTPException(status_code=404, detail={"code": "report_not_found",
                                                     "message": f"No report with id '{report_id}'."})
    # Strict ownership FIRST (authorization precedes capability checks):
    # committing a threat report on-chain is attributed to its reporter —
    # 403 for anyone else (admins excepted). Public/anonymous demo mode
    # (auth disabled) keeps the historical capability behaviour.
    meta = await asyncio.to_thread(repository.get_report_access_meta, report_id)
    if meta is not None:
        require_owner(user, meta, settings)

    client = _registry_client(request)

    existing = await asyncio.to_thread(repository.get_commitment, report_id)
    if existing is not None:
        raise HTTPException(status_code=409, detail={
            "code": "already_committed",
            "message": "This report is already committed on-chain.",
            "details": existing,
        })

    recomputed = recompute_report_hash(stored)
    stored_hash = (stored.get("integrity") or {}).get("canonical_json_sha256", "")
    if stored_hash and stored_hash.lower() != recomputed:
        raise HTTPException(status_code=409, detail={
            "code": "integrity_mismatch",
            "message": "Stored report does not match its recorded integrity hash; refusing to commit.",
        })

    # The coarse category tag reflects what was analysed (never report content).
    category = (CATEGORY_MESSAGE_ANALYSIS if stored.get("input_type") == "message"
                else CATEGORY_URL_ANALYSIS)
    try:
        receipt = await run_chain(
            client.submit, parse_report_hash("0x" + recomputed), category
        )
    except ChainUnavailableError as exc:
        raise HTTPException(status_code=502, detail={
            "code": "chain_unavailable",
            "message": f"Chain node unreachable or transaction failed: {exc}",
        }) from exc

    get_chain_id = getattr(client, "get_chain_id", None)
    try:
        receipt["chain_id"] = int(await asyncio.to_thread(get_chain_id)) if get_chain_id else 0
    except Exception as exc:
        # The transaction is ALREADY on-chain (submit returned a receipt) — a
        # hiccup while reading chain_id must not 500 the request and lose the
        # commitment record (a later retry would hit already_committed with
        # no persisted receipt, audit L-D). Record it with chain_id=0.
        logger.warning("chain_id lookup after successful commit failed (%s: %s); "
                       "recording the commitment with chain_id=0",
                       type(exc).__name__, str(exc)[:120])
        receipt["chain_id"] = 0
    payload = _commit_payload(request, report_id, recomputed, receipt)
    await asyncio.to_thread(repository.save_commitment, payload)
    logger.info("report %s committed at tx %s", report_id, payload["tx_hash"])
    return payload


@router.get("/verify/{identifier}", summary="Verify a report ID or on-chain hash")
async def verify(identifier: str, request: Request) -> dict:
    settings = request.app.state.settings
    client = getattr(request.app.state, "registry_client", None)
    enabled = chain_enabled(settings) and client is not None
    ident = identifier.strip()

    result: dict = {
        "identifier": ident,
        "chain_enabled": enabled,
        "mode": None,
        "report_hash": None,
        "integrity_match": None,
        "on_chain": None,
        "commitment": None,
        "note": "",
    }

    # Hash mode: anyone can paste the 0x-prefixed 64-hex hash.
    if ident.lower().startswith(_HEX32_PREFIX) and len(ident) == 66:
        result["mode"] = "hash"
        try:
            report_hash = parse_report_hash(ident)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"code": "invalid_hash",
                                                         "message": str(exc)}) from exc
        result["report_hash"] = "0x" + report_hash.hex()
        if not enabled:
            result["note"] = "Chain features disabled: set TRUSTLENS_REGISTRY_ADDRESS."
            return result
        try:
            result["on_chain"] = await run_chain(client.verify, report_hash)
        except ChainUnavailableError as exc:
            raise HTTPException(status_code=502, detail={
                "code": "chain_unavailable", "message": str(exc)}) from exc
        commitment = await asyncio.to_thread(repository.find_commitment_by_hash, result["report_hash"])
        result["commitment"] = commitment
        return result

    # Report-ID mode: recompute the hash from the stored report and cross-check.
    stored = await asyncio.to_thread(repository.get_report, ident)
    if stored is None:
        raise HTTPException(status_code=404, detail={"code": "report_not_found",
                                                     "message": f"No report with id '{ident}'."})
    result["mode"] = "report_id"
    recomputed = recompute_report_hash(stored)
    result["report_hash"] = "0x" + recomputed
    stored_hash = (stored.get("integrity") or {}).get("canonical_json_sha256", "")
    result["integrity_match"] = (stored_hash.lower() == recomputed) if stored_hash else None
    if result["integrity_match"] is False:
        result["note"] = (
            "WARNING: the stored report no longer matches its recorded integrity hash — "
            "it has been modified after analysis. The recomputed hash is what should exist on-chain."
        )
    if not enabled:
        result["note"] = (result["note"] + " " if result["note"] else "") + \
            "Chain features disabled: set TRUSTLENS_REGISTRY_ADDRESS."
        return result
    try:
        result["on_chain"] = await run_chain(client.verify, parse_report_hash("0x" + recomputed))
    except ChainUnavailableError as exc:
        raise HTTPException(status_code=502, detail={
            "code": "chain_unavailable", "message": str(exc)}) from exc
    result["commitment"] = await asyncio.to_thread(repository.get_commitment, ident)
    return result


@router.post(
    "/verify/report",
    summary="Verify a SUPPLIED report JSON: recompute its canonical hash and compare",
)
async def verify_supplied_report(body: VerifyReportRequest, request: Request) -> dict:
    """Independent verification without trusting the server's stored copy.

    Three independent facts are reported (never conflated):
      * integrity_match — does the supplied JSON match ITS OWN recorded
        integrity hash? (False ⇒ contents were altered after analysis.)
      * hash_match — do the supplied contents match the caller-supplied
        expected hash?
      * on_chain.exists — does the recomputed hash exist in ThreatRegistry?
        (Someone committed this hash; with `hash_match`/`integrity_match` true
        that someone committed THIS report's contents.)

    The supplied report is validated (schema + size) before hashing; report
    contents never go on-chain — only the recomputed 32-byte hash is looked up.
    """
    try:
        encoded = json.dumps(body.report, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail={
            "code": "invalid_report",
            "message": "The supplied report is not valid JSON-serialisable content.",
        }) from exc
    if len(encoded) > _MAX_VERIFY_REPORT_CHARS:
        raise HTTPException(status_code=400, detail={
            "code": "report_too_large",
            "message": f"Supplied report exceeds the {_MAX_VERIFY_REPORT_CHARS // 1000} kB verification limit.",
        })

    try:
        AnalysisReport.model_validate(body.report)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail={
            "code": "invalid_report",
            "message": "The supplied report does not match the TrustLens report schema.",
            "details": {"errors": str(exc.errors()[:5])},
        }) from exc

    recomputed = recompute_report_hash(body.report)
    supplied_integrity = (body.report.get("integrity") or {}).get("canonical_json_sha256") or ""

    result: dict = {
        "mode": "supplied_report",
        "chain_enabled": False,
        "recomputed_hash": "0x" + recomputed,
        "integrity_match": (supplied_integrity.lower() == recomputed) if supplied_integrity else None,
        "hash_match": None,
        "on_chain": None,
        "note": "",
    }

    if body.expected_hash:
        try:
            expected_hex = parse_report_hash(body.expected_hash).hex()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={
                "code": "invalid_hash", "message": str(exc)}) from exc
        result["hash_match"] = recomputed == expected_hex

    # On-chain lookup of the RECOMPUTED hash (never report contents). Unlike
    # the GET verify endpoints (which return 502 when the chain is down), the
    # supplied-report flow degrades: the integrity/hash comparison above is
    # independent of the chain and must stay available.
    settings = request.app.state.settings
    client = getattr(request.app.state, "registry_client", None)
    enabled = chain_enabled(settings) and client is not None
    result["chain_enabled"] = enabled
    if enabled:
        try:
            result["on_chain"] = await run_chain(client.verify, parse_report_hash("0x" + recomputed))
        except ChainUnavailableError:
            result["on_chain"] = None
            result["chain_node_unreachable"] = True

    notes: list[str] = []
    if result["integrity_match"] is False:
        notes.append("The supplied report does NOT match its own recorded integrity hash — "
                     "its contents were altered after analysis.")
    if result["hash_match"] is False:
        notes.append("The supplied report's contents do NOT match the supplied expected hash.")
    if result.get("chain_node_unreachable"):
        notes.append("The chain node was unreachable, so the on-chain check could not be "
                     "performed (the integrity/hash comparison above is independent of the chain).")
    elif result["on_chain"] is not None:
        notes.append(
            "The recomputed hash EXISTS on-chain." if result["on_chain"].get("exists")
            else "The recomputed hash does not exist on-chain (no commitment for it)."
        )
    notes.append(
        "These are independent facts: on-chain existence means someone committed this hash; "
        "integrity/hash-match mean the supplied JSON produces that hash. Only the hash is "
        "looked up on-chain — never report contents."
    )
    result["note"] = " ".join(notes)
    return result
