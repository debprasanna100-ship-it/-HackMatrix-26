"""Report persistence (synchronous SQLAlchemy, invoked via asyncio.to_thread)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, or_, select

from .database import (
    ChainCommitmentRow,
    CorrelationIndicatorRow,
    ReportRow,
    UserRow,
    session,
)


def save_report(payload: dict, owner_id: Optional[str] = None) -> str:
    """Persist a full report dict; returns the report id.

    `owner_id` is multi-tenant metadata stored OUTSIDE the report JSON, so the
    canonical integrity hash is unaffected by ownership.
    """
    normalized = payload.get("normalized") or {}
    with session() as db:
        row = ReportRow(
            id=payload["report_id"],
            created_at=datetime.fromisoformat(payload["created_at"]),
            input_type=payload.get("input_type", "url"),
            raw_input=payload.get("raw_input", ""),
            normalized_url=normalized.get("url"),
            registrable_domain=normalized.get("registrable_domain"),
            classification=payload.get("classification", "inconclusive"),
            report_json=json.dumps(payload, ensure_ascii=False),
            owner_id=owner_id,
            is_public=False,
        )
        db.merge(row)
        db.commit()
    return row.id


def get_report(report_id: str) -> Optional[dict]:
    with session() as db:
        row = db.get(ReportRow, report_id)
        if row is None:
            return None
        return json.loads(row.report_json)


def get_report_access_meta(report_id: str) -> Optional[dict]:
    """Ownership/visibility metadata for access-control decisions."""
    with session() as db:
        row = db.get(ReportRow, report_id)
        if row is None:
            return None
        return {"owner_id": row.owner_id, "is_public": bool(row.is_public)}


def set_report_visibility(report_id: str, is_public: bool) -> bool:
    """Toggle a report's public flag; returns False when the report is missing."""
    with session() as db:
        row = db.get(ReportRow, report_id)
        if row is None:
            return False
        row.is_public = bool(is_public)
        db.commit()
    return True


def list_reports(limit: int = 20, offset: int = 0, owner_id: Optional[str] = None,
                 include_all: bool = False) -> dict:
    """List stored reports. In multi-tenant mode non-admin users see only their
    own reports (`owner_id`; `include_all` for admins and auth-disabled modes)."""
    with session() as db:
        query = db.query(ReportRow.id)
        if not include_all and owner_id is not None:
            query = query.filter(ReportRow.owner_id == owner_id)
        total = query.count()
        stmt = (
            select(ReportRow)
            .order_by(ReportRow.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if not include_all and owner_id is not None:
            stmt = stmt.where(ReportRow.owner_id == owner_id)
        rows = db.execute(stmt).scalars().all()
        reports = [
            {
                "report_id": r.id,
                "created_at": r.created_at.isoformat() if isinstance(r.created_at, datetime) else str(r.created_at),
                "input_type": r.input_type,
                "normalized_url": r.normalized_url,
                "registrable_domain": r.registrable_domain,
                "classification": r.classification,
                "is_public": bool(r.is_public),
                "owner_id": r.owner_id,
                "findings_count": len((json.loads(r.report_json) or {}).get("findings", [])),
            }
            for r in rows
        ]
    return {"count": total, "reports": reports}


# ---- chain commitments (Phase 4) ---------------------------------------------


def save_commitment(payload: dict) -> str:
    """Persist an on-chain commitment for a report. Idempotent on report_id."""
    with session() as db:
        row = ChainCommitmentRow(
            report_id=payload["report_id"],
            report_hash=payload["report_hash"].lower(),
            tx_hash=payload["tx_hash"].lower(),
            contract_address=payload["contract_address"],
            chain_id=payload["chain_id"],
            block_number=payload["block_number"],
            gas_used=payload.get("gas_used", 0),
            committed_at=datetime.fromisoformat(payload["committed_at"])
            if isinstance(payload.get("committed_at"), str)
            else payload.get("committed_at"),
        )
        db.merge(row)
        db.commit()
    return row.report_id


def get_commitment(report_id: str) -> Optional[dict]:
    with session() as db:
        row = db.get(ChainCommitmentRow, report_id)
        if row is None:
            return None
        return {
            "report_id": row.report_id,
            "report_hash": row.report_hash,
            "tx_hash": row.tx_hash,
            "contract_address": row.contract_address,
            "chain_id": row.chain_id,
            "block_number": row.block_number,
            "gas_used": row.gas_used,
            "committed_at": row.committed_at.isoformat()
            if isinstance(row.committed_at, datetime)
            else str(row.committed_at),
        }


def find_commitment_by_hash(report_hash: str) -> Optional[dict]:
    with session() as db:
        row = (
            db.execute(
                select(ChainCommitmentRow).where(ChainCommitmentRow.report_hash == report_hash.lower())
            )
            .scalars()
            .first()
        )
        if row is None:
            return None
        return {
            "report_id": row.report_id,
            "report_hash": row.report_hash,
            "tx_hash": row.tx_hash,
            "contract_address": row.contract_address,
            "chain_id": row.chain_id,
            "block_number": row.block_number,
            "gas_used": row.gas_used,
            "committed_at": row.committed_at.isoformat()
            if isinstance(row.committed_at, datetime)
            else str(row.committed_at),
        }


# ---- correlation indicators (Phase 6) ------------------------------------------


def record_indicators(report_id: str, indicators: dict[str, set[str]], classification: str) -> int:
    """Persist normalised indicators for a report. Idempotent per (kind, value, report)."""
    count = 0
    with session() as db:
        for kind, values in indicators.items():
            for value in values:
                if not value or len(value) > 255:
                    continue
                # merge() keys on the autoincrement primary key, so it would always
                # INSERT and trip the (kind, value, report_id) unique constraint on a
                # re-record. Check existence first to stay genuinely idempotent.
                existing = db.execute(
                    select(CorrelationIndicatorRow.id)
                    .where(CorrelationIndicatorRow.kind == kind)
                    .where(CorrelationIndicatorRow.value == value[:255])
                    .where(CorrelationIndicatorRow.report_id == report_id)
                ).scalar_one_or_none()
                if existing is not None:
                    continue
                db.add(CorrelationIndicatorRow(
                    kind=kind, value=value[:255], report_id=report_id,
                    classification=classification,
                ))
                count += 1
        db.commit()
    return count


def _visibility_condition(visibility: Optional[dict]):
    """SQLAlchemy filter restricting correlation lookups to reports the caller
    may read (audit M-D).

    `visibility` is None for unrestricted lookups (demo mode, admins) or
    {"owner_id": <user id>} to restrict to that owner's reports plus public
    ones. Foreign private reports must be invisible to correlation exactly as
    they are to direct reads (404, existence not leaked)."""
    if not visibility or not visibility.get("owner_id"):
        return None
    cond = ReportRow.owner_id == visibility["owner_id"]
    if visibility.get("include_public", True):
        cond = or_(cond, ReportRow.is_public.is_(True))
    return cond


def find_indicator_hits(indicators: dict[str, set[str]], exclude_report_id: str,
                        visibility: Optional[dict] = None) -> dict:
    """Aggregate prior reports sharing any indicator (excluding the current one).

    Returns {kind: {value: {"prior_count", "report_ids", "prior_classifications"}}}.
    `visibility` scopes the lookup to reports the caller may read (audit M-D);
    None = unrestricted (demo mode / admins).
    """
    hits: dict = {}
    if not indicators:
        return hits
    cond = _visibility_condition(visibility)
    with session() as db:
        for kind, values in indicators.items():
            for value in values:
                stmt = (
                    select(CorrelationIndicatorRow)
                    # Join so the visibility filter can consult the report's
                    # owner/visibility columns (indicator rows carry neither).
                    .join(ReportRow, CorrelationIndicatorRow.report_id == ReportRow.id)
                    .where(CorrelationIndicatorRow.kind == kind)
                    .where(CorrelationIndicatorRow.value == value[:255])
                    .where(CorrelationIndicatorRow.report_id != exclude_report_id)
                    .order_by(CorrelationIndicatorRow.created_at.desc())
                    .limit(10)
                )
                if cond is not None:
                    stmt = stmt.where(cond)
                rows = db.execute(stmt).scalars().all()
                for row in rows:
                    entry = hits.setdefault(kind, {}).setdefault(value, {
                        "prior_count": 0, "report_ids": [], "prior_classifications": [],
                    })
                    entry["prior_count"] += 1
                    if row.report_id not in entry["report_ids"]:
                        entry["report_ids"].append(row.report_id)
                    entry["prior_classifications"].append(row.classification)
    return hits


def get_report_texts(exclude_report_id: str, limit: int = 100,
                     visibility: Optional[dict] = None) -> dict[str, str]:
    """raw_input texts of the most recent stored reports (for TF-IDF similarity).

    `visibility` scopes the lookup exactly as for find_indicator_hits."""
    cond = _visibility_condition(visibility)
    with session() as db:
        stmt = (
            select(ReportRow.id, ReportRow.raw_input)
            .where(ReportRow.id != exclude_report_id)
            .order_by(ReportRow.created_at.desc())
            .limit(limit)
        )
        if cond is not None:
            stmt = stmt.where(cond)
        rows = db.execute(stmt).all()
    return {row[0]: row[1] or "" for row in rows}


# ---- deletion / retention (privacy policy) --------------------------------------


def delete_report(report_id: str) -> bool:
    """Delete one report and its dependent rows (indicators, chain commitment).

    Returns True when a row was deleted, False when the report did not exist.
    """
    with session() as db:
        row = db.get(ReportRow, report_id)
        if row is None:
            return False
        db.execute(delete(CorrelationIndicatorRow).where(CorrelationIndicatorRow.report_id == report_id))
        db.execute(delete(ChainCommitmentRow).where(ChainCommitmentRow.report_id == report_id))
        db.delete(row)
        db.commit()
    return True


def purge_reports_older_than(days: int) -> int:
    """Delete reports (and dependents) created more than `days` days ago.

    Called at startup when TRUSTLENS_REPORT_RETENTION_DAYS > 0 (config.py).
    Returns the number of reports removed.
    """
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    with session() as db:
        ids = list(
            db.execute(select(ReportRow.id).where(ReportRow.created_at < cutoff)).scalars().all()
        )
        if not ids:
            return 0
        db.execute(delete(CorrelationIndicatorRow).where(CorrelationIndicatorRow.report_id.in_(ids)))
        db.execute(delete(ChainCommitmentRow).where(ChainCommitmentRow.report_id.in_(ids)))
        db.execute(delete(ReportRow).where(ReportRow.id.in_(ids)))
        db.commit()
    return len(ids)


# ---- users (multi-tenant auth, Step 4) ------------------------------------------


def create_user(user_id: str, email: str, hashed_password: str,
                api_key_hash: Optional[str] = None, role: str = "user",
                email_verified: bool = False) -> dict:
    with session() as db:
        row = UserRow(
            id=user_id, email=email.lower(), hashed_password=hashed_password,
            api_key_hash=api_key_hash, role=role, email_verified=email_verified,
        )
        db.add(row)
        db.commit()
        return {"id": row.id, "email": row.email, "role": row.role,
                "api_key_hash": row.api_key_hash, "email_verified": row.email_verified,
                "created_at": row.created_at}


def user_count() -> int:
    with session() as db:
        return db.query(UserRow.id).count()


def get_user_by_email(email: str) -> Optional[dict]:
    with session() as db:
        row = db.execute(
            select(UserRow).where(UserRow.email == (email or "").lower())
        ).scalars().first()
        if row is None:
            return None
        return {"id": row.id, "email": row.email, "hashed_password": row.hashed_password,
                "api_key_hash": row.api_key_hash, "role": row.role,
                "email_verified": row.email_verified}


def get_user_by_id(user_id: str) -> Optional[dict]:
    with session() as db:
        row = db.get(UserRow, user_id)
        if row is None:
            return None
        return {"id": row.id, "email": row.email, "hashed_password": row.hashed_password,
                "api_key_hash": row.api_key_hash, "role": row.role,
                "email_verified": row.email_verified}


def get_user_by_api_key_hash(api_key_hash: str) -> Optional[dict]:
    with session() as db:
        row = db.execute(
            select(UserRow).where(UserRow.api_key_hash == api_key_hash)
        ).scalars().first()
        if row is None:
            return None
        return {"id": row.id, "email": row.email, "hashed_password": row.hashed_password,
                "api_key_hash": row.api_key_hash, "role": row.role,
                "email_verified": row.email_verified}


def set_user_api_key_hash(user_id: str, api_key_hash: Optional[str]) -> bool:
    with session() as db:
        row = db.get(UserRow, user_id)
        if row is None:
            return False
        row.api_key_hash = api_key_hash
        db.commit()
    return True


def set_email_verified(user_id: str, verified: bool) -> bool:
    with session() as db:
        row = db.get(UserRow, user_id)
        if row is None:
            return False
        row.email_verified = verified
        db.commit()
    return True


def update_password(user_id: str, hashed_password: str) -> bool:
    with session() as db:
        row = db.get(UserRow, user_id)
        if row is None:
            return False
        row.hashed_password = hashed_password
        db.commit()
    return True
