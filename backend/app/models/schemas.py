"""Pydantic models for findings, pipeline artefacts, and the analysis report.

The report schema is versioned (`schema_version`); every finding carries its own
evidence, source, and `check_succeeded` flag so downstream consumers (scoring
engine in Phase 2, LLM explanation in Phase 5) can reason about coverage.
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from .enums import Classification, FetchErrorKind, FindingCategory, InputType, Severity

FINDING_SOURCE = "trustlens"

# Single schema-version constant for EVERY report type (URL and message alike,
# audit item L1). Both pipelines stamp the same value so the canonical integrity
# hash and the on-chain commitment are comparable across report kinds.
SCHEMA_VERSION = "2.1"


class Finding(BaseModel):
    """A single deterministic observation produced by a pipeline check."""

    id: str = Field(description="Stable finding id, e.g. 'DOM-TYPOSQUAT'. Referenced by LLM explanations.")
    title: str
    severity: Severity
    category: FindingCategory
    weight: int = Field(default=0, description="Contribution to the deterministic score (used from Phase 2).")
    evidence: list[str] = Field(default_factory=list)
    source: str
    check_succeeded: bool = Field(
        default=True, description="False when the check itself failed/was unavailable (never treated as a clean result)."
    )


class NormalizedTarget(BaseModel):
    """Canonical, safety-normalised view of the submitted URL."""

    url: str
    scheme: str
    host: str
    original_host: str
    unicode_host: Optional[str] = None
    port: Optional[int] = None
    path: str
    query: str
    is_ip_literal: bool
    ip: Optional[str] = None
    registrable_domain: Optional[str] = None
    suffix: Optional[str] = None
    subdomain: Optional[str] = None
    notes: list[str] = Field(default_factory=list)


class FetchHop(BaseModel):
    """One hop in the (manually followed) redirect chain."""

    url: str
    status: Optional[int] = None
    ok: bool = False
    location: Optional[str] = None
    content_type: Optional[str] = None
    server: Optional[str] = None
    resolved_ips: list[str] = Field(default_factory=list)
    peer_ip: Optional[str] = None
    elapsed_ms: int = 0
    bytes_read: int = 0
    note: Optional[str] = None


class FetchSummary(BaseModel):
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    success: bool = False
    ok: bool = False
    error_kind: FetchErrorKind = FetchErrorKind.NONE
    error: Optional[str] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    total_bytes: int = 0
    elapsed_ms: int = 0


class SafeFetchResult(FetchSummary):
    """Internal pipeline result (superset of FetchSummary, includes the hop chain).

    NEVER serialised into reports: `cert_pem` and `body_excerpt` are internal
    inputs for the TLS and header analysers only."""

    requested_url: str = ""
    hops: list[FetchHop] = Field(default_factory=list)
    response_headers: dict[str, str] = Field(default_factory=dict)
    size_capped: bool = Field(default=False, description="A response body hit the byte cap and was truncated.")
    cert_pem: str = Field(default="", description="PEM of the server-presented certificate chain (internal use).")
    cert_capture_method: str = Field(
        default="leaf-only",
        description="How the chain was captured: 'unverified-chain' (peer-presented via "
                    "get_unverified_chain, exposed by newer interpreters), 'verified-chain' "
                    "(get_verified_chain), 'leaf-only' (fallback), or 'unavailable'.",
    )
    body_excerpt: str = Field(default="", description="Capped text body excerpt (internal use: title + mixed-content scan).")


class Coverage(BaseModel):
    """How much of the planned analysis actually completed."""

    attempted: int
    completed: int
    completed_checks: list[str] = Field(default_factory=list)
    unavailable_checks: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)


class IntegrityInfo(BaseModel):
    algorithm: str = "sha256"
    canonical_json_sha256: str
    note: str = (
        "SHA-256 of the canonical JSON of this report (sorted keys, no whitespace), "
        "excluding this integrity field. This is the value committed on-chain in Phase 4."
    )


class AnalysisReport(BaseModel):
    schema_version: str = SCHEMA_VERSION
    report_id: str
    created_at: str  # ISO-8601 UTC
    input_type: InputType = InputType.URL
    raw_input: str
    normalized: Optional[NormalizedTarget] = None
    classification: Classification = Classification.INCONCLUSIVE
    classification_rationale: str = ""
    findings: list[Finding] = Field(default_factory=list)
    redirect_chain: list[FetchHop] = Field(default_factory=list)
    fetch: Optional[FetchSummary] = None
    tls: Optional["TlsSummary"] = None
    threat_intel: "ThreatIntelSummary" = Field(default_factory=lambda: ThreatIntelSummary())
    ct_history: "CtHistorySummary" = Field(default_factory=lambda: CtHistorySummary())
    scoring: "ScoringSummary" = Field(default_factory=lambda: ScoringSummary())
    explanation: Optional["ExplanationResult"] = None
    coverage: Coverage
    recommended_actions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    integrity: Optional[IntegrityInfo] = None
    extras: dict[str, Any] = Field(default_factory=dict)


class TlsSummary(BaseModel):
    """Certificate facts (Phase 2+) extracted from the fetched connection."""

    hostname: str = ""
    san_dns: list[str] = Field(default_factory=list)
    issuer: str = ""
    issuer_common_name: str = ""
    issuer_ca: bool = False
    public_key_type: str = ""
    public_key_size: Optional[int] = None
    signature_algorithm: str = ""
    days_remaining: Optional[int] = None
    is_self_signed: bool = False
    chain_length: int = 1
    chain: list[str] = Field(default_factory=list)
    cert_sha256: str = ""
    errors: list[str] = Field(default_factory=list)
    note: str = Field(
        default="",
        description="Capture-scope note: what was (and was not) independently verified about the certificate chain.",
    )


class ExplanationResult(BaseModel):
    """AI/rule-based explanation. NEVER carries a classification — that stays
    owned by the deterministic scoring engine."""

    summary: str = ""
    claims: list[dict] = Field(default_factory=list)  # [{claim, finding_ids[]}]
    caveats: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    generated_by: str = "rule-based-fallback"  # "llm" | "rule-based-fallback"
    model: Optional[str] = None
    stripped_claims: int = Field(
        default=0,
        description="Unsupported model statements removed: claims lacking valid finding "
                    "references, plus verdict-asserting caveats/actions, plus whole-summary fallbacks.",
    )
    fallback_reason: Optional[str] = None


class ThreatIntelSummary(BaseModel):
    """Aggregate threat-intelligence state (Phase 2+)."""

    checks_performed: list[str] = Field(default_factory=list)  # provider names that returned findings
    providers: dict[str, str] = Field(default_factory=dict)  # provider name -> "active" | "unconfigured" | "failed" | "rate_limited"
    authoritative_hits: list[str] = Field(default_factory=list)  # provider IDs of hits driving CONFIRMED_MALICIOUS
    total_findings: int = 0
    note: str = "Absence of intel hits is not proof of safety."  # pipelines override with intel_summary_note()


def intel_summary_note(providers: dict[str, str]) -> str:
    """Truthful one-line note derived from the ACTUAL provider statuses.

    Replaces the former static default, which claimed providers were
    "unavailable in this build by default" even on deployments where every
    provider was configured and answering (audit L-A)."""
    base = "Absence of intel hits is not proof of safety."
    if not providers:
        return base + " No threat-intel providers are configured."
    unconfigured = sorted(n for n, s in providers.items() if s == "unconfigured")
    unavailable = sorted(n for n, s in providers.items() if s in ("failed", "rate_limited"))
    parts: list[str] = []
    if unconfigured:
        parts.append(f"no API key configured for: {', '.join(unconfigured)}")
    if unavailable:
        parts.append(f"unavailable during this analysis: {', '.join(unavailable)}")
    if parts:
        return f"{base} " + "; ".join(parts) + "."
    return f"{base} All {len(providers)} configured providers were operational during this analysis."


class CtHistorySummary(BaseModel):
    """Certificate Transparency history state (Phase 2+)."""

    domain: str = ""
    records_found: int = 0
    most_recent: Optional[str] = None  # ISO timestamp
    error: Optional[str] = None
    note: str = "CT logs are public and read-only; data may lag minutes to hours."


class ScoringSummary(BaseModel):
    """Deterministic scoring state (Phase 2+)."""

    score: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    authoritative_hits: int = 0
    key_checks_failed: list[str] = Field(default_factory=list)
    key_checks_unavailable: list[str] = Field(default_factory=list)


# ---- request / error payloads ------------------------------------------------


class AnalyzeUrlRequest(BaseModel):
    url: str = Field(
        min_length=3,
        max_length=2048,
        description="A URL or bare domain to analyse. Messages are analysed via /analyze/message (Phase 5).",
    )


class ApiErrorBody(BaseModel):
    code: str
    message: str
    details: Optional[dict[str, Any]] = None


class ErrorResponse(BaseModel):
    error: ApiErrorBody
