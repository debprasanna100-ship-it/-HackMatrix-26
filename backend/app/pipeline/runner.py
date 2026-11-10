"""Pipeline orchestrator: normalise -> fetch -> TLS -> CT -> heuristics -> threat-intel -> scoring -> report.

Every finding is factual and source-tagged; the deterministic scoring engine
(scoring.py) turns them into a classification. The LLM (Phase 5) may explain and
summarise the findings but is NEVER permitted to change the classification.

Coverage rules (hard):
  * If the page fetch fails/times out or any authoritative feed was unavailable,
    the report is marked INCONCLUSIVE — never Low Risk.
  * Absence of findings means "no significant indicators found in the available
    checks"; we never claim the site is safe.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ..config import Settings
from ..models.enums import Classification, FetchErrorKind, FindingCategory, InputType, Severity
from ..models.schemas import (
    AnalysisReport,
    Coverage,
    FetchSummary,
    Finding,
    IntegrityInfo,
    NormalizedTarget,
    ThreatIntelSummary,
    CtHistorySummary,
    ScoringSummary,
    TlsSummary,
    intel_summary_note,
)
from ..storage import repository
from .correlation import build_matches, build_prior_from_hits, correlate_finding, extract_indicators, tfidf_cosine
from .dns_records import check_dns_records as analyze_dns_records
from .domain_heuristics import analyze_domain
from .fetcher import SafeFetcher, leaf_cert_sha256
from .headers import analyze_headers, headers_summary
from .normalizer import NormalizedUrl, normalize_url
from .scoring import ScoringEngine, classification_rationale, recommended_actions
from .ssrf import SystemDnsResolver
from .tls import analyze_tls, CertInfo, TlsAnalysisError
from .intel import init_intel, IntelRegistry
from .crtsh import analyze_ct

logger = logging.getLogger("trustlens.runner")

SEVERITY_ORDER = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


_LIMITATIONS = [
    "TrustLens never executes JavaScript, so content rendered client-side is not analysed.",
    "Checks are passive: no probing, exploitation, or file downloads are performed.",
    "A valid TLS certificate is not proof of safety — it only encrypts the connection; look-alike "
    "domains can hold perfectly valid certificates.",
    "Absence of findings means 'no significant indicators found in the available checks', never 'safe'.",
    "Threat-intel results shown are a best-effort aggregation of several providers; missing keys are "
    "marked as unavailable rather than as 'clean'.",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fetch_findings(result, norm: NormalizedUrl) -> list[Finding]:
    """Translate fetch outcomes into findings (source: trustlens/safe-fetch)."""
    findings: list[Finding] = []
    src = "trustlens/safe-fetch"

    if result.error_kind == FetchErrorKind.DNS:
        findings.append(Finding(
            id="FETCH-DNS-FAIL",
            title="Domain does not currently resolve",
            severity="low",
            category=FindingCategory.FETCH,
            evidence=[result.error or "DNS resolution failed",
                      "The domain may be unregistered, parked, or temporarily broken. "
                      "A dead domain cannot be verified, which is itself a coverage limitation."],
            source=src,
        ))
    elif result.error_kind == FetchErrorKind.POLICY:
        findings.append(Finding(
            id="FETCH-BLOCKED-POLICY",
            title="Fetch refused by TrustLens security policy",
            severity="medium",
            category=FindingCategory.FETCH,
            evidence=[result.error or "refused by policy",
                      "Refusals cover private/reserved/metadata addresses, non-http(s) targets, "
                      "non-standard ports, and embedded credentials. The target was never contacted."],
            source=src,
        ))
    elif result.error_kind in (FetchErrorKind.TIMEOUT, FetchErrorKind.CONNECTION,
                               FetchErrorKind.TLS, FetchErrorKind.HTTP, FetchErrorKind.OTHER):
        findings.append(Finding(
            id="FETCH-FAILED",
            title="Page fetch did not complete",
            severity="info",
            category=FindingCategory.FETCH,
            evidence=[result.error or "fetch failed"],
            source=src,
            check_succeeded=False,
        ))

    for hop in result.hops:
        if hop.note and "TLS downgrade" in hop.note:
            findings.append(Finding(
                id="FETCH-TLS-DOWNGRADE",
                title="Redirect chain downgrades from HTTPS to HTTP",
                severity="medium",
                category=FindingCategory.FETCH,
                evidence=[
                    f"Hop '{hop.url}' redirected to an http:// URL.",
                    "Traffic after the downgrade is unencrypted and modifiable in transit.",
                ],
                source=src,
            ))
            break
    if result.error and "exceeded maximum" in result.error:
        findings.append(Finding(
            id="FETCH-TOO-MANY-REDIRECTS",
            title=f"Redirect chain exceeded {len(result.hops)} hop(s)",
            severity="low",
            category=FindingCategory.FETCH,
            evidence=[result.error,
                      "Long or looping redirect chains are used to evade naive scanners."],
            source=src,
        ))
    if result.size_capped:
        findings.append(Finding(
            id="FETCH-SIZE-CAP",
            title="Response exceeded the size cap and was truncated",
            severity="low",
            category=FindingCategory.FETCH,
            evidence=[f"TrustLens reads at most the configured byte cap; larger bodies are never stored.",
                      "Only the beginning of the page was inspected."],
            source=src,
        ))
    return findings


def _tls_findings(info: CertInfo, hostname: str) -> list[Finding]:
    """Translate parsed certificate facts into findings (source: trustlens/tls)."""
    findings: list[Finding] = []
    src = "trustlens/tls"

    if info.signature_algorithm.lower().startswith("md"):
        findings.append(Finding(
            id="TLS-WEAK-SIGNATURE",
            title="Weak signature algorithm",
            severity="high",
            category=FindingCategory.TLS,
            evidence=[f"Certificate uses {info.signature_algorithm}, which is cryptographically weak."],
            source=src,
        ))
    if info.public_key_size is not None and info.public_key_type == "RSA" and info.public_key_size < 2048:
        findings.append(Finding(
            id="TLS-WEAK-KEY",
            title="Weak RSA key size",
            severity="high",
            category=FindingCategory.TLS,
            evidence=[f"RSA key is {info.public_key_size} bits; minimum recommended is 2048."],
            source=src,
        ))
    if info.days_remaining is not None:
        if info.days_remaining < 0:
            findings.append(Finding(
                id="TLS-EXPIRED",
                title="Certificate expired",
                severity="medium",
                category=FindingCategory.TLS,
                evidence=[f"Certificate expired {abs(info.days_remaining)} day(s) ago."],
                source=src,
            ))
        elif info.days_remaining < 7:
            findings.append(Finding(
                id="TLS-EXPIRY-IMMINENT",
                title="Certificate expires soon",
                severity="low",
                category=FindingCategory.TLS,
                evidence=[f"Certificate expires in {info.days_remaining} day(s)."],
                source=src,
            ))
        elif info.days_remaining < 30:
            findings.append(Finding(
                id="TLS-EXPIRY-NEAR",
                title="Certificate expires within 30 days",
                severity="info",
                category=FindingCategory.TLS,
                evidence=[f"Certificate expires in {info.days_remaining} days; renewal may be due."],
                source=src,
            ))
    if info.is_self_signed:
        findings.append(Finding(
            id="TLS-SELF-SIGNED",
            title="Self-signed certificate",
            severity="medium",
            category=FindingCategory.TLS,
            evidence=[
                "The certificate is self-signed (issuer == subject); there is no third-party validation.",
                "Self-signed certs are common for internal tools; on the public internet they are a phishing "
                "enabler since anyone can generate one.",
            ],
            source=src,
        ))
    for err in info.errors:
        findings.append(Finding(
            id="TLS-POLICY",
            title="TLS policy violation",
            severity="high" if "distrusted" in err.lower() else ("medium" if "covered" in err.lower() else "low"),
            category=FindingCategory.TLS,
            evidence=[err],
            source=src,
        ))
    return findings


async def analyze_url(
    raw: str,
    settings: Settings,
    fetcher: SafeFetcher | None = None,
    intel: IntelRegistry | None = None,
    persist: bool = True,
    owner_id: str | None = None,
) -> AnalysisReport:
    report_id = uuid.uuid4().hex
    created_at = _now_iso()

    # ---- Stage 1: normalisation ----
    norm = normalize_url(raw)
    normalized = NormalizedTarget(
        url=norm.url, scheme=norm.scheme, host=norm.host, original_host=norm.original_host,
        unicode_host=norm.unicode_host, port=norm.port, path=norm.path, query=norm.query,
        is_ip_literal=norm.is_ip_literal, ip=norm.ip, registrable_domain=norm.registrable_domain,
        suffix=norm.suffix, subdomain=norm.subdomain, notes=norm.notes,
    )
    completed: list[str] = ["url-normalisation"]
    unavailable: list[str] = []

    # ---- Stage 2: deterministic domain heuristics (offline, always available) ----
    findings = analyze_domain(norm)
    completed.append("domain-heuristics")

    # ---- Stage 3: SSRF-safe fetch with redirect tracing + cert capture ----
    fetcher = fetcher or SafeFetcher(settings, SystemDnsResolver(timeout=3.0))
    intel = intel or init_intel(settings)

    # Launch independent I/O tasks concurrently
    fetch_task = asyncio.create_task(fetcher.fetch(norm))
    from .crtsh import query_ct
    ct_query_task = (
        asyncio.create_task(query_ct(norm.registrable_domain))
        if norm.registrable_domain
        else None
    )
    dns_task = (
        asyncio.create_task(
            analyze_dns_records(
                norm.registrable_domain,
                timeout=settings.dns_timeout,
                use_doh=settings.dns_use_doh,
            )
        )
        if (norm.registrable_domain and not norm.is_ip_literal)
        else None
    )
    intel_domain_task = (
        asyncio.create_task(intel.check_domain(norm.registrable_domain))
        if norm.registrable_domain
        else None
    )

    fetch_result = await fetch_task
    findings.extend(_fetch_findings(fetch_result, norm))
    if fetch_result.success:
        completed.append("page-fetch")
    else:
        unavailable.append(f"page-fetch ({fetch_result.error_kind.value}: {fetch_result.error or 'failed'})")

    # ---- Stage 4: TLS / certificate analysis ----
    # The certificate is analysed against the FINAL redirect URL's hostname:
    # after a cross-host redirect the presented certificate belongs to the
    # destination host, not the originally submitted one.
    final_url = fetch_result.final_url
    final_scheme = (urlsplit(final_url).scheme if final_url else None) or norm.scheme
    final_host = (urlsplit(final_url).hostname if final_url else None) or norm.host
    tls: TlsSummary | None = None
    cert_sha256 = ""
    if fetch_result.success and final_scheme == "https":
        if not (fetch_result.cert_pem or "").strip():
            # Missing capture must be recorded as an unavailable check — never
            # treated as a clean TLS result. Distinguish "nothing captured"
            # from a leaf-only capture attempt that yielded no parsable chain
            # (audit L5): the wording must not claim a leaf exists when the
            # capture produced no certificate at all.
            if fetch_result.cert_capture_method == "unavailable":
                capture_detail = "no certificate was captured on the final connection"
            else:
                capture_detail = (
                    "certificate capture yielded no parsable chain "
                    f"(capture method: {fetch_result.cert_capture_method})"
                )
            unavailable.append(f"tls-analysis (certificate capture unavailable: {capture_detail})")
        else:
            try:
                tls_info = analyze_tls(final_host, fetch_result.cert_pem)
                findings.extend(_tls_findings(tls_info, final_host))
                cert_sha256 = leaf_cert_sha256(fetch_result.cert_pem)
                capture = fetch_result.cert_capture_method
                n_certs = len(tls_info.chain)
                if capture.startswith(("unverified-chain", "verified-chain")) and n_certs > 1:
                    if tls_info.chain_verified:
                        tls_note = (
                            f"Full peer-presented chain ({n_certs} certificates, capture: {capture}) was "
                            "captured and independently re-verified: signatures from leaf up the presented "
                            "issuers, validity windows, and BasicConstraints; every certificate was also "
                            "screened against the distrusted-CA list. The trust anchor comes from the system "
                            "store and was validated during the TLS handshake."
                        )
                    else:
                        first_chain_err = next(
                            (e.removeprefix("chain verification: ") for e in tls_info.errors
                             if e.startswith("chain verification:")),
                            "see TLS findings",
                        )
                        tls_note = (
                            f"Full peer-presented chain ({n_certs} certificates, capture: {capture}) was "
                            f"captured, but independent re-verification reported a problem: {first_chain_err}. "
                            "The fetcher separately validated the chain against system trust roots during "
                            "the TLS handshake."
                        )
                else:
                    tls_note = (
                        f"Only the leaf certificate was captured (capture method: {capture}); intermediate "
                        "certificates were not recorded, so chain completeness was not independently "
                        "re-verified here. The fetcher still validated the full chain against system trust "
                        "roots during the TLS handshake."
                    )
                tls = TlsSummary(
                    hostname=final_host,
                    san_dns=tls_info.san_dns,
                    issuer=tls_info.issuer,
                    issuer_common_name=tls_info.issuer_common_name,
                    issuer_ca=tls_info.issuer_ca,
                    public_key_type=tls_info.public_key_type,
                    public_key_size=tls_info.public_key_size,
                    signature_algorithm=tls_info.signature_algorithm,
                    days_remaining=tls_info.days_remaining,
                    is_self_signed=tls_info.is_self_signed,
                    chain_length=tls_info.chain_length,
                    chain=tls_info.chain,
                    cert_sha256=cert_sha256,
                    errors=list(tls_info.errors),
                    note=tls_note,
                )
                completed.append("tls-analysis")
            except TlsAnalysisError as exc:
                unavailable.append(f"tls-analysis ({exc})")
            except Exception as exc:  # malformed cert / unexpected parse error -> coverage loss, not fatal
                unavailable.append(f"tls-analysis ({type(exc).__name__})")
    elif fetch_result.success:
        unavailable.append("tls-analysis (final URL is plain http; no TLS session to inspect)")

    # ---- Stage 5: Certificate Transparency history ----
    ct_summary = CtHistorySummary(domain=norm.registrable_domain or norm.host)
    extras: dict = {}
    if norm.registrable_domain:
        if ct_query_task is not None:
            try:
                await ct_query_task
            except Exception:
                pass
        try:
            ct_findings, ct_stats = await analyze_ct(
                norm.registrable_domain, cert_sha256=cert_sha256, max_records=50
            )
            findings.extend(ct_findings)
            ct_summary.records_found = ct_stats.get("records_found", 0)
            ct_summary.most_recent = ct_stats.get("most_recent")
            if ct_stats.get("error"):
                # crt.sh was unreachable/rate-limited: the check did not
                # complete, so coverage must not count it as completed.
                ct_summary.error = f"ct-history ({ct_stats['error']})"
                unavailable.append(ct_summary.error)
            else:
                completed.append("ct-history")
        except Exception as exc:  # CT must never break analysis
            logger.exception("ct-history lookup failed for %s", report_id)
            ct_summary.error = f"ct-history ({type(exc).__name__})"
            ct_summary.records_found = 0
            unavailable.append(ct_summary.error)

    # ---- Stage 5a: passive DNS record checks (optional stage) ----
    if dns_task is not None:
        try:
            dns_findings, dns_stats = await dns_task
            findings.extend(dns_findings)
            extras["dns_summary"] = dns_stats
            if dns_stats.get("failed_types"):
                unavailable.append(
                    f"dns-records ({', '.join(dns_stats['failed_types'])} lookup(s) failed)"
                )
            else:
                completed.append("dns-records")
        except Exception:  # DNS checks must never break analysis
            logger.exception("dns-records stage failed for %s", report_id)
            unavailable.append("dns-records (failed)")
    else:
        unavailable.append("dns-records (skipped: no registrable domain — IP-literal target)")

    # ---- Stage 5b: passive header checks (on the already-captured response) ----
    header_findings = analyze_headers(fetch_result, final_scheme)
    findings.extend(header_findings)
    if fetch_result.success:
        completed.append("header-checks")
    extras["headers_summary"] = headers_summary(fetch_result, final_scheme)

    # ---- Stage 5c: correlation against previous analyses (rule-based) ----
    # Only meaningful for persisted analyses; non-persisted (sub-)reports skip
    # the DB entirely.
    if persist:
        try:
            pre_indicators: dict[str, set[str]] = {"domain": set(), "ip": set()}
            if norm.registrable_domain:
                pre_indicators["domain"].add(norm.registrable_domain.lower())
            if not norm.is_ip_literal:
                pre_indicators["domain"].add(norm.host.lower())
            if norm.ip:
                pre_indicators["ip"].add(norm.ip)
            for hop in fetch_result.hops:
                pre_indicators["ip"].update(hop.resolved_ips[:4])
            # Audit M-D: in multi-tenant mode, prior-hit lookups must be
            # scoped to what the owner may read (own + public reports), so
            # foreign private report IDs never leak into this report's
            # correlation evidence. Demo mode stays unrestricted.
            pre_visibility = ({"owner_id": owner_id}
                              if (settings.auth_required and owner_id) else None)
            pre_hits = repository.find_indicator_hits(
                pre_indicators, exclude_report_id=report_id, visibility=pre_visibility)
            if pre_hits:
                prior = build_prior_from_hits(pre_hits)
                corr_finding = correlate_finding(prior)
                if corr_finding is not None:
                    findings.append(corr_finding)
        except Exception:  # correlation must never break analysis
            logger.exception("correlation lookup failed for %s", report_id)

    # ---- Stage 6: threat-intel aggregation ----
    # Audit M2: the whole stage (domain pass + URL pass) runs under one
    # wall-clock budget (TRUSTLENS_INTEL_BUDGET_SECONDS, default 60s; 0
    # disables). Providers are called concurrently and bounded by provider
    # timeouts. On expiry the remaining provider checks are cancelled and
    # reported as FAILED coverage (never as a clean answer); findings and
    # authoritative matches obtained before the timeout are preserved.
    status = intel.status()
    tsum = ThreatIntelSummary()

    async def _run_intel_passes() -> None:
        if intel_domain_task is not None:
            try:
                domain_findings = await intel_domain_task
                findings.extend(domain_findings)
                tsum.total_findings += len(domain_findings)
            except Exception:
                logger.exception("threat-intel domain check failed for %s", report_id)
                unavailable.append("threat-intel (domain check failed)")
        elif norm.registrable_domain:
            try:
                domain_findings = await intel.check_domain(norm.registrable_domain)
                findings.extend(domain_findings)
                tsum.total_findings += len(domain_findings)
            except Exception:
                logger.exception("threat-intel domain check failed for %s", report_id)
                unavailable.append("threat-intel (domain check failed)")
        if fetch_result.success:
            try:
                url_findings = await intel.check_url(fetch_result.final_url or norm.url)
                findings.extend(url_findings)
                tsum.total_findings += len(url_findings)
            except Exception:
                logger.exception("threat-intel URL check failed for %s", report_id)
                unavailable.append("threat-intel (URL check failed)")

    intel_budget = max(0.0, float(settings.intel_budget_seconds))
    intel_timed_out = False
    if intel_budget > 0:
        try:
            await asyncio.wait_for(_run_intel_passes(), timeout=intel_budget)
        except asyncio.TimeoutError:
            intel_timed_out = True
    else:
        await _run_intel_passes()

    if intel_timed_out:
        unavailable.append(
            f"threat-intel (budget of {intel_budget:.0f}s exceeded; remaining provider checks were cancelled)"
        )
        findings.append(Finding(
            id="INTEL-BUDGET-EXCEEDED",
            title="Threat-intel stage exceeded its time budget",
            severity=Severity.INFO,
            category=FindingCategory.INTEL,
            evidence=[
                f"The threat-intel stage did not finish within its {intel_budget:.0f}s budget.",
                "Providers that had not answered were cancelled: their silence is recorded as "
                "failed coverage, never as a clean result. Findings obtained before the "
                "timeout are preserved.",
            ],
            source="trustlens/intel",
            check_succeeded=False,
        ))
    else:
        # The stage completed (within budget, or no budget configured) — only
        # then does it count as completed coverage (audit L-C).
        completed.append("threat-intel")
    # Post-call statuses are more truthful than the pre-call snapshot: a
    # provider that got rate-limited DURING this analysis shows up as
    # rate_limited here instead of active (audit L-C).
    final_status = intel.status()
    tsum.providers = final_status
    tsum.note = intel_summary_note(final_status)

    # Threat-intel required-check state (see scoring.py policy): when at least
    # one provider is configured, at least one must answer. A clean no-hit is
    # an answer; transport/ratelimit/key failures are not.
    intel_outcome: tuple[list[str], list[str]] | None = None
    if norm.registrable_domain or fetch_result.success:
        configured = sorted(name for name, s in status.items() if s != "unconfigured")
        intel_outcome = (configured, intel.answered_providers())

    # The domain pass and the URL pass can each emit the same provider-status
    # finding (UNAVAILABLE / RATELIMIT / KEY-ERROR) — keep a single copy so the
    # report doesn't list the same unavailable provider twice.
    _seen_status: set[tuple[str, str]] = set()
    deduped: list[Finding] = []
    for f in findings:
        if f.category == FindingCategory.INTEL and not f.check_succeeded:
            key = (f.id, f.evidence[0] if f.evidence else "")
            if key in _seen_status:
                continue
            _seen_status.add(key)
        deduped.append(f)
    findings = deduped

    # ---- Stage 7: scoring ----
    # page-fetch is the hard-required check: without a completed fetch no
    # verdict is issued (Inconclusive), unless an authoritative feed hit
    # exists (protective precedence — see scoring.py).
    required_failures = [] if fetch_result.success else ["page-fetch"]
    engine = ScoringEngine()
    classification = engine.score(findings, None, required_failures=required_failures,
                                  intel_outcome=intel_outcome)
    completed.append("scoring")
    # The summary's authoritative_hits lists the finding IDs whose authority
    # rule actually FIRED (engine-decided, evidence-based) — not a severity
    # proxy, which over-counts now that same-id findings survive the dedup
    # (audit M-A follow-up).
    tsum.authoritative_hits = list(engine.ctx.authoritative_ids)

    ssum = ScoringSummary(
        score=engine.ctx.score,
        high=engine.ctx.high,
        medium=engine.ctx.medium,
        low=engine.ctx.low,
        authoritative_hits=engine.ctx.authoritative_hits,
        key_checks_failed=engine.ctx.key_checks_failed,
        key_checks_unavailable=engine.ctx.key_checks_unavailable,
    )
    tsum.checks_performed = [p for p, s in final_status.items() if s == "active"]

    report = AnalysisReport(
        report_id=report_id,
        created_at=created_at,
        input_type=InputType.URL,
        raw_input=raw,
        normalized=normalized,
        classification=classification,
        classification_rationale=classification_rationale(classification, findings, engine.ctx),
        findings=findings,
        redirect_chain=fetch_result.hops,
        fetch=FetchSummary(
            final_url=fetch_result.final_url,
            status_code=fetch_result.status_code,
            success=fetch_result.success,
            ok=fetch_result.ok,
            error_kind=fetch_result.error_kind,
            error=fetch_result.error,
            content_type=fetch_result.content_type,
            title=fetch_result.title,
            total_bytes=fetch_result.total_bytes,
            elapsed_ms=fetch_result.elapsed_ms,
        ),
        tls=tls,
        threat_intel=tsum,
        ct_history=ct_summary,
        scoring=ssum,
        coverage=Coverage(
            attempted=10,
            completed=len(completed),
            completed_checks=completed,
            unavailable_checks=unavailable,
        ),
        recommended_actions=recommended_actions(classification, findings),
        limitations=list(_LIMITATIONS),
        extras=extras,
    )
    # ---- Stage 8: AI/rule-based explanation (cannot change classification) ----
    from ..llm.explain import explain_report
    try:
        report.explanation = await explain_report(report, settings)
    except Exception as exc:  # explanations must never break analysis
        logger.warning("explanation generation failed: %s", type(exc).__name__)

    # ---- Stage 9: correlation record + matches (rule-based, DB only) ----
    correlation_payload: dict = {"shared_indicators": [], "similar_reports": [],
                                 "prior": {}, "summary": "Correlation disabled (report not persisted).",
                                 "note": ""}
    if persist:
        try:
            indicators = extract_indicators(report)
            await asyncio.to_thread(
                repository.record_indicators, report.report_id, indicators, classification.value
            )
            # Same visibility scoping as stage 5c (audit M-D): the persisted
            # correlation snapshot must not embed foreign private report IDs.
            corr_visibility = ({"owner_id": owner_id}
                               if (settings.auth_required and owner_id) else None)
            hits = await asyncio.to_thread(
                repository.find_indicator_hits, indicators, report.report_id, corr_visibility
            )
            texts = await asyncio.to_thread(
                repository.get_report_texts, report.report_id, 100, corr_visibility
            )
            similar = tfidf_cosine(report.raw_input, texts)
            correlation_payload = build_matches(report, hits, similar)
            completed.append("correlation")
            report.coverage.completed = len(completed)
            report.coverage.completed_checks = list(completed)
        except Exception:
            logger.exception("correlation stage failed for %s", report_id)
            unavailable.append("correlation (failed)")
            # Coverage was already built into the report — keep the model in sync
            # (pydantic copied the local list at construction time).
            report.coverage.unavailable_checks = list(unavailable)
    report.extras = {**report.extras, "correlation": correlation_payload}

    # Integrity hash is computed AFTER all stored content exists (explanation is
    # excluded from the canonical payload as regenerable prose).
    report.integrity = _canonical_hash(report)

    if persist:
        payload = json.loads(report.model_dump_json())
        try:
            await asyncio.to_thread(repository.save_report, payload, owner_id=owner_id)
        except Exception:
            logger.exception("failed to persist report %s", report_id)
    return report


# Fields excluded from the canonical-JSON hash. `integrity` is the hash carrier
# itself; `explanation` is regenerable presentation output (rule-based or LLM) —
# the on-chain commitment proves the deterministic analysis, not the prose.
CANONICAL_EXCLUDE = {"integrity", "explanation"}


def _canonical_hash(report: AnalysisReport) -> IntegrityInfo:
    payload = json.loads(report.model_dump_json(exclude=CANONICAL_EXCLUDE))  # type: ignore[arg-type]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return IntegrityInfo(canonical_json_sha256=digest)
