"""Scam / message analysis: deterministic extraction + tactic tagging.

Design rules (from the spec, enforced here):
  * Urgent or persuasive language ALONE must never label a message fraudulent.
    Language tactics are reported as "suspicious language" findings; only
    verified evidence — threat-intel hits on embedded URLs, look-alike domains,
    credential-collection links — can push a report toward malicious verdicts.
  * The LLM may summarise and tag with quoted evidence but cannot classify; the
    same deterministic scoring engine decides the final classification.
  * Extracted URLs run through the full URL pipeline (normalise -> safe fetch).
  * Message text is treated as untrusted everywhere: delimited for the model,
    never logged in full, capped at input size.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..config import Settings
from ..models.enums import FindingCategory, InputType, Severity
from ..models.schemas import (
    SCHEMA_VERSION,
    AnalysisReport,
    Coverage,
    ExplanationResult,
    FetchSummary,
    Finding,
    IntegrityInfo,
    NormalizedTarget,
    ScoringSummary,
    ThreatIntelSummary,
    intel_summary_note,
)
from .domain_heuristics import analyze_domain
from .fetcher import SafeFetcher
from .intel import IntelRegistry, init_intel
from .normalizer import UrlNormalizationError, normalize_url
from .runner import _canonical_hash, analyze_url
from .ssrf import SystemDnsResolver

SOURCE = "trustlens/message-analysis"

MAX_MESSAGE_CHARS = 20_000
MAX_EXTRACTED_URLS = 10

# ---- entity patterns ---------------------------------------------------------

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'\u200b-\u200f\u2060-\u2064\ufeff]+",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(
    r"(?<![\dA-Za-z])(?:\+?\d{1,3}[ .\-]?)?(?:\(?\d{2,4}\)?[ .\-]?){2,4}\d{2,4}(?![\dA-Za-z])"
)

PAYMENT_PATTERNS: list[tuple[str, str]] = [
    (r"\b(?:bitcoin|btc|crypto(?:currency)?|ethereum|eth|usdt|stablecoin)\b", "cryptocurrency"),
    (r"\bgift\s*card\b|\bapple\s*gift|\bsteam\s*wallet|\bgoogle\s*play\s*card\b", "gift card"),
    (r"\bwestern\s*union\b|\bmoneygram\b|\bwire\s*transfer\b|\bbank\s*transfer\b", "wire/transfer"),
    (r"\bpaypal\b(?!\.com)|\bvenmo\b|\bzelle\b|\bcash\s*app\b", "P2P payment app"),
    (r"\b(?:payment|invoice|fee|taxes?|refund|payout)\b", "payment demand"),
    (r"\b(?:credit\s*card|debit\s*card|cvv|card\s*number)\b", "card details"),
]

# Social-engineering tactic lexicons. Each hit records the matched phrase as
# quoted evidence so humans (and the LLM) can see exactly what triggered it.
TACTICS: dict[str, tuple[list[str], str]] = {
    "urgency": (
        ["immediately", "right now", "within 24 hours", "within 48 hours", "expires today",
         "last chance", "act now", "hurry", "urgent", "asap", "final notice", "time is running out"],
        "Time pressure to bypass careful thinking.",
    ),
    "threat_or_consequence": (
        ["account will be closed", "account suspended", "will be terminated", "legal action",
         "police", "arrest", "lawsuit", "locked out", "permanently disabled", "your account has been compromised",
         "suspended unless", "closed unless"],
        "Threat of negative consequence if the recipient does not act.",
    ),
    "impersonation": (
        ["paypal", "netflix", "microsoft", "apple", "google", "amazon", "bank of america", "chase",
         "wells fargo", "binance", "coinbase", "irs", "hmrc", "fedex", "dhl", "ups", "usps",
         "customer support", "security team", "fraud department", "compliance"],
        "Claims to be a known organisation or authority.",
    ),
    "credential_harvesting": (
        ["verify your account", "confirm your identity", "update your password", "sign in to verify",
         "validate your login", "re-enable your account", "enter your credentials", "one-time code",
         "otp", "2fa code", "share your code", "read this code aloud"],
        "Asks the recipient to supply or relay authentication material.",
    ),
    "too_good_to_be_true": (
        ["you have been selected", "you won", "congratulations", "claim your prize", "lottery",
         "free iphone", "inheritance", "unclaimed funds", "double your money", "guaranteed returns"],
        "Unrealistic reward offered for little effort.",
    ),
    "secrecy": (
        ["do not tell anyone", "keep this confidential", "secret transaction", "don't share this",
         "between us", "private matter"],
        "Instructs the recipient to hide the interaction — classic fraud isolation tactic.",
    ),
    "authority_pressure": (
        ["ceo", "hr department", "payroll", "the tax office", "court order", "government official",
         "manager asked me"],
        "Invokes authority figures to discourage verification.",
    ),
}

# Payment demands that pair with secrecy/cryptocurrency are stronger signals
# than any single tactic, but still "suspicious language", not proof.
_STRONG_LANGUAGE_COMBOS = [("cryptocurrency", "secrecy"), ("gift card", "urgency")]


@dataclass
class ExtractedEntities:
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    payment_indicators: list[str] = field(default_factory=list)
    tactic_tags: list[dict] = field(default_factory=list)  # [{tactic, phrases, note}]

    def to_report_dict(self) -> dict:
        """Privacy-preserving entity summary for the persisted report.

        Extracted email addresses and phone numbers are personal data that is
        not needed for the verdict — they are stored as COUNTS only, never as
        values (in reports or anywhere else). Extracted URLs remain: they are
        the analysis subject and are needed to make embedded-URL reports
        retrievable. See docs/methodology.md (privacy section).
        """
        return {
            "extracted_urls": self.urls,
            "extracted_email_count": len(self.emails),
            "extracted_phone_count": len(self.phones),
            "payment_indicators": self.payment_indicators,
            "tactics": self.tactic_tags,
        }


def extract_entities(message: str) -> ExtractedEntities:
    ent = ExtractedEntities()

    seen_urls: set[str] = set()
    for m in URL_RE.finditer(message):
        raw = m.group(0).rstrip(".,;:!?)>'\"]")
        url = raw if re.match(r"^https?://", raw, re.I) else "http://" + raw
        if url.lower() not in seen_urls:
            seen_urls.add(url.lower())
            ent.urls.append(url)
        if len(ent.urls) >= MAX_EXTRACTED_URLS:
            break

    seen_emails = {e.lower() for e in ent.emails}
    for m in EMAIL_RE.finditer(message):
        email = m.group(0)
        if email.lower() not in seen_emails:
            ent.emails.append(email)
            seen_emails.add(email.lower())

    seen_phones: set[str] = set()
    for m in PHONE_RE.finditer(message):
        digits = re.sub(r"\D", "", m.group(0))
        if 7 <= len(digits) <= 15 and digits not in seen_phones:
            ent.phones.append(m.group(0).strip())
            seen_phones.add(digits)

    lowered = message.lower()
    for pattern, label in PAYMENT_PATTERNS:
        if re.search(pattern, lowered):
            ent.payment_indicators.append(label)

    for tactic, (phrases, note) in TACTICS.items():
        hits = [p for p in phrases if p in lowered]
        if hits:
            ent.tactic_tags.append({
                "tactic": tactic,
                "phrases": hits[:5],
                "note": note,
            })

    return ent


def _finding(fid: str, title: str, severity: Severity, evidence: list[str],
             check_succeeded: bool = True) -> Finding:
    return Finding(
        id=fid, title=title, severity=severity, category=FindingCategory.MESSAGE,
        evidence=evidence, source=SOURCE, check_succeeded=check_succeeded,
    )


def _language_findings(ent: ExtractedEntities) -> list[Finding]:
    """Suspicious-language findings. Explicitly NOT proof of fraud."""
    findings: list[Finding] = []
    if ent.tactic_tags:
        lines = []
        for t in ent.tactic_tags:
            quoted = ", ".join(f'"{p}"' for p in t["phrases"][:4])
            lines.append(f"{t['tactic']}: {quoted} — {t['note']}")
        findings.append(_finding(
            "MSG-LANGUAGE-TACTICS",
            "Message uses social-engineering language patterns",
            Severity.LOW,
            lines + [
                "Persuasive or urgent wording alone does NOT make a message fraudulent; "
                "legitimate organisations sometimes write badly. These are soft indicators only.",
            ],
        ))
    for combo_a, combo_b in _STRONG_LANGUAGE_COMBOS:
        if combo_a in ent.payment_indicators and any(t["tactic"] == combo_b for t in ent.tactic_tags):
            findings.append(_finding(
                "MSG-PAYMENT-PRESSURE",
                f"Payment method ({combo_a}) combined with {combo_b.replace('_', ' ')} instructions",
                Severity.MEDIUM,
                [
                    f"Detected payment indicator '{combo_a}' alongside tactic '{combo_b}'.",
                    "This combination is common in scams, but remains suspicious language, "
                    "not verified evidence of fraud.",
                ],
            ))
            break
    return findings


OTP_REQUEST_RE = re.compile(
    r"\b(?:share|send|give|read aloud|forward|tell me|reply with|respond with|enter)\b.{0,40}\b(?:code|otp|one[- ]time)\b",
    re.IGNORECASE | re.DOTALL,
)


def _otp_finding(message: str) -> list[Finding]:
    m = OTP_REQUEST_RE.search(message)
    if not m:
        return []
    snippet = re.sub(r"\s+", " ", m.group(0))[:120]
    return [_finding(
        "MSG-OTP-REQUEST",
        "Message asks the recipient to hand over a one-time code",
        Severity.HIGH,
        [
            f'Matched text: "{snippet}".',
            "No legitimate company asks customers to send or read aloud their login codes; "
            "this is an account-takeover attempt indicator.",
        ],
    )]


async def analyze_message(
    text: str,
    settings: Settings,
    fetcher: SafeFetcher | None = None,
    intel: IntelRegistry | None = None,
    persist: bool = True,
    owner_id: str | None = None,
) -> AnalysisReport:
    """Full message analysis: entities -> language findings -> URL pipeline per link.

    `intel` may be injected (tests / a shared registry); a fresh registry is
    created otherwise and shared by every embedded-URL analysis so provider
    caches and backoff state are reused across the sub-reports."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("message text is empty")
    message = text[:MAX_MESSAGE_CHARS]
    truncated = len(text) > MAX_MESSAGE_CHARS

    ent = extract_entities(message)
    findings: list[Finding] = _language_findings(ent) + _otp_finding(message)
    if truncated:
        findings.append(_finding(
            "MSG-TRUNCATED", "Message exceeded the analysis cap and was truncated",
            Severity.INFO, [f"Only the first {MAX_MESSAGE_CHARS} characters were analysed."],
            check_succeeded=False,
        ))

    # Coverage model for message reports (stages of THIS pipeline):
    #   message-entity-extraction | language-analysis | embedded-url-analysis
    completed: list[str] = ["message-entity-extraction", "language-analysis"]
    unavailable: list[str] = []
    attempted = 3

    # Run each extracted URL through the real URL pipeline (safe fetch
    # included). Sub-reports are PERSISTED so the message report's embedded-URL
    # links stay retrievable; their findings are lifted into this report.
    #
    # Audit M2: the whole embedded-URL stage runs under one aggregate
    # wall-clock budget (TRUSTLENS_MESSAGE_URL_BUDGET_SECONDS, default 240s;
    # 0 disables) so a message with many links cannot multiply the per-URL
    # cost (fetch + CT + DNS + intel) without bound. URLs past the deadline
    # are SKIPPED and reported as failed coverage (MSG-URL-SKIPPED), never as
    # clean results. Cancellation of the intel stage inside each URL analysis
    # is bounded by that stage's own budget (audit M2), so this loop cannot
    # stall indefinitely.
    sub_reports: list[AnalysisReport] = []
    invalid_url_count = 0
    skipped_urls: list[str] = []
    url_budget = max(0.0, float(settings.message_url_budget_seconds))
    url_deadline = (time.monotonic() + url_budget) if url_budget > 0 else None
    fetcher = fetcher or SafeFetcher(settings, SystemDnsResolver(timeout=3.0))
    intel = intel or init_intel(settings)
    for url in ent.urls:
        if url_deadline is not None and time.monotonic() > url_deadline:
            skipped_urls.append(url)
            continue
        try:
            sub = await analyze_url(url, settings, fetcher=fetcher, intel=intel,
                                    persist=True, owner_id=owner_id)
        except UrlNormalizationError as exc:
            invalid_url_count += 1
            findings.append(_finding(
                "MSG-URL-INVALID", "Extracted string could not be parsed as a URL",
                Severity.INFO, [str(exc)[:200]], check_succeeded=False,
            ))
            continue
        sub_reports.append(sub)
        # Lift every finding from the URL pipeline into the message report.
        findings.extend(sub.findings)
        # Verified-evidence escalations from feeds/lookalikes stay authoritative.

    if skipped_urls:
        skipped_list = "; ".join(skipped_urls[:5]) + (" …" if len(skipped_urls) > 5 else "")
        findings.append(_finding(
            "MSG-URL-SKIPPED",
            "Embedded URLs skipped: message analysis budget exhausted",
            Severity.INFO,
            [
                f"{len(skipped_urls)} of {len(ent.urls)} embedded URL(s) were not analysed: "
                f"the message URL-analysis budget of {url_budget:.0f}s ran out.",
                f"Skipped: {skipped_list}",
                "Skipped URLs are a coverage limitation of this analysis run, NOT a clean "
                "result. Re-run the analysis to cover them.",
            ],
            check_succeeded=False,
        ))
        unavailable.append(
            f"embedded-url-analysis ({len(skipped_urls)}/{len(ent.urls)} embedded URL(s) skipped: "
            f"message URL-analysis budget of {url_budget:.0f}s exhausted)"
        )

    if not ent.urls:
        unavailable.append("embedded-url-analysis (no URLs found in the message)")
    elif sub_reports:
        completed.append("embedded-url-analysis")
        failed_fetches = sum(1 for s in sub_reports if not s.fetch.success)
        if failed_fetches:
            unavailable.append(
                f"embedded-url-fetch ({failed_fetches}/{len(sub_reports)} embedded URL fetch(es) failed)"
            )
    else:
        unavailable.append(
            f"embedded-url-analysis (none of the {len(ent.urls)} extracted URL(s) could be parsed)"
        )

    # Deduplicate identical findings across sub-reports. The key is
    # (finding id, first evidence line) — NOT the id alone: two embedded URLs
    # can legitimately produce the same finding id with different strengths
    # (e.g. VT-MATCH with positives=3 from URL A, positives=9 from URL B);
    # keying on the id alone would drop B's authoritative evidence BEFORE
    # scoring and dampen confirmed_malicious to high_risk (audit M-A). The
    # URL runner uses the same key for its failed-status dedup
    # (runner.py) — identical evidence still collapses, distinct evidence
    # is preserved and scored.
    deduped: dict[tuple[str, str], Finding] = {}
    for f in findings:
        deduped.setdefault((f.id, f.evidence[0] if f.evidence else ""), f)
    findings = sorted(deduped.values(), key=lambda f: -{Severity.CRITICAL: 4, Severity.HIGH: 3,
                                                        Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}[f.severity])

    # Deterministic scoring via the same engine used for URLs.
    from .scoring import ScoringEngine, classification_rationale, recommended_actions

    # Required-check policy (scoring.py / methodology §7): when a message
    # embeds URLs, the embedded-URL fetch is the required check — if EVERY
    # embedded URL failed to complete a fetch, the verdict is Inconclusive.
    # Failed fetches, unparsable URLs, and budget-skipped URLs all count as
    # "not fetched" (none of them completed a fetch); partial failures (a mix
    # of live and dead links) stay scorable and remain visible as evidence.
    required_failures: list[str] = []
    if ent.urls and (not sub_reports or all(not s.fetch.success for s in sub_reports)):
        required_failures = ["page-fetch (embedded URLs)"]
    engine = ScoringEngine()
    classification = engine.score(findings, None, required_failures=required_failures)

    # Audit M1: message reports previously carried the pydantic defaults for
    # `scoring` and `threat_intel` (all zeros / no providers) even when the
    # deterministic engine had scored real findings. Populate both from the
    # actual scoring context and the intel registry state — the same truthful
    # summaries the URL runner builds. No value here implies a check ran when
    # it did not: `providers` is configuration status (never "clean"),
    # `checks_performed` is empty unless embedded-URL analyses (the only place
    # a message triggers intel work) actually ran, and the counts come from
    # the engine's context.
    ssum = ScoringSummary(
        score=engine.ctx.score,
        high=engine.ctx.high,
        medium=engine.ctx.medium,
        low=engine.ctx.low,
        authoritative_hits=engine.ctx.authoritative_hits,
        key_checks_failed=engine.ctx.key_checks_failed,
        key_checks_unavailable=engine.ctx.key_checks_unavailable,
    )
    intel_status = intel.status()
    tsum = ThreatIntelSummary(
        providers=intel_status,
        checks_performed=(
            [p for p, s in intel_status.items() if s == "active"] if sub_reports else []
        ),
        # Engine-decided authoritative hits (evidence-based), never a severity
        # proxy — same-id findings with different strengths must not inflate
        # the summary beyond what actually drove the verdict (audit M-A).
        authoritative_hits=list(engine.ctx.authoritative_ids),
        total_findings=sum(1 for f in findings if f.category == FindingCategory.INTEL),
        note=intel_summary_note(intel_status),
    )

    message_sha256 = hashlib.sha256(message.encode("utf-8")).hexdigest()

    # Privacy: only a short excerpt of the message is persisted, and extracted
    # emails/phone numbers are never stored (counts only) — see the privacy
    # section in docs/methodology.md.
    report = AnalysisReport(
        schema_version=SCHEMA_VERSION,
        report_id="",  # assigned below
        created_at="",
        input_type=InputType.MESSAGE,
        raw_input=message[:500] + ("…" if len(message) > 500 else ""),
        normalized=None,
        classification=classification,
        classification_rationale=classification_rationale(classification, findings, engine.ctx),
        findings=findings,
        redirect_chain=[hop for s in sub_reports for hop in s.redirect_chain][:20],
        fetch=FetchSummary(error_kind="none", success=any(
            s.fetch.success for s in sub_reports
        )),
        threat_intel=tsum,
        scoring=ssum,
        coverage=Coverage(
            attempted=attempted,
            completed=len(completed),
            completed_checks=completed,
            unavailable_checks=unavailable,
        ),
        recommended_actions=recommended_actions(classification, findings),
        limitations=[
            "TrustLens never executes JavaScript and never follows instructions inside messages.",
            "Social-engineering language tags are soft indicators; they do NOT prove fraud.",
            "Embedded URLs were analysed with the same passive pipeline as direct submissions.",
            "Absence of findings means 'no significant indicators found in the available checks', never 'safe'.",
        ],
        extras={
            "message": ent.to_report_dict(),
            "message_sha256": message_sha256,
            "sub_reports": [
                {
                    "report_id": s.report_id,
                    "url": s.normalized.url if s.normalized else None,
                    "classification": s.classification.value,
                }
                for s in sub_reports
            ],
        },
    )

    import uuid
    from datetime import datetime, timezone
    report.report_id = uuid.uuid4().hex
    report.created_at = datetime.now(timezone.utc).isoformat()
    report.integrity = _canonical_hash(report)

    # ---- explanation (rule-based offline; LLM when a key is configured) ----
    from ..llm.explain import explain_report
    try:
        report.explanation = await explain_report(report, settings)
    except Exception:  # explanations must never break analysis
        pass

    if persist:
        import asyncio
        import json
        from ..storage import repository
        # Correlation: record the message hash + embedded-URL domains so future
        # analyses can link related incidents (rule-based, DB only).
        try:
            indicators: dict[str, set[str]] = {"message_hash": {message_sha256}, "domain": set()}
            for s in sub_reports:
                if s.normalized and s.normalized.registrable_domain:
                    indicators["domain"].add(s.normalized.registrable_domain.lower())
            await asyncio.to_thread(
                repository.record_indicators, report.report_id, indicators, classification.value
            )
        except Exception:
            logging.getLogger("trustlens.message").warning(
                "indicator recording failed for %s", report.report_id
            )
        payload = json.loads(report.model_dump_json())
        try:
            await asyncio.to_thread(repository.save_report, payload, owner_id=owner_id)
        except Exception:
            logging.getLogger("trustlens.message").exception("failed to persist message report %s", report.report_id)
    return report
