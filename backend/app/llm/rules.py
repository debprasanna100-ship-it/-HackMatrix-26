"""Rule-based explanation fallback (offline mode — no LLM, no key required).

Produces the same structured output shape as the LLM path so downstream code
(UI, schema) never branches on provider availability. Every claim references a
finding id; wording is deterministic and honest ("no significant indicators
found in the available checks", never "safe").
"""
from __future__ import annotations

import json
from typing import Optional

from ..models.enums import Classification, Severity
from ..models.schemas import AnalysisReport, Finding

_SEVERITY_RANK = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}


def _top_findings(findings: list[Finding], limit: int = 6) -> list[Finding]:
    ranked = sorted(
        [f for f in findings if f.severity != Severity.INFO or not f.check_succeeded],
        key=lambda f: -_SEVERITY_RANK[f.severity],
    )
    return ranked[:limit]


def build_explanation(report: AnalysisReport) -> dict:
    """Return an ExplanationResult-shaped dict derived purely from findings."""
    findings = report.findings
    classification = report.classification
    top = _top_findings(findings)

    # ---- summary ----
    domain = (report.normalized.registrable_domain or report.normalized.host) if report.normalized else None
    counts = {"high": sum(f.severity == Severity.HIGH for f in findings),
              "medium": sum(f.severity == Severity.MEDIUM for f in findings),
              "low": sum(f.severity == Severity.LOW for f in findings)}
    if classification == Classification.CONFIRMED_MALICIOUS:
        hits = ", ".join(report.threat_intel.authoritative_hits) or "threat-intel feed"
        summary = (
            f"{domain or 'This target'} matches known malicious infrastructure reported by {hits}. "
            "Do not interact with it."
        )
    elif classification == Classification.INCONCLUSIVE:
        missing = "; ".join(report.coverage.unavailable_checks)
        if not missing:
            failed = [f.title.lower() for f in findings if not f.check_succeeded]
            missing = "; ".join(failed) if failed else "one or more key checks did not complete"
        summary = (
            f"A reliable verdict was not possible: {missing}. This is a coverage limitation, "
            "not evidence of safety."
        )
    elif classification == Classification.HIGH_RISK:
        lead = top[0].title if top else "multiple strong indicators"
        summary = (
            f"{domain or 'This target'} shows strong risk indicators ({lead.lower()}"
            + (f" plus {counts['medium'] + counts['low']} weaker ones)." if counts["medium"] + counts["low"] else ").")
        )
    elif classification == Classification.SUSPICIOUS:
        names = ", ".join(f.title.lower() for f in top[:3])
        summary = f"{domain or 'This target'} raised {len(top)} indicator(s): {names}. Verify independently before trusting it."
    else:  # low_risk
        summary = (
            f"No significant indicators were found in the available checks for {domain or 'this target'}. "
            "That is not proof of safety — look-alike domains can pass every passive check."
        )

    # ---- claims (each must cite a finding id) ----
    claims: list[dict] = []
    for f in top:
        detail = f.evidence[0] if f.evidence else f.title
        claims.append({
            "claim": f"{f.title}: {detail}",
            "finding_ids": [f.id],
        })
    if not claims:
        claims.append({
            "claim": "No findings above informational severity were produced by the completed checks.",
            "finding_ids": [],
        })

    # ---- what this does NOT mean ----
    caveats = [
        "A valid TLS certificate proves encryption only, never legitimacy.",
        "Absence of threat-feed hits means the feeds had not seen this target recently; "
        "absence is never proof of safety.",
        "Passive checks cannot see JavaScript-rendered content, hidden redirects, or login-page payloads.",
    ]
    if any(not f.check_succeeded for f in findings):
        caveats.insert(0, "Some checks failed or were unavailable; their absence from this report is a coverage gap, not a clean result.")

    # ---- recommended actions (mirrors scoring guidance) ----
    actions = list(report.recommended_actions)

    return {
        "summary": summary,
        "claims": claims,
        "caveats": caveats,
        "recommended_actions": actions,
        "generated_by": "rule-based-fallback",
        "model": None,
        "stripped_claims": 0,
    }


def explanation_json_for_prompt(expl: dict) -> str:
    """Compact serialisation used when injecting into other prompts."""
    return json.dumps(expl, ensure_ascii=False, separators=(",", ":"))
