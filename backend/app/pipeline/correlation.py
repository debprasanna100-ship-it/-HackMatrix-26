"""Threat correlation (Phase 6): deterministic matching of past analyses.

Indicators (registrable domain, host, resolved IPs, TLS issuer, message text
hash) are recorded for every persisted report. Correlation is purely rule-based:

  * shared indicators — exact matches on normalised values;
  * text similarity — TF-IDF cosine over report raw_input (implemented in pure
    Python; no heavyweight dependencies).

The LLM may summarise relationships in a future iteration, but matching itself
never involves the model.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Optional

from ..models.enums import FindingCategory, Severity
from ..models.schemas import AnalysisReport, Finding

SOURCE = "trustlens/correlation"

_WORD_RE = re.compile(r"[a-z0-9]{3,}")
# Small-corpus IDF down-weights shared vocabulary, so modest overlaps land
# around 0.25-0.35; unrelated texts land under 0.15.
SIMILARITY_THRESHOLD = 0.25


# ---- indicator extraction -----------------------------------------------------


def extract_indicators(report: AnalysisReport) -> dict[str, set[str]]:
    """Pull normalised indicators out of a finished report.

    Returns {kind: {values}} with kinds: domain, ip, issuer, message_hash.
    """
    out: dict[str, set[str]] = {"domain": set(), "ip": set(), "issuer": set(), "message_hash": set()}

    if report.normalized:
        if report.normalized.registrable_domain:
            out["domain"].add(report.normalized.registrable_domain.lower())
        if report.normalized.host and not report.normalized.is_ip_literal:
            out["domain"].add(report.normalized.host.lower())
        if report.normalized.ip:
            out["ip"].add(report.normalized.ip)

    for hop in report.redirect_chain:
        for ip in hop.resolved_ips:
            try:
                import ipaddress as _ipa
                _ipa.ip_address(ip)
                out["ip"].add(ip)
            except ValueError:
                continue

    if report.tls and report.tls.issuer_common_name:
        out["issuer"].add(report.tls.issuer_common_name.strip().lower())

    msg_hash = (report.extras or {}).get("message_sha256")
    if isinstance(msg_hash, str) and msg_hash:
        out["message_hash"].add(msg_hash)

    return {k: v for k, v in out.items() if v}


def build_prior_from_hits(hits: dict) -> dict:
    """Reduce raw indicator hits to the strongest single prior for the finding.

    Prefers domain indicators, then the highest prior count; worst prior
    classification decides the severity band.
    """
    rank = {"low_risk": 1, "suspicious": 2, "inconclusive": 0, "high_risk": 3, "confirmed_malicious": 4}
    best: Optional[dict] = None
    for kind, entries in hits.items():
        for value, info in entries.items():
            if not info.get("prior_count"):
                continue
            candidate = {
                "kind": kind,
                "indicator": value,
                "domain": value if kind == "domain" else None,
                "prior_count": info["prior_count"],
                "prior_classifications": info.get("prior_classifications", []),
            }
            if best is None:
                best = candidate
                continue
            # Prefer domains, then more priors, then worse classification.
            better = (
                (kind == "domain" and best.get("kind") != "domain")
                or (info["prior_count"] > best["prior_count"] and kind == best.get("kind"))
            )
            if better:
                best = candidate
    if best is None:
        best = {"kind": None, "indicator": None, "domain": None, "prior_count": 0,
                "prior_classifications": []}
    classifications = best.get("prior_classifications") or []
    best["worst_prior_classification"] = max(
        classifications, key=lambda c: rank.get(c, 0), default=""
    )
    return best


def correlate_finding(prior: dict) -> Optional[Finding]:
    """Finding for an indicator seen in previous analyses (rule-based)."""
    worst = prior.get("worst_prior_classification", "")
    domain = prior.get("domain")
    sev = Severity.MEDIUM if worst in ("confirmed_malicious", "high_risk") else Severity.INFO
    lines = [
        f"Indicator '{domain or prior.get('indicator')}' appeared in {prior['prior_count']} earlier "
        f"TrustLens analysis(es).",
        f"Prior classifications: {prior['prior_classifications']}.",
        "Reputation history is context, not proof: legitimate infrastructure can be reused by "
        "campaigns, and earlier benign verdicts can age out.",
    ]
    fid = "CORR-PRIOR-MALICIOUS" if sev == Severity.MEDIUM else "CORR-PRIOR-SEEN"
    title = ("Indicator previously seen in high-risk analyses"
             if sev == Severity.MEDIUM else "Indicator seen in previous analyses")
    return Finding(
        id=fid, title=title, severity=sev, category=FindingCategory.CORRELATION,
        evidence=lines, source=SOURCE,
    )


# ---- text similarity (TF-IDF cosine, pure python) -------------------------------


def _tokenize(text: str) -> Counter:
    return Counter(_WORD_RE.findall(text.lower()))


def tfidf_cosine(target: str, candidates: dict[str, str]) -> dict[str, float]:
    """TF-IDF cosine similarity of `target` against each candidate text.

    IDF is computed over the union {target} ∪ candidates so no extra storage or
    corpus statistics are required. Returns {} when either side has no tokens.
    """
    docs = {"__target__": _tokenize(target)}
    docs.update({k: _tokenize(v) for k, v in candidates.items()})
    n_docs = len(docs)
    if n_docs < 2 or not docs["__target__"]:
        return {}

    df: Counter = Counter()
    for tokens in docs.values():
        for word in tokens:
            df[word] += 1

    def tfidf(tokens: Counter) -> dict[str, float]:
        total = sum(tokens.values()) or 1
        return {w: (c / total) * math.log((1 + n_docs) / (1 + df[w])) + 1e-9 for w, c in tokens.items()}

    vectors = {k: tfidf(v) for k, v in docs.items()}
    target_vec = vectors.pop("__target__")
    target_norm = math.sqrt(sum(v * v for v in target_vec.values())) or 1.0

    scores: dict[str, float] = {}
    for key, vec in vectors.items():
        dot = sum(target_vec.get(w, 0.0) * v for w, v in vec.items())
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        scores[key] = dot / (target_norm * norm)
    return scores


# ---- public API used by runner / routes -----------------------------------------


def build_matches(
    report: AnalysisReport,
    indicator_hits: dict,
    similar_reports: dict[str, float],
) -> dict:
    """Assemble the correlation payload for a report (rule-based)."""
    shared: list[dict] = []
    for kind, entries in indicator_hits.items():
        for value, info in entries.items():
            if info["prior_count"]:
                shared.append({
                    "kind": kind,
                    "value": value,
                    "prior_count": info["prior_count"],
                    "report_ids": info["report_ids"][:5],
                    "prior_classifications": sorted(set(info["prior_classifications"])),
                })

    worst_rank = {"low_risk": 1, "suspicious": 2, "inconclusive": 0, "high_risk": 3, "confirmed_malicious": 4}
    prior_classifications = [c for s in shared for c in s["prior_classifications"]]
    worst = max(prior_classifications, key=lambda c: worst_rank.get(c, 0), default="")

    similar = [
        {"report_id": rid, "text_similarity": round(score, 3)}
        for rid, score in sorted(similar_reports.items(), key=lambda kv: -kv[1])
        if score >= SIMILARITY_THRESHOLD
    ][:5]

    domain = (report.normalized.registrable_domain if report.normalized else None) or \
        next((s["value"] for s in shared if s["kind"] == "domain"), None)

    prior = {
        "indicator": domain,
        "domain": domain,
        "prior_count": sum(s["prior_count"] for s in shared),
        "prior_classifications": prior_classifications,
        "worst_prior_classification": worst,
    }

    summary_bits = [f"{s['kind']} '{s['value']}' shared with {s['prior_count']} earlier report(s)"
                    for s in shared[:3]]
    text_bits = [f"message text ~{int(s['text_similarity'] * 100)}% similar to report {s['report_id']}"
                 for s in similar[:2]]
    summary = ("Deterministic matches: " + "; ".join(summary_bits + text_bits)) if (summary_bits or text_bits) \
        else "No prior TrustLens analyses share indicators with this report."

    return {
        "shared_indicators": shared,
        "similar_reports": similar,
        "prior": prior,
        "summary": summary,
        "note": ("Matching is rule-based (exact indicator equality + TF-IDF cosine over report text); "
                 "the AI never decides relationships."),
    }
