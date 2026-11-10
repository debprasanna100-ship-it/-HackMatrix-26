"""Deterministic risk scoring engine.

Takes the findings produced by the pipeline (normalisation, fetch, domain
heuristics, TLS, CT history, DNS records, threat intel) and accumulates a
weighted score into one of five classifications:

  LOW_RISK              — no significant indicators; "no significant indicators found in the available checks"
  SUSPICIOUS            — one or more low/medium indicators present
  HIGH_RISK             — multiple medium, or one high indicator, or a strong heuristic cluster
  CONFIRMED_MALICIOUS   — an authoritative threat-feed hit OR validated evidence (e.g. IP in 169.254.169.16/28,
                          known-malware URL from URLhaus/Virustotal, brand impersonation + payment keyword on a
                          disposable-looking domain)
  INCONCLUSIVE          — a REQUIRED check failed or timed out

Required vs optional checks (policy, enforced in `score()`):

  REQUIRED — `page-fetch`
      The SSRF-safe fetch must complete (DNS resolution + TCP connect + response
      headers). The runner (URL pipeline) and the message pipeline (embedded
      URLs) declare required-check failures explicitly via `required_failures`.
      A failed/timed-out/blocked fetch always yields INCONCLUSIVE — a verdict
      without a completed fetch is never issued.

  REQUIRED (conditional) — `threat-intel`
      When at least one threat-intel provider is *configured* (API key present),
      at least one configured provider must return a usable answer. If every
      configured provider is down / rate-limited / rejected (an outage), absence
      of intel hits is NOT evidence, so the report is INCONCLUSIVE. The runner
      passes this state as `intel_outcome=(configured, answered)`.

  OPTIONAL — everything else
      tls-analysis, ct-history, dns-records, header-checks, correlation, and
      *unconfigured* threat-intel providers. Their unavailability is preserved
      as evidence (finding with check_succeeded=False, excluded from counts and
      score, listed in coverage.unavailable_checks and
      scoring.key_checks_unavailable) but never changes the verdict band.
      Missing optional feed keys in particular are a configuration state, not a
      target signal.

Precedence (documented, deterministic):
  1. CONFIRMED_MALICIOUS — authoritative feed evidence wins over everything,
     including failed required checks. Rationale: positive, feed-confirmed
     evidence about the target must stay actionable; the hard rule is only that
     a failed check may never produce a *benign* verdict.
  2. INCONCLUSIVE — a required check failed (fetch) or every configured intel
     provider is unavailable.
  3. Risk bands (high_risk / suspicious / low_risk).

Design rules (hard):
  * The LLM is NEVER allowed to change the classification; it only explains.
  * If a required check fails/times out, the result is INCONCLUSIVE (never Low Risk).
  * Absence of findings is never "safe" — the report wording says
    "no significant indicators found in the available checks".
  * Weights are fixed constants in code, not in the LLM prompt.
  * A single authoritative intel hit is sufficient for CONFIRMED_MALICIOUS only
    when the source is a curated, verified feed (URLhaus, PhishTank verified+valid,
    VirusTotal positives >= threshold, GSB malware/social_engineering).

Authoritative feeds (strongest evidence):
  URLhaus, PhishTank (verified AND valid), VirusTotal (positives >= 6),
  Google Safe Browsing (malware / social engineering / PHA only).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from ..models.enums import Classification, FindingCategory, Severity
from ..models.schemas import AnalysisReport, Finding


@dataclass
class ScoreContext:
    """Accumulator for the scoring pass."""

    score: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    authoritative_hits: int = 0
    # Finding IDs whose authority rule actually FIRED (evidence-based, e.g.
    # VT positives >= threshold) — the authoritative drivers of the verdict.
    # Summaries must report THESE, not a severity proxy (audit M-A follow-up:
    # severity-based lists over-count when same-id findings are preserved).
    authoritative_ids: list[str] = field(default_factory=list)
    intel_findings: list[Finding] = field(default_factory=list)
    # Names of REQUIRED checks that failed (populated by the caller, which has
    # the pipeline context — e.g. ["page-fetch"]). Drives the INCONCLUSIVE gate.
    key_checks_failed: list[str] = field(default_factory=list)
    # IDs of findings whose check failed/was unavailable but is OPTIONAL —
    # preserved for the report summary, never gating.
    key_checks_unavailable: list[str] = field(default_factory=list)

    @property
    def any_intel(self) -> bool:
        return bool(self.intel_findings)


@dataclass
class WeightedFinding:
    """A finding with its effective weight and category context."""

    finding: Finding
    weight: int


# ---- severity weights ----
_WEIGHT = {Severity.INFO: 0, Severity.LOW: 2, Severity.MEDIUM: 5, Severity.HIGH: 8, Severity.CRITICAL: 12}

# ---- category overrides: same severity means different impact in different contexts ----
_CATEGORY_WEIGHT = {
    FindingCategory.FETCH: lambda sev: _WEIGHT[sev],
    FindingCategory.TLS: lambda sev: _WEIGHT[sev],
    # Domain heuristics can be quite discriminating on their own.
    FindingCategory.DOMAIN: lambda sev: _WEIGHT[sev],
    # Threat intel hits are authoritative evidence.
    FindingCategory.INTEL: lambda sev: _WEIGHT[sev] * 2,
    # CT history adds contextual weight to domain findings.
    FindingCategory.CORRELATION: lambda sev: _WEIGHT[sev],
    FindingCategory.DNS: lambda sev: _WEIGHT[sev],
    FindingCategory.SYSTEM: lambda sev: _WEIGHT[sev],
}

# ---- per-finding-id special rules ----
# Each handler is called as handler(engine, finding). NOTE: fetch-failure
# findings are NOT gated here — the caller declares required-check failures
# explicitly (see module docstring), because only the caller knows whether a
# failed fetch is THE required fetch (single target) or one of several embedded
# message URLs.
_SPECIAL_RULES = {
    # Authoritative intel confirmations -> immediate confirmed-malicious territory.
    "GSB-MATCH": lambda c, f: c._special_gsb(f),
    "URLHAUS-MATCH": lambda c, f: c._special_urlhaus(f),
    "OPENPHISH-MATCH": lambda c, f: c._special_openphish(f),
    "PHISHTANK-MATCH": lambda c, f: c._special_phishtank(f),
    "VT-MATCH": lambda c, f: c._special_vt(f),
}


@dataclass
class ScoringEngine:
    """Deterministic risk scorer."""

    # Authoritative intel thresholds.
    VT_MALICIOUS_THRESHOLD: int = 6
    GSB_HIGH_SEVERITY_TYPES = {"MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"}
    TTL_SECONDS: int = 300

    def __post_init__(self):
        self.ctx = ScoreContext()
        self.findings: list[Finding] = []
        self.coverage: dict[str, int] = {}
        self.now = time.time()

    @property
    def ttl(self) -> int:
        return self.TTL_SECONDS

    def _record(self, finding: Finding):
        self.findings.append(finding)
        sev = finding.severity
        if finding.check_succeeded:
            # Severity counts drive the classification bands; findings from
            # checks that themselves failed are coverage limitations, not
            # indicators, so they stay out of the counts (and the score below).
            self.ctx.low += sev == Severity.LOW
            self.ctx.medium += sev == Severity.MEDIUM
            self.ctx.high += sev == Severity.HIGH
        # Severity-based weight for the finding's category; an explicit
        # non-zero finding.weight overrides the table value.
        contribution = _CATEGORY_WEIGHT.get(finding.category, _CATEGORY_WEIGHT[FindingCategory.FETCH])(sev)
        if finding.weight:
            contribution = finding.weight
        if not finding.check_succeeded:
            # A check that itself failed or was unavailable is a coverage
            # limitation, not evidence about the target — it must never raise
            # the risk band (e.g. a crt.sh outage flagging benign sites).
            contribution = 0
        self.ctx.score += contribution

    def _special_gsb(self, finding: Finding) -> Optional[Classification]:
        # Evidence carries "THREAT_TYPE=MALWARE" strings (plus the raw URL).
        # Match only THREAT_TYPE-prefixed evidence: a naive substring check
        # over ALL lines would let a URL that merely contains "MALWARE"
        # trigger a confirmed-malicious verdict.
        prefix = "THREAT_TYPE="
        before = self.ctx.authoritative_hits
        for ev in finding.evidence:
            if ev.startswith(prefix) and any(
                gt in ev[len(prefix):] for gt in self.GSB_HIGH_SEVERITY_TYPES
            ):
                self.ctx.authoritative_hits += 1
        if self.ctx.authoritative_hits > before:
            self.ctx.authoritative_ids.append(finding.id)
        return None

    def _special_urlhaus(self, finding: Finding) -> Optional[Classification]:
        self.ctx.authoritative_hits += 1
        self.ctx.authoritative_ids.append(finding.id)
        return None

    def _special_openphish(self, finding: Finding) -> Optional[Classification]:
        self.ctx.authoritative_hits += 1
        self.ctx.authoritative_ids.append(finding.id)
        return None

    def _special_phishtank(self, finding: Finding) -> Optional[Classification]:
        self.ctx.authoritative_hits += 1
        self.ctx.authoritative_ids.append(finding.id)
        return None

    def _special_vt(self, finding: Finding) -> Optional[Classification]:
        evidence = finding.evidence
        before = self.ctx.authoritative_hits
        for e in evidence:
            if e.startswith("positives="):
                positives = int(e.split("=")[1].split("/")[0])
                if positives >= self.VT_MALICIOUS_THRESHOLD:
                    self.ctx.authoritative_hits += 1
        if self.ctx.authoritative_hits > before:
            self.ctx.authoritative_ids.append(finding.id)
        return None

    def _rule(self, finding: Finding):
        handler = _SPECIAL_RULES.get(finding.id)
        if handler:
            r = handler(self, finding)
            if r is not None:
                return r
        return None

    def score(
        self,
        findings: list[Finding],
        report: AnalysisReport | None = None,
        required_failures: Optional[list[str]] = None,
        intel_outcome: Optional[tuple[list[str], list[str]]] = None,
    ) -> Classification:
        """Return the deterministic classification.

        required_failures: names of REQUIRED checks that failed/timed out
            (declared by the caller — see module docstring).
        intel_outcome: (configured_provider_names, answered_provider_names).
            Configured = API key present. Answered = the provider returned a
            usable response for this analysis (a clean no-hit counts as an
            answer; transport/ratelimit/key failures do not).
        """
        # Rebuild from scratch. self.findings gets a FRESH list — never alias the
        # caller's list here: _record() appends to self.findings while score()
        # iterates the input, and aliasing caused an infinite loop.
        self.findings = []
        self.ctx = ScoreContext()
        if required_failures:
            self.ctx.key_checks_failed = list(dict.fromkeys(required_failures))

        # First pass: apply special rules.
        for f in findings:
            spec = self._rule(f)
            if spec is not None:
                return spec

        # Second pass: accumulate weights.
        for f in findings:
            self._record(f)

        # Optional-check unavailability is bookkeeping only — it must never
        # gate the verdict (a crt.sh outage or a missing feed key must not turn
        # a benign site inconclusive).
        self.ctx.key_checks_unavailable = sorted(
            {f.id for f in findings if not f.check_succeeded}
        )

        # 1. Authoritative evidence wins over everything (protective: positive
        #    feed-confirmed evidence stays actionable even when other checks
        #    failed; a failed check can never produce a *benign* verdict).
        if self.ctx.authoritative_hits > 0:
            return Classification.CONFIRMED_MALICIOUS

        # 2. Required-check gate: fetch failed, or every CONFIGURED intel
        #    provider was unavailable (an outage — absence of intel hits is
        #    then not evidence).
        if self.ctx.key_checks_failed:
            return Classification.INCONCLUSIVE
        if intel_outcome is not None:
            configured, answered = intel_outcome
            if configured and not answered:
                return Classification.INCONCLUSIVE

        # 3. Classification bands. A single high-severity indicator, or an
        #    accumulated score of 20+ (e.g. four medium indicators), puts a
        #    target in the high-risk band.
        if self.ctx.high >= 1 or self.ctx.score >= 20:
            return Classification.HIGH_RISK
        if self.ctx.medium >= 1 or self.ctx.low >= 1 or self.ctx.score >= 8:
            return Classification.SUSPICIOUS
        return Classification.LOW_RISK


# ---- helper for report construction (phase 2): build rationale + recommended actions ----

def classification_rationale(classification: Classification, findings: list[Finding], ctx: ScoreContext) -> str:
    if classification == Classification.LOW_RISK:
        return (
            "No significant indicators were found in the available checks. This means "
            "TRUSTLENS could not identify evidence of fraud or compromise; it does NOT prove the site is "
            "safe. Always verify the registrable domain directly with the organisation's known contact."
        )
    if classification == Classification.SUSPICIOUS:
        return (
            "Findings indicate suspicious activity. The deterministic score is "
            f"{ctx.score} points ({ctx.high} high / {ctx.medium} medium / {ctx.low} low indicators), "
            "but no authoritative threat-feed hit was required for this band. Treat the destination "
            "as untrusted until independently verified."
        )
    if classification == Classification.HIGH_RISK:
        return (
            "Strong indicators of risk. Multiple high-severity findings or a high weighted score "
            f"({ctx.score} points) place this on a high-risk band. Do not enter credentials, "
            "payment details, or personal information."
        )
    if classification == Classification.CONFIRMED_MALICIOUS:
        return (
            f"{ctx.authoritative_hits} authoritative threat-intel hit(s) confirmed this as malicious "
            "(authoritative sources: URLhaus, PhishTank, VirusTotal, Google Safe Browsing). "
            "This matches known malware/phishing infrastructure."
        )
    return (
        "Some key checks failed, timed out, or were unavailable, so a final classification could not be "
        "reliably computed. This is a coverage limitation, not a safe verdict."
    )


def recommended_actions(classification: Classification, findings: list[Finding]) -> list[str]:
    actions = ["Treat this report as one input alongside your own judgement; absence of findings is not proof of safety."]
    if classification == Classification.LOW_RISK:
        actions.insert(0, "No significant indicators found in the available checks.")
    elif classification == Classification.SUSPICIOUS:
        actions.insert(0, "Several suspicious indicators were found; verify the destination independently "
                          "(e.g. type the organisation's known address yourself).")
    elif classification == Classification.HIGH_RISK:
        actions.insert(0, "Multiple high-severity indicators were found: do not enter credentials, payment "
                          "details, or personal information on this site.")
    elif classification == Classification.CONFIRMED_MALICIOUS:
        actions = [
            "CONFIRMED MALICIOUS — do not visit, click links, or enter any information on this site.",
            "Report the URL/message to your security team and the relevant authorities.",
            "If you already entered credentials or payment details, contact your bank/card issuer and "
            "change your passwords immediately.",
        ]
    if any(f.id == "DOM-CREDENTIALS-IN-URL" for f in findings):
        actions.append("Never enter information into a URL containing credentials (userinfo); browsers ignore "
                       "the part before '@'.")
    return actions
