"""Certificate Transparency (crt.sh) lookup.

Queries the public crt.sh API for all certificates issued for a domain. Used to
detect:
  * a certificate issued very recently (brand-new infra is a phishing signal),
  * a large number of certificates issued in a short window (cert-bombing /
    mass-issuance patterns typical of phishing kits and compromised CT logs).

Only public, read-only information is fetched. No credentials are required.
The API is rate-limited; results are cached per domain.

crt.sh documentation: https://crt.sh/docs

Note: crt.sh is a public aggregator, not a curated trust source. It complements
(never replaces) threat-intel feeds and heuristic analysis. A new cert is a
weak signal on its own.
"""
from __future__ import annotations

import base64
import hashlib
import html as _html
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Awaitable, Optional

import httpx
import idna

from ..config import Settings
from ..models.enums import FindingCategory, Severity
from ..models.schemas import Finding

SOURCE = "trustlens/crtsh"
API = "https://crt.sh/"
QUERY = "https://crt.sh/?q=%s&output=json"
CACHE_TTL_SECONDS = 300  # 5 minutes — CT logs mutate; this is a heuristic, not a security boundary.


def _parse_ts(value) -> Optional[datetime]:
    """Parse a crt.sh timestamp, returning None when absent/unparseable.

    The old API returned 'Z'-suffixed UTC stamps (inserted_timestamp); the 2025
    rewrite returns naive stamps (not_before). Naive values are treated as UTC
    so comparisons against timezone-aware datetimes never raise TypeError.
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class CtRecord:
    """One certificate record from crt.sh."""

    id: int
    name: str                    # common name or newline/comma-joined SAN list
    common_name: str
    names: list[str]
    entry_timestamp: Optional[datetime]  # log insertion (old schema) or not_before (2025 schema)
    issuer: str
    sha256: str
    sha1: str
    fingerprint: str

    @classmethod
    def from_api_json(cls, row: dict) -> "CtRecord":
        """Build a record from either crt.sh JSON schema.

        The 2025 crt.sh rewrite dropped `inserted_timestamp` and the
        certfingerprint* columns; the current JSON carries `not_before` and no
        fingerprints. Old-schema field names are still accepted first so
        historical payloads keep parsing.
        """
        name_val = row.get("name_value") or row.get("common_name") or ""
        return cls(
            id=int(row.get("id") or 0),
            name=name_val,
            common_name=re.split(r"[,\n]", name_val)[0].strip() if name_val else "",
            names=[n.strip() for n in re.split(r"[,\n]", name_val) if n.strip()],
            entry_timestamp=(
                _parse_ts(row.get("inserted_timestamp"))
                or _parse_ts(row.get("entry_timestamp"))
                or _parse_ts(row.get("not_before"))
            ),
            issuer=row.get("issuer_name", ""),
            sha256=(row.get("certfingerprintsha256") or ""),
            sha1=(row.get("certfingerprintsha1") or ""),
            fingerprint=row.get("certfingerprintsha256") or row.get("certfingerprintsha1", ""),
        )


class CrtshResult:
    """Aggregated CT findings for a domain."""

    def __init__(
        self,
        domain: str,
        records: list[CtRecord] = None,
        total: int = 0,
        fetched_at: datetime = None,
        error: Optional[str] = None,
    ):
        self.domain = domain
        self.records = records or []
        self.total = total
        self.fetched_at = fetched_at or datetime.now(timezone.utc)
        self.error = error

    @property
    def most_recent(self) -> Optional[datetime]:
        return max((r.entry_timestamp for r in self.records if r.entry_timestamp), default=None)

    @property
    def oldest(self) -> Optional[datetime]:
        return min((r.entry_timestamp for r in self.records if r.entry_timestamp), default=None)


def _domain_for_ct(domain: str) -> str:
    """Build a crt.sh query string covering the registrable domain and its subdomains.

    crt.sh wildcard query: '*.example.com' returns 'example.com' itself plus all
    immediate/sub-deep subdomains, depending on log coverage. For very deep or
    very old infra, this query alone may undercount; that is acceptable — we use
    it as a relative signal, not a ground truth.
    """
    if domain.startswith("*."):
        return domain
    try:
        ascii_domain = idna.encode(domain, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        ascii_domain = domain
    if "." in ascii_domain:
        return f"*.{ascii_domain}"
    return f"*.{ascii_domain}"


async def _fetch_json(url: str, timeout: float = 10.0) -> tuple[list[dict] | None, Optional[str]]:
    """Fetch crt.sh JSON with a per-request timeout and a soft cap on returned rows.

    crt.sh is frequently slow under load; the timeout is generous but bounded so
    the analysis pipeline degrades gracefully instead of hanging."""
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            trust_env=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; TrustLensBot/0.1; crt.sh lookup)"},
        ) as client:
            resp = await client.get(url)
        if resp.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            raise httpx.HTTPStatusError(
                "Too many requests (crt.sh rate limit)", request=resp.request,
                response=resp,
            )
        if resp.status_code != HTTPStatus.OK:
            raise RuntimeError(f"crt.sh returned {resp.status_code}")
        text = resp.text[:2_000_000]  # never materialise a gigabyte of JSON
        return json.loads(text), None
    except (httpx.HTTPError, RuntimeError, ValueError, TimeoutError,
            OSError, json.JSONDecodeError) as exc:
        # httpx.HTTPError covers timeouts (ReadTimeout/ConnectTimeout), connect
        # errors and HTTPStatusError — none of which are OSError/TimeoutError
        # subclasses, so they must be listed explicitly to keep crt.sh flakiness
        # from escaping into the runner as an unexpected exception.
        return None, f"{type(exc).__name__}: {str(exc)[:250]}"


def _find_in_record(text: str, name: str, default: str = "") -> str:
    """crude field extractor used as a fallback when named keys are missing."""
    m = re.search(rf'{name}"\s*:\s*"((?:\\.|[^"\\])*)"', text)
    if not m:
        return default
    raw = m.group(1)
    raw = raw.replace("\\/", "/")
    return _html.unescape(raw)


# Module-level cache so repeated analyses of the same domain within the TTL
# share one crt.sh request (the API is rate-limited).
_CACHE: dict[str, tuple[CrtshResult, float]] = {}


def query_ct(domain: str, use_cache: bool = True) -> Awaitable[CrtshResult]:
    """Query crt.sh for certificate history of `domain` with caching (async)."""
    cache_key = domain.lower().rstrip(".")

    async def _run() -> CrtshResult:
        if use_cache and cache_key in _CACHE:
            result, ts = _CACHE[cache_key]
            if time.time() - ts < CACHE_TTL_SECONDS:
                return result
            del _CACHE[cache_key]

        query_url = QUERY % _domain_for_ct(domain)
        raw, err = await _fetch_json(query_url)
        if err:
            # Do not cache failures: crt.sh is frequently transient (502s under
            # load), and a cached error would suppress retries for the whole TTL.
            return CrtshResult(domain, error=err)
        else:
            records: list[CtRecord] = []
            for row in (raw or []):
                if not isinstance(row, dict):
                    continue
                try:
                    records.append(CtRecord.from_api_json(row))
                except (ValueError, TypeError, AttributeError, IndexError):
                    continue
            result = CrtshResult(domain, records=records, total=len(records))

        _CACHE[cache_key] = (result, time.time())
        return result

    return _run()


async def analyze_ct(
    registrable_domain: str,
    cert_sha256: str = "",
    max_records: int = 2000,
) -> tuple[list[Finding], dict]:
    """Derive findings from certificate transparency history.

    Returns (findings, stats) where stats carries `records_found` and
    `most_recent` (ISO string or None) for the report's CT summary.
    """
    findings: list[Finding] = []
    stats: dict = {"records_found": 0, "most_recent": None}
    if not registrable_domain:
        return findings, stats

    result = await query_ct(registrable_domain)
    if result.error:
        findings.append(Finding(category=FindingCategory.TLS,
            id="CT-CACHE-FAIL",
            title="Certificate Transparency lookup unavailable",
            severity=Severity.LOW,
            evidence=[result.error],
            source=SOURCE,
            check_succeeded=False,
        ))
        # Surface the failure so the runner records ct-history as incomplete in
        # the coverage section rather than as a completed check.
        stats["error"] = result.error
        return findings, stats

    if not result.records:
        findings.append(Finding(category=FindingCategory.TLS, 
            id="CT-NONE-FOUND",
            title="No Certificate Transparency records for this domain",
            severity=Severity.INFO,
            evidence=[
                f"No public CT log entries for '{registrable_domain}' were found.",
                "Absence of CT records is not proof of legitimacy: new domains, private "
                "logs, and recently-issued certificates may not yet be indexed.",
            ],
            source=SOURCE,
        ))
        return findings, stats

    most_recent = result.most_recent
    oldest = result.oldest
    stats["records_found"] = result.total
    stats["most_recent"] = most_recent.isoformat() if most_recent else None

    now = datetime.now(timezone.utc)
    days_recent = (now - most_recent).days if most_recent else 0
    days_oldest = (now - oldest).days if oldest else 0
    recent_hours = (now - most_recent).total_seconds() / 3600 if most_recent else 0

    # Signal 1: a certificate issued very recently — fresh infra. Only a
    # meaningful signal on small domains: large legitimate sites (CDNs, SaaS)
    # reissue certificates constantly, so "recent" alone is noise there.
    small_domain = result.total < 10
    if most_recent and (days_recent <= 1 or recent_hours < 1) and small_domain:
        findings.append(Finding(category=FindingCategory.TLS, 
            id="CT-RECENTLY-ISSUED",
            title="Certificate issued extremely recently (hours) on a small CT footprint",
            severity=Severity.MEDIUM,
            evidence=[
                f"Most recent certificate for '{registrable_domain}' was issued "
                f"{recent_hours:.1f} hour(s) ago ({most_recent.isoformat()}); the domain has only "
                f"{result.total} CT record(s).",
                "Fresh certificates on brand-new domains are typical of disposable phishing "
                "infrastructure that cycles hosts to survive takedowns.",
            ],
            source=SOURCE,
        ))
    elif most_recent and days_recent <= 7:
        findings.append(Finding(category=FindingCategory.TLS, 
            id="CT-RECENTLY-ISSUED",
            title="Certificate issued recently (informational)",
            severity=Severity.INFO,
            evidence=[
                f"Most recent certificate for '{registrable_domain}' was issued {days_recent} day(s) ago "
                f"({most_recent.isoformat()}). Large sites reissue often; informational only.",
            ],
            source=SOURCE,
        ))

    # Signal 2: old infra but certificate inserted much later (certificate
    # re-announcement / log mutation — rare but seen in hijacked infra).
    if oldest and most_recent and oldest != most_recent and (now - oldest).days > 365:
        findings.append(Finding(category=FindingCategory.TLS, 
            id="CT-OLD-INFRA",
            title="Domain pre-dates its oldest known certificate by over a year",
            severity=Severity.INFO,
            evidence=[
                f"Earliest CT record is {days_oldest} days old while the newest is only {days_recent} days old.",
            ],
            source=SOURCE,
        ))

    # Signal 3: certificate volume — informational context only. Large
    # legitimate sites (CDNs, multi-tenant SaaS) have huge CT footprints, so
    # volume alone must never push the risk band.
    total = result.total
    if total >= 100:
        findings.append(Finding(category=FindingCategory.TLS, 
            id="CT-HIGH-VOLUME",
            title="High certificate volume for this domain (informational)",
            severity=Severity.INFO,
            evidence=[
                f"{total} certificate(s) issued for '{registrable_domain}' are present in CT logs.",
                "Volume is common for legitimate CDN/multi-tenant setups; correlated with "
                "certificate-bombing campaigns only when combined with other signals.",
            ],
            source=SOURCE,
        ))
    elif total >= 20:
        findings.append(Finding(category=FindingCategory.TLS, 
            id="CT-MODERATE-VOLUME",
            title="Moderate certificate volume for this domain (informational)",
            severity=Severity.INFO,
            evidence=[
                f"{total} certificate(s) issued for '{registrable_domain}' are present in CT logs.",
            ],
            source=SOURCE,
        ))

    # Signal 4: issuer diversity — many different CAs issuing for one domain
    # is a strong phishing-kit indicator (kits rotate through cheap/free CAs).
    # Only meaningful when certs-per-CA is low: long-lived domains accumulate
    # CA diversity over decades (CA churn, reissues) — e.g. example.com shows
    # 8+ CAs across dozens of records — so a high certs-per-CA ratio is
    # demoted to informational, mirroring the volume/recency calibration.
    unique_issuers = {r.issuer for r in result.records if r.issuer}
    certs_per_ca = total / len(unique_issuers) if unique_issuers else 0
    if len(unique_issuers) >= 8 and certs_per_ca < 3:
        findings.append(Finding(category=FindingCategory.TLS,
            id="CT-MULTIPLE-ISSUERS",
            title="Certificates issued by many different CAs",
            severity=Severity.MEDIUM,
            evidence=[
                f"Certificates for '{registrable_domain}' were issued by {len(unique_issuers)} distinct "
                f"CAs: {', '.join(sorted(unique_issuers)[:6])}"
                + (" ..." if len(unique_issuers) > 6 else "."),
                "Legitimate single-organisation infra typically uses 1-3 CAs; phishing kits rotate "
                "through many CAs to maintain continuous HTTPS coverage.",
            ],
            source=SOURCE,
        ))
    elif len(unique_issuers) >= 8:
        findings.append(Finding(category=FindingCategory.TLS,
            id="CT-MULTIPLE-ISSUERS",
            title="Certificates issued by many different CAs (informational)",
            severity=Severity.INFO,
            evidence=[
                f"Certificates for '{registrable_domain}' were issued by {len(unique_issuers)} distinct "
                f"CAs across {total} record(s) (~{certs_per_ca:.1f} certificates per CA).",
                "Broad CA diversity on a large CT footprint is typical of long-lived, "
                "multi-issuer infrastructure; informational only.",
            ],
            source=SOURCE,
        ))

    # Signal 5: multiple very recent certificates in a short window (minutes),
    # indicating automated cert generation.
    recent = [r for r in result.records if r.entry_timestamp and (now - r.entry_timestamp).total_seconds() < 300]
    if len(recent) >= 3:
        findings.append(Finding(category=FindingCategory.TLS, 
            id="CT-BURST-ISSUANCE",
            title="Certificate issuance burst detected in the last 5 minutes",
            severity=Severity.MEDIUM,
            evidence=[
                f"{len(recent)} certificate(s) for '{registrable_domain}' were issued "
                "within the last 5 minutes.",
                "Automated generation of certificates for many subdomains is typical of phishing-kit "
                "deployment automation.",
            ],
            source=SOURCE,
        ))

    # Signal 6: current cert fingerprint not seen — the fetched cert is new to CT.
    # Only comparable when the API actually returned fingerprints (the 2025
    # crt.sh rewrite removed them); otherwise skipping avoids a false positive
    # on every scan.
    if (cert_sha256 and result.records and any(r.sha256 for r in result.records)
            and cert_sha256.lower() not in {r.sha256.lower() for r in result.records}):
        findings.append(Finding(category=FindingCategory.TLS, 
            id="CT-CERT-NOT-IN-LOGS",
            title="Presented certificate not found in public CT logs",
            severity=Severity.LOW,
            evidence=[
                f"SHA-256 {cert_sha256[:16]}... was inserted into {total} CT record(s) for the domain, "
                "but the certificate presented during this analysis was not among them.",
                "Possibilities: the cert is freshly issued and not yet indexed (seconds-to-minutes lag), "
                "the CT index query missed it, or a man-in-the-middle served a different cert than the "
                "one later logged. Fresh certs typically appear within a few minutes of issuance.",
            ],
            source=SOURCE,
        ))

    return findings[:max_records], stats
