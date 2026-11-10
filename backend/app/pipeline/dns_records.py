"""Passive DNS record checks (A / MX / NS / TXT) via dnspython.

These lookups enrich the report with infrastructure context:
  * A      — how many addresses the apex resolves to (hops already carry them)
  * MX     — whether the domain sends/receives mail (phishing domains often don't)
  * NS     — which nameservers serve the zone
  * TXT    — record count + SPF presence ONLY. Raw TXT bodies are never stored
             or reported: they can carry site-verification tokens and other
             sensitive strings.

Resolution strategy (Step 3, restricted networks):
  Queries first go to the system resolver (UDP/TCP port 53, dnspython). If
  that times out or fails, each query falls back to RFC 8484 DNS-over-HTTPS
  (standard port 443) against public resolvers (Cloudflare, then Google, then
  Quad9) via dnspython's DoH transport. NXDOMAIN is a definitive answer and
  is NOT retried over DoH.

  This fallback applies ONLY to the passive record checks. The SSRF-safe
  fetcher's pinning resolver (ssrf.SystemDnsResolver) deliberately keeps
  using the system resolver — changing the fetch path's resolver is a
  security-sensitive change outside this stage's scope.

Hard rules:
  * Read-only queries. DNS records are never used to bypass SSRF validation or
    to initiate connections to the target — the safe fetcher's policy applies
    independently.
  * Every query outcome is recorded (source, evidence, success/failure) and
    fed into coverage as the optional `dns-records` stage.
  * This is an OPTIONAL check per the scoring policy: a DNS lookup failure is
    a coverage limitation, never a verdict change.
  * DNS records can be absent or change at any time; their presence/absence is
    context, not proof of legitimacy or malice.

The query function is injectable so tests stay deterministic and offline.
"""
from __future__ import annotations

import asyncio
import copy
import logging
import time

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.message
import dns.rcode
import dns.resolver

from ..models.enums import FindingCategory, Severity
from ..models.schemas import Finding

logger = logging.getLogger("trustlens.dns-records")

SOURCE = "trustlens/dns-records"
_LOOKUP_TIMEOUT = 3.0
_MAX_NAMES_IN_EVIDENCE = 3

_RECORD_TYPES = ("A", "MX", "NS", "TXT")

_DNS_CACHE: dict[str, tuple[list[Finding], dict, float]] = {}
_DNS_CACHE_TTL = 300.0  # 5 minutes

# RFC 8484 DoH endpoints (standard HTTPS port 443), tried in order: three
# independent operators so a single-provider outage or block never disables
# the fallback.
DOH_ENDPOINTS: tuple[str, ...] = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
)
# Per-endpoint budget: a stalled DoH provider must not consume the whole
# query budget — each attempt is capped independently.
_DOH_PER_ENDPOINT_TIMEOUT = 2.0


async def _standard_query(domain: str, rtype: str, timeout: float) -> list[str]:
    """System-resolver lookup (UDP/TCP port 53 via dnspython's default resolver)."""
    answers = await dns.asyncresolver.resolve(domain, rtype, lifetime=timeout)
    return [r.to_text().rstrip(".") for r in answers]


async def _doh_query(domain: str, rtype: str, timeout: float, endpoint: str) -> list[str]:
    """One RFC 8484 DNS-over-HTTPS query (standard port 443)."""
    query_msg = dns.message.make_query(domain, rtype)
    try:
        response = await dns.asyncquery.https(query_msg, endpoint, timeout=timeout)
    except (dns.resolver.LifetimeTimeout, getattr(dns.query, "NoDOH", Exception), dns.exception.Timeout, OSError) as exc:
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                endpoint,
                content=query_msg.to_wire(),
                headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
                timeout=timeout,
            )
            if resp.status_code != 200:
                raise dns.exception.DNSException(f"DoH HTTP {resp.status_code} from {endpoint}") from exc
            response = dns.message.from_wire(resp.content)
    rcode = response.rcode()
    if rcode == dns.rcode.NXDOMAIN:
        raise dns.resolver.NXDOMAIN(f"DoH: {domain} does not exist")
    if rcode != dns.rcode.NOERROR:
        raise dns.exception.DNSException(f"DoH answer rcode {dns.rcode.to_text(rcode)} for {domain} {rtype}")
    values: list[str] = []
    for rrset in response.answer:
        for rdata in rrset:
            values.append(rdata.to_text().rstrip("."))
    return values


async def _query_with_fallback(domain: str, rtype: str, timeout: float, use_doh: bool = True, skip_standard: bool = False) -> list[str]:
    """System resolver first; on failure, sequential DoH failover over 443
    with a short per-endpoint budget (unless disabled).

    NXDOMAIN propagates immediately — it is a definitive answer, not a
    transport failure, so the DoH fallback is skipped for it.
    """
    if not skip_standard:
        try:
            return await _standard_query(domain, rtype, timeout)
        except dns.resolver.NXDOMAIN:
            raise
        except (dns.exception.DNSException, OSError, TimeoutError, ValueError) as std_exc:
            if not use_doh:
                raise
            last_exc: Exception = std_exc
    else:
        if not use_doh:
            raise dns.exception.Timeout("system resolver skipped and DoH disabled")
        last_exc = dns.exception.Timeout("system resolver skipped")

    for endpoint in DOH_ENDPOINTS:
        try:
            logger.info("dns-records: port-53 lookup for %s %s failed/skipped; trying DoH %s",
                        domain, rtype, endpoint)
            return await _doh_query(domain, rtype, min(timeout, _DOH_PER_ENDPOINT_TIMEOUT),
                                    endpoint)
        except (dns.exception.DNSException, OSError, TimeoutError, ValueError) as exc:
            last_exc = exc
    raise last_exc


async def check_dns_records(
    registrable_domain: str,
    timeout: float = _LOOKUP_TIMEOUT,
    query=None,
    use_doh: bool = True,
) -> tuple[list[Finding], dict]:
    """Look up A/MX/NS/TXT for `registrable_domain`.

    Returns (findings, stats). `stats` carries per-type counts, an `spf` flag,
    and `failed_types` for coverage reporting. `query` may be injected as an
    ``async (domain, rtype[, timeout]) -> list[str]`` callable for tests; by
    default the system resolver is used with an RFC 8484 DoH fallback
    (controlled by `use_doh`).
    """
    findings: list[Finding] = []
    stats: dict = {"domain": registrable_domain, "A": 0, "MX": 0, "NS": 0, "TXT": 0,
                   "spf": False, "failed_types": [], "error": None}
    if not registrable_domain:
        return findings, stats

    cache_key = registrable_domain.lower().rstrip(".")
    if query is None and cache_key in _DNS_CACHE:
        cached_findings, cached_stats, ts = _DNS_CACHE[cache_key]
        if time.time() - ts < _DNS_CACHE_TTL:
            return copy.deepcopy(cached_findings), copy.deepcopy(cached_stats)
        del _DNS_CACHE[cache_key]

    if query is None:
        query = _query_with_fallback

    system_failed = False

    async def _default_call(rtype: str) -> list[str]:
        nonlocal system_failed
        try:
            return await _query_with_fallback(registrable_domain, rtype, timeout, use_doh=use_doh, skip_standard=system_failed)
        except Exception:
            system_failed = True
            raise

    results: dict[str, dict] = {}

    async def run(rtype: str) -> None:
        try:
            if query is _query_with_fallback:
                values = await _default_call(rtype)
            else:
                values = await query(registrable_domain, rtype, timeout) if _arity(query) == 3 \
                    else await query(registrable_domain, rtype)
            results[rtype] = {"ok": True, "values": [str(v) for v in values], "error": None}
        except dns.resolver.NXDOMAIN:
            results[rtype] = {"ok": False, "values": [], "error": "NXDOMAIN"}
        except (dns.exception.DNSException, OSError, TimeoutError, ValueError) as exc:
            # DNSException covers NoAnswer/NoNameservers/LifetimeTimeout/etc.;
            # ValueError covers malformed answers.
            results[rtype] = {"ok": False, "values": [], "error": type(exc).__name__}
        except Exception as exc:  # defensive: a DNS check must never break analysis
            logger.warning("dns %s lookup for %s failed unexpectedly: %s",
                           rtype, registrable_domain, type(exc).__name__)
            results[rtype] = {"ok": False, "values": [], "error": type(exc).__name__}

    # NXDOMAIN short-circuits: if the apex does not exist, the other queries
    # would each fail the same way — query A first, then decide.
    await run("A")
    if results["A"]["error"] == "NXDOMAIN":
        findings.append(Finding(
            id="DNS-NXDOMAIN",
            title="Domain does not exist in DNS (NXDOMAIN)",
            severity=Severity.INFO,
            category=FindingCategory.DNS,
            evidence=[
                f"'{registrable_domain}' does not resolve (NXDOMAIN).",
                "The remaining record lookups (MX/NS/TXT) were skipped. The safe-fetch "
                "stage records the same condition as FETCH-DNS-FAIL.",
            ],
            source=SOURCE,
            check_succeeded=False,
        ))
        stats["error"] = "NXDOMAIN"
        stats["failed_types"] = ["A", "MX", "NS", "TXT"]
        return findings, stats

    await asyncio.gather(run("MX"), run("NS"), run("TXT"))

    # One informational finding summarising the successful lookups (capped,
    # sanitised evidence); per-type failure findings for the failed ones.
    ok_lines: list[str] = []
    for rtype in _RECORD_TYPES:
        res = results[rtype]
        if res["ok"]:
            stats[rtype] = len(res["values"])
            if rtype == "A":
                shown = ", ".join(res["values"][:_MAX_NAMES_IN_EVIDENCE])
                ok_lines.append(f"A: {len(res['values'])} address(es) resolved"
                                + (f" ({shown})" if shown else ""))
            elif rtype == "MX":
                shown = ", ".join(res["values"][:_MAX_NAMES_IN_EVIDENCE])
                ok_lines.append(f"MX: {len(res['values'])} mail exchanger(s)"
                                + (f" ({shown})" if shown else "")
                                + ("; no MX records — the domain does not accept mail"
                                   if not res["values"] else ""))
            elif rtype == "NS":
                shown = ", ".join(res["values"][:_MAX_NAMES_IN_EVIDENCE])
                ok_lines.append(f"NS: {len(res['values'])} nameserver(s)"
                                + (f" ({shown})" if shown else ""))
            elif rtype == "TXT":
                # TXT bodies can carry site-verification tokens and other
                # sensitive strings — only the count and SPF presence are kept.
                stats["spf"] = any(v.lower().startswith("v=spf1") for v in res["values"])
                ok_lines.append(
                    f"TXT: {len(res['values'])} record(s) (contents not stored); "
                    f"SPF record present: {'yes' if stats['spf'] else 'no'}"
                )
        else:
            stats["failed_types"].append(rtype)
            findings.append(Finding(
                id=f"DNS-{rtype}-UNAVAILABLE",
                title=f"{rtype} record lookup unavailable",
                severity=Severity.INFO,
                category=FindingCategory.DNS,
                evidence=[f"{rtype} lookup for '{registrable_domain}' failed: {res['error']}.",
                          "A DNS lookup failure is a coverage limitation, not a signal "
                          "about the target."],
                source=SOURCE,
                check_succeeded=False,
            ))

    if ok_lines:
        findings.insert(0, Finding(
            id="DNS-RECORDS",
            title="Passive DNS record summary",
            severity=Severity.INFO,
            category=FindingCategory.DNS,
            evidence=ok_lines + [
                "DNS records can be absent or change at any time; they are context "
                "only and are not proof of legitimacy.",
            ],
            source=SOURCE,
        ))

    # Every lookup failed (system resolver AND all DoH endpoints): one honest
    # summary finding. This is an optional check — the pipeline continues.
    if len(stats["failed_types"]) == len(_RECORD_TYPES):
        stats["error"] = "all record lookups failed (port 53 and every DoH endpoint)"
        findings.append(Finding(
            id="DNS-LOOKUP-FAILED",
            title="All passive DNS record lookups failed",
            severity=Severity.INFO,
            category=FindingCategory.DNS,
            evidence=[
                f"DNS resolution for '{registrable_domain}' failed on the system resolver "
                "and every DoH fallback endpoint.",
                "This is a coverage limitation of the TrustLens environment, NOT a signal "
                "about the target. The analysis pipeline continues; the safe-fetch stage "
                "reports its own DNS state independently.",
            ],
            source=SOURCE,
            check_succeeded=False,
        ))
    if query is None and not stats.get("error"):
        _DNS_CACHE[cache_key] = (copy.deepcopy(findings), copy.deepcopy(stats), time.time())
    return findings, stats


def _arity(fn) -> int:
    """Support injected query callables with or without the timeout parameter."""
    try:
        import inspect
        return len(inspect.signature(fn).parameters)
    except (TypeError, ValueError):  # builtins/C functions
        return 2
