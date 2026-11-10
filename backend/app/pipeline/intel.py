"""Threat-intelligence interface with provider-agnostic adapters and graceful degradation.

Provides a uniform check() contract across:
  * Google Safe Browsing API (GSB) — broad URL/domain lookups, requires API key
  * URLhaus — recent malware URL collection, requires API key (v1: key in header)
  * OpenPhish — commercial phishing feed, free tier requires key
  * PhishTank — community-sourced phishing database, requires key + CORS proxy
  * VirusTotal — comprehensive URL/domain/file checks, requires API key

Missing/invalid keys → that source is marked UNAVAILABLE (never fatal). Rate limits
→ that source is UNAVAILABLE for the window. 4xx on the source's side (e.g. NOTFOUND
vs 404) is mapped to "no hit", never an error.

All external responses are cached keyed by (source, normalized indicator). Cache is
in-process only (Redis-backed caching is Phase 6).
"""
from __future__ import annotations

import asyncio
import base64
import logging
import time
import urllib.parse
from typing import Optional

import httpx

from ..config import Settings
from ..models.enums import FindingCategory, Severity
from ..models.schemas import Finding

logger = logging.getLogger("trustlens.intel")

SOURCE_PREFIX = "trustlens/intel/"


def _retry_after_seconds(response, default: float) -> float:
    """Parse a provider's Retry-After header (seconds or HTTP-date); the value
    is bounded to a sane window so a hostile header cannot disable a provider
    for days."""
    raw = ""
    try:
        raw = response.headers.get("retry-after") or ""
    except Exception:
        raw = ""
    if not raw:
        return default
    try:
        return min(max(float(raw), 0.0), 3600.0)
    except ValueError:
        return default

# ---- per-provider config: provider name -> Settings field carrying its key ----
_PROVIDER_KEY_FIELDS: dict[str, str] = {
    "google_safe_browsing": "google_safe_browsing_api_key",
    "urlhaus": "urlhaus_api_key",
    "openphish": "openphish_api_key",
    "phishtank": "phishtank_api_key",
    "virustotal": "virustotal_api_key",
}


class IntelUnavailable(Exception):
    """The source requires a key we don't have, or is rate-limited/down.

    `retry_after` carries the provider-advised (or default) backoff window in
    seconds; the registry converts it into a silent no-HTTP window so repeated
    calls cannot stall worker threads against a 429-ing provider.
    """

    def __init__(self, message: str, retry_after: float = 60.0):
        super().__init__(message)
        self.retry_after = float(retry_after)


class _FindingCache:
    """Small in-process TTL cache for provider responses.

    Entries are (findings, timestamp). The class-level caches this replaces
    were plain dicts: unbounded growth, no expiry, and a "no hit" answer stuck
    for the process lifetime. Failures are never stored, so transient provider
    outages retry on the next analysis.
    """

    def __init__(self, ttl_seconds: float = 300.0, max_entries: int = 512):
        self._ttl = ttl_seconds
        self._max = max_entries
        self._entries: dict = {}

    def get(self, key):
        hit = self._entries.get(key)
        if hit is None:
            return None
        findings, ts = hit
        if time.time() - ts >= self._ttl:
            self._entries.pop(key, None)
            return None
        return findings

    def put(self, key, findings) -> None:
        if len(self._entries) >= self._max:
            oldest = sorted(self._entries, key=lambda k: self._entries[k][1])[: self._max // 4]
            for k in oldest:
                self._entries.pop(k, None)
        self._entries[key] = (findings, time.time())


class IntelSource:
    """Base adapter. Subclasses implement check_url(...) and check_domain(...).

    Contract: BOTH methods are SYNC callables — IntelRegistry runs them in
    worker threads via asyncio.to_thread (the adapters do blocking httpx I/O).
    A source that does not support a check simply inherits the raising default;
    the registry translates IntelUnavailable("not supported …") into a skip.

    Every adapter receives the (optional) Settings object so behaviour flags
    (e.g. VirusTotal fallback policy) are configurable without globals.
    """

    name = "intel-base"
    check_url_supported = True
    check_domain_supported = True
    requires_key = True

    def __init__(self, key: str, settings: Optional[Settings] = None):
        self.key = key
        self.settings = settings

    def check_url(self, url: str) -> list[Finding]:
        raise IntelUnavailable("not supported by this provider")

    def check_domain(self, domain: str) -> list[Finding]:
        raise IntelUnavailable("not supported by this provider")


class GoogleSafeBrowsing(IntelSource):
    """Google Safe Browsing API v4.

    Checks a URL against the threat lists. Free tier: 1000 units/day; we map
    one check to one unit. 429/5xx → rate-limited/down.
    """

    name = "google_safe_browsing"
    requires_key = True
    # GSB v4 threatMatches has no domain-report variant; only URL lookups.
    check_domain_supported = False

    # Valid v4 threatTypes. Values like THREAT_TYPE_UNSPECIFIED / API_ABUSE /
    # MOBILE_APP are rejected by the API with 400 INVALID_ARGUMENT, which made
    # every GSB check fail.
    THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION")
    HIGH_SEVERITY_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION")

    def __init__(self, key: str, settings: Optional[Settings] = None):
        super().__init__(key, settings)
        self.base = "https://safebrowsing.googleapis.com"
        self.client = httpx.Client(headers={"User-Agent": "Mozilla/5.0 TrustLens"})
        self._cache = _FindingCache()

    def _build_body(self, url: str, check_types=THREAT_TYPES, platforms=("ANY_PLATFORM",)):
        # Documented threatMatches:find shape: client + threatInfo wrapper.
        # (A flat {"requests": [...]} body is rejected with 400
        # "Unknown name ...: Cannot find field".)
        return {
            "client": {"clientId": "trustlens", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": list(check_types),
                "platformTypes": list(platforms),
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

    def check(self, url: str) -> list[Finding]:
        cache_key = ("gsb:url", url)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        body = self._build_body(url)
        try:
            # Auth: Google's documented `key` query parameter. Header-based
            # identity (x-api-key / x-goog-apikey) is refused by this endpoint
            # with 403 "Method doesn't allow unregistered callers" (observed
            # live), so the parameter is the only working transport. The key
            # never appears in any log or report — evidence carries only the
            # URL and parsed threat types.
            resp = self.client.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                                    params={"key": self.key}, json=body, timeout=10)
        except (httpx.HTTPError, OSError) as exc:
            return [Finding(category=FindingCategory.INTEL, id="GSB-ERROR", title="Google Safe Browsing check failed",
                            severity=Severity.INFO, evidence=[f"{type(exc).__name__}: {str(exc)[:250]}"],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]

        if resp.status_code == 429:
            raise IntelUnavailable("Google Safe Browsing rate-limited")
        if resp.status_code == 403:
            return [Finding(category=FindingCategory.INTEL, id="GSB-KEY-ERROR", title="Google Safe Browsing key rejected",
                            severity=Severity.MEDIUM,
                            evidence=["The Google Safe Browsing API key is invalid or insufficient."],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]
        if resp.status_code != 200:
            return [Finding(category=FindingCategory.INTEL, id="GSB-ERROR", title="Google Safe Browsing check failed",
                            severity=Severity.INFO, evidence=[f"HTTP {resp.status_code}: {resp.text[:500]}"],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]

        try:
            body_out = resp.json()
        except ValueError:
            return [Finding(category=FindingCategory.INTEL, id="GSB-ERROR", title="Google Safe Browsing check failed",
                            severity=Severity.INFO, evidence=["malformed JSON response"],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]
        if not isinstance(body_out, dict) or not body_out.get("matches"):
            self._cache.put(cache_key, [])
            return []

        # Parse the actual threatType values; evidence strings keep the
        # "THREAT_TYPE=…" format the scoring engine matches on.
        threat_types = [m.get("threatType", "UNKNOWN") for m in body_out["matches"]]
        threats = [f"THREAT_TYPE={tt}" for tt in threat_types]
        # Membership must be tested against the parsed types — `"MALWARE" in
        # threats` compares against whole list items like "THREAT_TYPE=MALWARE"
        # and is always False.
        if any(tt in self.HIGH_SEVERITY_TYPES for tt in threat_types):
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM

        findings = [Finding(category=FindingCategory.INTEL, id="GSB-MATCH", title="Google Safe Browsing flagged URL",
                            severity=sev, evidence=threats + [url], source=SOURCE_PREFIX + self.name,
                            check_succeeded=True)]
        self._cache.put(cache_key, findings)
        return findings

    # Registry contract: sync check_url, run in a worker thread like every
    # other adapter. `check` predates the registry wiring and stays the
    # unit-test entry point.
    def check_url(self, url: str) -> list[Finding]:
        return self.check(url)


class Urlhaus(IntelSource):
    """URLhaus API v1 — known malicious URL collection (malware distribution).

    The v1 endpoints answer with a JSON *object* ({"query_status": "ok",
    "url_details": {...}} / {"query_status": "no_results"}), not a list, and
    expect a form-encoded body (an optional auth key goes in the Auth-Key
    header). Domain checks use the /v1/host/ endpoint.
    """

    name = "urlhaus"

    def __init__(self, key: str, settings: Optional[Settings] = None):
        super().__init__(key, settings)
        self.client = httpx.Client(headers={"User-Agent": "Mozilla/5.0 TrustLens"})
        self._cache = _FindingCache()

    def _make_request(self, endpoint: str, payload: dict, label: str) -> list[Finding]:
        cache_key = ("urlhaus", endpoint, label)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        headers = {"Auth-Key": self.key} if self.key else {}
        try:
            r = self.client.post(endpoint, headers=headers, data=payload, timeout=10)
        except (httpx.HTTPError, OSError) as exc:
            return [Finding(category=FindingCategory.INTEL, id="URLHAUS-ERROR", title="URLhaus check failed", severity=Severity.INFO,
                            evidence=[f"{type(exc).__name__}: {str(exc)[:250]}"],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]
        if r.status_code == 429:
            raise IntelUnavailable("URLhaus rate-limited")
        if r.status_code == 403:
            return [Finding(category=FindingCategory.INTEL, id="URLHAUS-KEY-ERROR", title="URLhaus key rejected", severity=Severity.MEDIUM,
                            evidence=["URLhaus API key invalid or insufficient."],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]
        if r.status_code != 200:
            return [Finding(category=FindingCategory.INTEL, id="URLHAUS-ERROR", title="URLhaus check failed", severity=Severity.INFO,
                            evidence=[f"HTTP {r.status_code}"],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]

        try:
            body = r.json()
        except ValueError:
            return [Finding(category=FindingCategory.INTEL, id="URLHAUS-ERROR", title="URLhaus check failed", severity=Severity.INFO,
                            evidence=["unparsable JSON response"],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]
        if not isinstance(body, dict) or body.get("query_status") != "ok":
            self._cache.put(cache_key, [])
            return []

        # url_details (url endpoint) or host_details (host endpoint); abuse.ch
        # returns a single object for exact matches and a list for host
        # listings — normalise both to a list.
        details = body.get("url_details") or body.get("host_details") or []
        if isinstance(details, dict):
            details = [details]

        findings: list[Finding] = []
        for row in details[:10]:
            if isinstance(row, dict):
                evidence = [
                    f"url_id={row.get('url_id')}",
                    f"url_status={row.get('url_status', 'unknown')}",
                    f"threat={row.get('threat', row.get('malware_name', 'unknown'))}",
                    f"date_added={row.get('date_added', row.get('first_seen'))}",
                ] + [f"target={label}"]
                findings.append(Finding(category=FindingCategory.INTEL,
                    id="URLHAUS-MATCH", title="Found in URLhaus (malware distribution)", severity=Severity.HIGH,
                    evidence=[e for e in evidence if not e.endswith("=None")],
                    source=SOURCE_PREFIX + self.name, check_succeeded=True,
                ))
        self._cache.put(cache_key, findings)
        return findings

    def check_url(self, url: str) -> list[Finding]:
        return self._make_request("https://urlhaus-api.abuse.ch/v1/url/", {"url": url}, url)

    def check_domain(self, domain: str) -> list[Finding]:
        return self._make_request("https://urlhaus-api.abuse.ch/v1/host/", {"host": domain}, domain)


class OpenPhish(IntelSource):
    """OpenPhish community feed adapter (official access point:
    https://feed.openphish.com/v3/feed.txt — a plain-text list of phishing URLs).

    The community feed requires no API key and no key-in-URL authentication.
    TrustLens still requires TRUSTLENS_OPENPHISH_API_KEY to be set (any
    non-empty value, e.g. "community") so that network use stays an explicit
    opt-in and unit tests remain hermetic; the value itself is never sent
    anywhere. Commercial OpenPhish feeds with per-customer endpoints are out
    of scope for this MVP.

    The feed is fetched at most once per TTL and indexed by exact URL and
    hostname. Feed-fetch failures are reported as failed checks and are never
    cached as clean results.
    """

    name = "openphish"
    requires_key = True
    FEED_URL = "https://feed.openphish.com/v3/feed.txt"
    FEED_TTL_SECONDS = 300
    FEED_ERROR_RETRY_SECONDS = 60

    def __init__(self, key: str, settings: Optional[Settings] = None):
        super().__init__(key, settings)
        self.client = httpx.Client(headers={"User-Agent": "Mozilla/5.0 TrustLens"})

    # Class-level feed state shared by all instances of the current process.
    _feed_urls: Optional[set] = None
    _feed_hosts: Optional[dict] = None
    _feed_ts: float = 0.0
    _feed_error: Optional[str] = None
    _feed_error_ts: float = 0.0

    def _load_feed(self) -> bool:
        """Ensure the feed index is loaded. Returns True on success; False
        records/returns a failure (never cached as a clean result)."""
        cls = type(self)
        now = time.time()
        if cls._feed_urls is not None and now - cls._feed_ts < cls.FEED_TTL_SECONDS:
            return True
        if cls._feed_error is not None and now - cls._feed_error_ts < cls.FEED_ERROR_RETRY_SECONDS:
            return False
        try:
            r = self.client.get(cls.FEED_URL, timeout=15)
        except (httpx.HTTPError, OSError) as exc:
            cls._feed_error = f"{type(exc).__name__}: {str(exc)[:200]}"
            cls._feed_error_ts = now
            return False
        if r.status_code != 200 or not r.text.strip():
            cls._feed_error = f"HTTP {r.status_code}" + ("" if r.text.strip() else " (empty response)")
            cls._feed_error_ts = now
            return False
        urls: set[str] = set()
        hosts: dict[str, list[str]] = {}
        for line in r.text.splitlines():
            entry = line.split("|")[0].strip().rstrip("/")
            if not entry:
                continue
            urls.add(entry.lower())
            host = urllib.parse.urlparse(entry).hostname
            if host:
                hosts.setdefault(host.lower(), []).append(entry)
        cls._feed_urls = urls
        cls._feed_hosts = hosts
        cls._feed_ts = now
        cls._feed_error = None
        return True

    def _feed_error_finding(self) -> Finding:
        return Finding(category=FindingCategory.INTEL, id="OPENPHISH-ERROR",
                       title="OpenPhish check failed", severity=Severity.INFO,
                       evidence=[f"feed fetch failed: {type(self)._feed_error}"],
                       source=SOURCE_PREFIX + self.name, check_succeeded=False)

    def check_url(self, url: str) -> list[Finding]:
        if not self._load_feed():
            return [self._feed_error_finding()]
        target = url.strip().rstrip("/").lower()
        if target in (type(self)._feed_urls or set()):
            return [Finding(category=FindingCategory.INTEL,
                id="OPENPHISH-MATCH", title="URL found in the OpenPhish community feed",
                severity=Severity.HIGH,
                evidence=[f"phish_url={url}", "source=OpenPhish community feed v3"],
                source=SOURCE_PREFIX + self.name, check_succeeded=True)]
        return []

    def check_domain(self, domain: str) -> list[Finding]:
        if not self._load_feed():
            return [self._feed_error_finding()]
        matches = (type(self)._feed_hosts or {}).get(domain.lower(), [])[:5]
        if matches:
            return [Finding(category=FindingCategory.INTEL,
                id="OPENPHISH-MATCH", title="URLs in this domain found in the OpenPhish community feed",
                severity=Severity.HIGH,
                evidence=[f"phish_url={m}" for m in matches] + ["source=OpenPhish community feed v3"],
                source=SOURCE_PREFIX + self.name, check_succeeded=True)]
        return []


class PhishTank(IntelSource):
    """PhishTank API v2 — community-sourced phishing database.

    The documented endpoint is POST /api/v2/checkurl/ with url, format=json and
    an app_key. Results come back as {"results": {"url0": {...}}} — a dict, not
    a list — and only when the URL is in the database. PhishTank offers no
    domain-level lookup, so check_domain is unsupported.
    """

    name = "phishtank"
    requires_key = True
    check_domain_supported = False
    _cache: _FindingCache = _FindingCache()

    def __init__(self, key: str, settings: Optional[Settings] = None):
        super().__init__(key, settings)
        self.client = httpx.Client(headers={"User-Agent": "Mozilla/5.0 TrustLens"})

    def check_url(self, url: str) -> list[Finding]:
        cache_key = ("phishtank:url", url)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        data_payload = {"url": url, "format": "json"}
        if self.key:
            data_payload["app_key"] = self.key
        try:
            r = self.client.post(
                "https://checkurl.phishtank.com/api/v2/checkurl/",
                data=data_payload,
                timeout=10,
            )
        except (httpx.HTTPError, OSError) as exc:
            return [Finding(category=FindingCategory.INTEL, id="PHISHTANK-ERROR", title="PhishTank check failed", severity=Severity.INFO,
                            evidence=[f"{type(exc).__name__}: {str(exc)[:250]}"],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]
        if r.status_code == 403:
            return [Finding(category=FindingCategory.INTEL, id="PHISHTANK-KEY-ERROR", title="PhishTank key rejected", severity=Severity.MEDIUM,
                            evidence=["PhishTank app key invalid or insufficient."],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]
        if r.status_code != 200:
            return [Finding(category=FindingCategory.INTEL, id="PHISHTANK-ERROR", title="PhishTank check failed", severity=Severity.INFO,
                            evidence=[f"HTTP {r.status_code}"],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]
        try:
            data = r.json()
        except ValueError:
            return [Finding(category=FindingCategory.INTEL, id="PHISHTANK-ERROR", title="PhishTank check failed", severity=Severity.INFO,
                            evidence=["unparsable JSON response"],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]
        if data.get("errormessage"):
            return [Finding(category=FindingCategory.INTEL, id="PHISHTANK-ERROR", title="PhishTank check failed", severity=Severity.INFO,
                            evidence=[str(data["errormessage"])[:200]],
                            source=SOURCE_PREFIX + self.name, check_succeeded=False)]

        # results is {"url0": {...}} (dict) in v2; accept a list defensively.
        results = data.get("results") or {}
        items = list(results.values()) if isinstance(results, dict) else results
        findings = []
        for item in (items or [])[:5]:
            if not isinstance(item, dict):
                continue
            verified = str(item.get("verified", "")).strip().lower() == "yes"
            valid = str(item.get("valid", "")).strip().lower() == "yes"
            if verified and valid:
                findings.append(Finding(category=FindingCategory.INTEL,
                    id="PHISHTANK-MATCH", title="Verified phishing entry in PhishTank", severity=Severity.HIGH,
                    evidence=[
                        f"phish_id={item.get('phish_id')}",
                        f"verified={item.get('verified')}",
                        f"valid={item.get('valid')}",
                        f"verification_time={item.get('verified_time')}",
                        f"phish_detail_page={item.get('phish_detail_page')}",
                    ],
                    source=SOURCE_PREFIX + self.name, check_succeeded=True,
                ))
            else:
                # In the database but not (yet) verified/valid: data worth
                # surfacing, never an authoritative match.
                findings.append(Finding(category=FindingCategory.INTEL,
                    id="PHISHTANK-UNVERIFIED",
                    title="Present in PhishTank's database but not a verified entry",
                    severity=Severity.INFO,
                    evidence=[
                        f"phish_id={item.get('phish_id')}",
                        f"verified={item.get('verified', 'no')}",
                        f"valid={item.get('valid', 'no')}",
                        "Only verified+valid PhishTank records count as authoritative; "
                        "unverified database entries are informational context.",
                    ],
                    source=SOURCE_PREFIX + self.name, check_succeeded=True,
                ))
        self._cache.put(cache_key, findings)
        return findings


class VirusTotal(IntelSource):
    """VirusTotal API v3 (current, documented).

    Uses GET /api/v3/urls/{id} and GET /api/v3/domains/{name} with
    ``x-apikey`` header authentication — the key is never placed in a URL.

    Miss policy (config.py: ``vt_domain_fallback`` / ``vt_submit_on_miss``):
      1. GET /api/v3/urls/{id}.
      2. On 404 (URL never analysed): if ``vt_submit_on_miss`` is enabled
         (opt-in, ACTIVE), POST the URL to /api/v3/urls and re-check; else/by
         default (100% passive) fall back to GET /api/v3/domains/{host} and
         evaluate that domain's last_analysis_stats.
      3. Only an exact-URL match — or a domain fallback with a strong
         malicious majority (>= 8 malicious engines) — is treated as
         authoritative; a domain-level match with fewer malicious engines
         stays a non-authoritative signal (the evidence key
         ``domain_positives=`` is deliberately invisible to the scoring
         engine's ``positives=`` authority rule).

    Limitations (documented): 404 means "never analysed", NOT clean — surfaced
    as VT-NODATA (info) when neither the URL nor its domain has data.
    """

    name = "virustotal"
    requires_key = True
    _cache: _FindingCache = _FindingCache()

    # Matches scoring.ScoringEngine.VT_MALICIOUS_THRESHOLD: this many adverse
    # engine verdicts are treated as authoritative by the scoring engine.
    AUTHORITATIVE_POSITIVES = 6
    # Domain-fallback matches become authoritative only at a strong malicious
    # majority (domain reputation is about the host, not the exact URL).
    DOMAIN_AUTHORITATIVE_MALICIOUS = 8
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, key: str, settings: Optional[Settings] = None):
        super().__init__(key, settings)
        self._domain_fallback = bool(settings.vt_domain_fallback) if settings else True
        self._submit_on_miss = bool(settings.vt_submit_on_miss) if settings else False
        self.client = httpx.Client(headers={
            "x-apikey": key,
            "User-Agent": "Mozilla/5.0 TrustLens",
            "Accept": "application/json",
        })

    @staticmethod
    def _url_id(url: str) -> str:
        """VT v3 URL object id: urlsafe-base64 of the URL, padding stripped."""
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    def _error_finding(self, detail: str) -> Finding:
        return Finding(category=FindingCategory.INTEL, id="VT-ERROR",
                       title="VirusTotal check failed", severity=Severity.INFO,
                       evidence=[detail], source=SOURCE_PREFIX + self.name,
                       check_succeeded=False)

    def _nodata_finding(self, url_id: str, host: str) -> Finding:
        scope = f"this URL or its domain ('{host}')" if host else "this URL"
        return Finding(category=FindingCategory.INTEL, id="VT-NODATA",
                       title="No existing verdict in VirusTotal's dataset",
                       severity=Severity.INFO,
                       evidence=[f"VirusTotal has no analysis data for {scope} (HTTP 404): "
                                 "never analysed, not clean. TrustLens never submits URLs "
                                 "for scanning unless TRUSTLENS_VT_SUBMIT_ON_MISS=true.",
                                 f"url_id={url_id}"],
                       source=SOURCE_PREFIX + self.name, check_succeeded=True)

    def _fetch_json(self, path: str) -> tuple[dict | None, Optional[Finding]]:
        """GET a v3 endpoint; returns (json, error_finding). A 404 becomes a
        VT-NODATA marker (check_succeeded=True — the provider ANSWERED 'no
        data'); every other failure is a failed check. 429 raises
        IntelUnavailable carrying the provider's Retry-After window."""
        try:
            r = self.client.get(self.BASE + path, timeout=10)
        except (httpx.HTTPError, OSError) as exc:
            return None, self._error_finding(f"{type(exc).__name__}: {str(exc)[:250]}")
        if r.status_code == 429:
            raise IntelUnavailable("VirusTotal rate-limited",
                                   retry_after=_retry_after_seconds(r, default=60.0))
        if r.status_code in (401, 403):
            return None, Finding(category=FindingCategory.INTEL, id="VT-KEY-ERROR",
                                 title="VirusTotal key rejected", severity=Severity.MEDIUM,
                                 evidence=["VirusTotal API key invalid or insufficient."],
                                 source=SOURCE_PREFIX + self.name, check_succeeded=False)
        if r.status_code == 404:
            return None, self._nodata_finding(path.rsplit("/", 1)[-1], "")
        if r.status_code != 200:
            return None, self._error_finding(f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return None, self._error_finding("malformed JSON response")
        if not isinstance(data, dict):
            return None, self._error_finding("unexpected response shape")
        return data, None

    @staticmethod
    def _parse_stats(data: dict) -> dict:
        """Flatten v3 ``last_analysis_stats``/``last_analysis_results``."""
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        if not isinstance(stats, dict):
            stats = {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
        engines: list[str] = []
        results = attrs.get("last_analysis_results") or {}
        if isinstance(results, dict):
            for eng, res in results.items():
                if isinstance(res, dict) and res.get("category") in ("malicious", "suspicious"):
                    engines.append(f"{eng}={res.get('result') or res.get('category')}")
        return {"malicious": malicious, "suspicious": suspicious, "harmless": harmless,
                "undetected": undetected, "adverse": malicious + suspicious,
                "total": total, "engines": engines}

    def _match_from_stats(self, data: dict, target_label: str,
                          is_domain_fallback: bool) -> list[Finding]:
        """Evaluate v3 stats; authoritative only for exact-URL matches or a
        domain fallback with a strong malicious majority (>= 8)."""
        s = self._parse_stats(data)
        if s["adverse"] == 0:
            return []
        authoritative = (not is_domain_fallback) or s["malicious"] >= self.DOMAIN_AUTHORITATIVE_MALICIOUS
        # Only "positives=" is visible to the scoring engine's authority rule;
        # domain-level matches without a malicious majority use
        # "domain_positives=" so they inform without confirming.
        counter = "positives" if authoritative else "domain_positives"
        evidence = [
            f"target={target_label}",
            f"malicious={s['malicious']}, suspicious={s['suspicious']}, "
            f"harmless={s['harmless']}, undetected={s['undetected']}",
        ] + s["engines"][:10]
        if s["adverse"] >= self.AUTHORITATIVE_POSITIVES:
            evidence.append(f"{counter}={s['adverse']}/{s['total']}")
            return [Finding(category=FindingCategory.INTEL,
                id="VT-MATCH",
                title=f"VirusTotal flagged {target_label} ({s['adverse']} engines)",
                severity=Severity.HIGH,
                evidence=evidence, source=SOURCE_PREFIX + self.name, check_succeeded=True)]
        evidence.append(f"{counter}={s['adverse']}/{s['total']}")
        return [Finding(category=FindingCategory.INTEL,
            id="VT-LOW-CONFIDENCE",
            title=f"VirusTotal low-count detections on {target_label} ({s['adverse']} engines)",
            severity=Severity.MEDIUM,
            evidence=evidence + ["A small number of engines flagged this target: "
                                 "a supporting signal, not an authoritative verdict."],
            source=SOURCE_PREFIX + self.name, check_succeeded=True)]

    def _submit_on_miss_and_recheck(self, url: str, url_id: str) -> list[Finding] | None:
        """OPT-IN active behaviour: submit the unknown URL for scanning and
        re-check, bounded by the hourly quota budget
        (TRUSTLENS_VT_SUBMIT_MAX_PER_HOUR). Returns findings, or None when the
        budget is exhausted or submission/re-check did not produce a usable
        URL verdict (the caller continues with the passive fallback)."""
        if not self._consume_submit_budget():
            logger.info("VT submit-on-miss skipped for %s: hourly submission budget exhausted", url)
            return None
        try:
            r = self.client.post(self.BASE + "/urls",
                                 data={"url": url}, timeout=10)
        except (httpx.HTTPError, OSError) as exc:
            logger.info("VT submit-on-miss failed for %s: %s", url, type(exc).__name__)
            return None
        if r.status_code not in (200, 201):
            return None
        data, err = self._fetch_json(f"/urls/{url_id}")
        if err is not None or data is None:
            return None
        return self._match_from_stats(data, f"URL ({url})", is_domain_fallback=False)

    # Class-level rolling-hour budget, shared across registry instances (the
    # runner builds a fresh registry per analysis; the quota is a property of
    # the VT ACCOUNT, not of one analysis).
    _submit_window_start: float = 0.0
    _submit_count: int = 0

    def _consume_submit_budget(self) -> bool:
        import time as _time
        now = _time.time()
        cls = type(self)
        if now - cls._submit_window_start >= 3600:
            cls._submit_window_start = now
            cls._submit_count = 0
        limit = self.settings.vt_submit_max_per_hour if self.settings else 10
        if cls._submit_count >= max(0, int(limit)):
            return False
        cls._submit_count += 1
        return True

    @staticmethod
    def _host_of(url: str) -> str:
        try:
            return (urllib.parse.urlparse(url).hostname or "").rstrip(".")
        except ValueError:
            return ""

    def check_url(self, url: str) -> list[Finding]:
        cache_key = ("vt:url", url)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        url_id = self._url_id(url)
        data, err = self._fetch_json(f"/urls/{url_id}")
        if err is not None:
            if err.id != "VT-NODATA":
                return [err]  # transport / key / rate-limit / malformed → failed check

            # --- URL cache miss (404) ---
            if self._submit_on_miss:
                submitted = self._submit_on_miss_and_recheck(url, url_id)
                if submitted is not None:
                    self._cache.put(cache_key, submitted)
                    return submitted

            if self._domain_fallback:
                host = self._host_of(url)
                if host:
                    ddata, derr = self._fetch_json(f"/domains/{host}")
                    if derr is None and ddata is not None:
                        findings = self._match_from_stats(
                            ddata, f"domain {host} (URL uncached)", is_domain_fallback=True)
                        self._cache.put(cache_key, findings)
                        return findings
                    if derr is not None and derr.id in ("VT-ERROR", "VT-KEY-ERROR"):
                        return [derr]  # honest failure — never read as clean
                    # domain 404 → fall through to the combined NODATA finding

            nodata = self._nodata_finding(url_id, self._host_of(url))
            self._cache.put(cache_key, [nodata])
            return [nodata]

        findings = self._match_from_stats(data, f"URL ({url})", is_domain_fallback=False)
        self._cache.put(cache_key, findings)
        return findings

    def check_domain(self, domain: str) -> list[Finding]:
        cache_key = ("vt:domain", domain)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        data, err = self._fetch_json(f"/domains/{domain}")
        if err is not None:
            return [err]
        # Direct domain-reputation check (requested explicitly by the runner):
        # adverse engines here are meaningful domain-level evidence.
        s = self._parse_stats(data)
        findings: list[Finding] = []
        if s["adverse"] > 0:
            findings.append(Finding(category=FindingCategory.INTEL,
                id="VT-MATCH",
                title=f"VirusTotal flagged domain ({s['adverse']}/{s['total']} engines)",
                severity=Severity.HIGH if s["adverse"] >= self.AUTHORITATIVE_POSITIVES else Severity.MEDIUM,
                evidence=[f"target=domain ({domain})",
                          f"malicious={s['malicious']}, suspicious={s['suspicious']}, "
                          f"harmless={s['harmless']}, undetected={s['undetected']}"]
                         + s["engines"][:10] + [f"positives={s['adverse']}/{s['total']}"],
                source=SOURCE_PREFIX + self.name, check_succeeded=True,
            ))
        self._cache.put(cache_key, findings)
        return findings


# ---- registry and dispatcher --------------------------------------------------

_REGISTRY: list[type[IntelSource]] = [
    GoogleSafeBrowsing,
    Urlhaus,
    OpenPhish,
    PhishTank,
    VirusTotal,
]


def init_intel(settings: Settings) -> "IntelRegistry":
    return IntelRegistry(settings)


class IntelRegistry:
    """Provider dispatcher. Keys are read from Settings per instance (never a
    module global, so concurrent apps/tests with different settings stay isolated)."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._keys: dict[str, str] = {
            name: (getattr(settings, field, "") or "")
            for name, field in _PROVIDER_KEY_FIELDS.items()
        }
        self._instances: dict[str, IntelSource] = {}
        # name -> absolute epoch until which the provider is silently backed
        # off (429 Retry-After aware; no HTTP calls hit a rate-limited
        # provider inside the window, so worker threads never stall).
        self._failed: dict[str, float] = {}
        # Providers that returned a usable answer for the current analysis (a
        # clean no-hit counts as an answer; transport/ratelimit/key failures
        # do not). Used by the runner for the required threat-intel gate.
        self._answered: set[str] = set()
        self._init_from_settings()

    def answered_providers(self) -> list[str]:
        """Configured providers that produced a usable answer so far."""
        return sorted(self._answered)

    @staticmethod
    def _answer_usable(findings: list[Finding]) -> bool:
        """No findings = clean answer; any check that completed = usable. A
        provider whose ONLY output is failed-check findings did not answer."""
        if not findings:
            return True
        return any(f.check_succeeded for f in findings)

    def _has_key(self, name: str) -> bool:
        return bool(self._keys.get(name))

    def _init_from_settings(self):
        for cls in _REGISTRY:
            if not self._has_key(cls.name) or not cls.requires_key:
                continue
            try:
                self._instances[cls.name] = cls(self._keys[cls.name], self._settings)
            except Exception as exc:
                self._failed[cls.name] = time.time() + 60.0
                logger.warning("[intel] %s failed to init: %s: %s", cls.name, type(exc).__name__, exc)

    def _active(self, name: str) -> IntelSource | None:
        if name not in self._instances:
            return None
        if time.time() < self._failed.get(name, 0):
            return None  # silent backoff window (rate limit / flaky failure)
        return self._instances[name]

    async def _check_provider_url(self, cls: type[IntelSource], url: str) -> list[Finding]:
        name = cls.name
        if not cls.check_url_supported:
            return []
        inst = self._active(name)
        if inst is None:
            if not self._has_key(name):
                return [Finding(category=FindingCategory.INTEL, 
                    id=name.upper() + "-UNAVAILABLE", title=f"{name} unavailable",
                    severity=Severity.INFO, evidence=[f"{name} requires TRUSTLENS_{name.upper()}_API_KEY"],
                    source=SOURCE_PREFIX + name, check_succeeded=False)]
            elif time.time() < self._failed.get(name, 0):
                return [Finding(category=FindingCategory.INTEL, 
                    id=name.upper() + "-RATELIMIT", title=f"{name} temporarily unavailable",
                    severity=Severity.INFO, evidence=["Provider rate-limited; retry later."],
                    source=SOURCE_PREFIX + name, check_succeeded=False)]
            return []
        try:
            findings = await asyncio.to_thread(inst.check_url, url)
            if self._answer_usable(findings):
                self._answered.add(name)
            return findings
        except IntelUnavailable as exc:
            if "not supported" in str(exc).lower():
                return []
            self._failed[name] = time.time() + getattr(exc, "retry_after", 60.0)
            return [Finding(category=FindingCategory.INTEL,
                id=name.upper() + "-RATELIMIT", title=f"{name} temporarily unavailable",
                severity=Severity.INFO,
                evidence=[f"Provider rate-limited; retry after {getattr(exc, 'retry_after', 60.0):.0f}s."],
                source=SOURCE_PREFIX + name, check_succeeded=False)]
        except Exception as exc:
            return [Finding(category=FindingCategory.INTEL, 
                id=name.upper() + "-ERROR", title=f"{name} check failed unexpectedly",
                severity=Severity.INFO, evidence=[f"{type(exc).__name__}: {str(exc)[:250]}"],
                source=SOURCE_PREFIX + name, check_succeeded=False)]

    async def check_url(self, url: str) -> list[Finding]:
        tasks = [self._check_provider_url(cls, url) for cls in _REGISTRY if cls.check_url_supported]
        provider_findings = await asyncio.gather(*tasks)
        all_findings: list[Finding] = []
        for findings in provider_findings:
            all_findings.extend(findings)
        return all_findings

    async def _check_provider_domain(self, cls: type[IntelSource], domain: str) -> list[Finding]:
        name = cls.name
        if not cls.check_domain_supported:
            return []
        inst = self._active(name)
        if inst is None:
            if not self._has_key(name):
                return [Finding(category=FindingCategory.INTEL, 
                    id=name.upper() + "-UNAVAILABLE", title=f"{name} unavailable",
                    severity=Severity.INFO, evidence=[f"{name} requires TRUSTLENS_{name.upper()}_API_KEY"],
                    source=SOURCE_PREFIX + name, check_succeeded=False)]
            elif time.time() < self._failed.get(name, 0):
                return [Finding(category=FindingCategory.INTEL, 
                    id=name.upper() + "-RATELIMIT", title=f"{name} temporarily unavailable",
                    severity=Severity.INFO, evidence=["Provider rate-limited; retry later."],
                    source=SOURCE_PREFIX + name, check_succeeded=False)]
            return []
        try:
            findings = await asyncio.to_thread(inst.check_domain, domain)
            if self._answer_usable(findings):
                self._answered.add(name)
            return findings
        except IntelUnavailable as exc:
            if "not supported" in str(exc).lower():
                return []
            self._failed[name] = time.time() + getattr(exc, "retry_after", 60.0)
            return [Finding(category=FindingCategory.INTEL,
                id=name.upper() + "-RATELIMIT", title=f"{name} temporarily unavailable",
                severity=Severity.INFO,
                evidence=[f"Provider rate-limited; retry after {getattr(exc, 'retry_after', 60.0):.0f}s."],
                source=SOURCE_PREFIX + name, check_succeeded=False)]
        except Exception as exc:
            return [Finding(category=FindingCategory.INTEL, 
                id=name.upper() + "-ERROR", title=f"{name} check failed unexpectedly",
                severity=Severity.INFO, evidence=[f"{type(exc).__name__}: {str(exc)[:250]}"],
                source=SOURCE_PREFIX + name, check_succeeded=False)]

    async def check_domain(self, domain: str) -> list[Finding]:
        tasks = [self._check_provider_domain(cls, domain) for cls in _REGISTRY if cls.check_domain_supported]
        provider_findings = await asyncio.gather(*tasks)
        all_findings: list[Finding] = []
        for findings in provider_findings:
            all_findings.extend(findings)
        return all_findings

    def status(self) -> dict:
        out: dict[str, str] = {}
        for cls in _REGISTRY:
            name = cls.name
            if name not in self._instances:
                out[name] = "unconfigured" if not self._has_key(name) else "failed"
            elif time.time() < self._failed.get(name, 0):
                out[name] = "rate_limited"
            else:
                out[name] = "active"
        return out
