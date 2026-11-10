"""Passive response-header checks (Phase 6).

Analyses the headers captured by the safe fetcher — no new requests, no active
probing. Missing security headers are coverage/quality signals, never proof of
malice: plenty of legitimate sites ship without CSP. Conversely, present
headers prove nothing about trustworthiness. Findings here are informational
by design and feed the explanation, not the verdict band.
"""
from __future__ import annotations

import re
from typing import Optional

from ..models.enums import FindingCategory, Severity
from ..models.schemas import Finding, SafeFetchResult

SOURCE = "trustlens/headers"

# Resource-reference patterns for the naive mixed-content check (https page only).
_SRC_HTTP_RE = re.compile(r'(?:src|href)\s*=\s*["\']http://[^"\']+', re.IGNORECASE)
# Common non-content URLs that legitimately appear as http:// in markup.
_BENIGN_HTTP_RE = re.compile(r"http://(?:www\.w3\.org|schemas\.|purl\.org|ogp\.me|gmpg\.org|xmlns)", re.IGNORECASE)


def _finding(fid: str, title: str, severity: Severity, evidence: list[str]) -> Finding:
    return Finding(
        id=fid, title=title, severity=severity, category=FindingCategory.HEADERS,
        evidence=evidence, source=SOURCE,
    )


def analyze_headers(result: SafeFetchResult, final_scheme: str) -> list[Finding]:
    """Passive header checks on the final fetched response (2xx/3xx only)."""
    if not result.success or result.status_code is None or result.status_code >= 400:
        return []
    headers = result.response_headers
    get = lambda name: headers.get(name.lower())
    findings: list[Finding] = []

    # --- transport ------------------------------------------------------------
    if final_scheme == "http":
        findings.append(_finding(
            "HEADER-PLAIN-HTTP", "Page served over plain HTTP (no TLS)", Severity.MEDIUM,
            [
                "The final response was delivered over http:// without encryption.",
                "Anything submitted to this page (including credentials) transits the network in the clear.",
            ],
        ))
    else:
        hsts = get("strict-transport-security")
        if not hsts:
            findings.append(_finding(
                "HEADER-HSTS-MISSING", "Strict-Transport-Security header missing", Severity.INFO,
                [
                    "The HTTPS page does not send Strict-Transport-Security (HSTS).",
                    "Without HSTS a man-in-the-middle can keep visitors on an http:// downgrade. "
                    "A quality signal only — not evidence of malice.",
                ],
            ))

    # --- content security ------------------------------------------------------
    csp = get("content-security-policy")
    if not csp:
        findings.append(_finding(
            "HEADER-CSP-MISSING", "Content-Security-Policy header missing", Severity.INFO,
            [
                "No Content-Security-Policy was returned.",
                "CSP limits what scripts a page may load; its absence is a hardening gap, "
                "not an indicator of fraud.",
            ],
        ))
    xfo = get("x-frame-options")
    csp_frame = "frame-ancestors" in (csp or "").lower()
    if not xfo and not csp_frame:
        findings.append(_finding(
            "HEADER-FRAMING-OPEN", "No clickjacking protection (X-Frame-Options / frame-ancestors)",
            Severity.INFO,
            [
                "Neither X-Frame-Options nor CSP frame-ancestors restricts embedding this page in frames.",
                "Relevant mainly for login pages; informational here.",
            ],
        ))
    xcto = get("x-content-type-options")
    if not xcto or xcto.lower() != "nosniff":
        findings.append(_finding(
            "HEADER-CTO-MISSING", "X-Content-Type-Options: nosniff missing", Severity.INFO,
            ["The server does not forbid MIME-sniffing; a hardening detail only."],
        ))

    # --- version disclosure ------------------------------------------------------
    server = get("server") or ""
    if re.search(r"\d+\.\d+", server):
        findings.append(_finding(
            "HEADER-SERVER-VERSION", "Server header discloses a version number", Severity.INFO,
            [
                f"Server header: '{server[:120]}'.",
                "Version disclosure helps attackers target known CVEs; it says nothing about intent.",
            ],
        ))
    powered = get("x-powered-by") or ""
    if powered:
        findings.append(_finding(
            "HEADER-XPOWERED-DISCLOSURE", "X-Powered-By header discloses stack details", Severity.INFO,
            [f"X-Powered-By: '{powered[:120]}'."],
        ))

    # --- cookies -------------------------------------------------------------------
    # Audit L4: only cookie NAMES and Secure-flag facts are retained — raw
    # Set-Cookie values (which can carry session tokens issued to TrustLensBot)
    # are never stored in findings or the report summary.
    set_cookie = get("set-cookie")
    cookie_names = _cookie_names(set_cookie)
    cookies_without_secure = [n for n in cookie_names if n not in _secure_cookie_names(set_cookie)]
    if cookie_names and final_scheme == "https" and cookies_without_secure:
        findings.append(_finding(
            "HEADER-COOKIE-NOSECURE", "Set-Cookie without the Secure flag over HTTPS", Severity.INFO,
            [
                f"At least one cookie was set without Secure (first: '{cookies_without_secure[0][:60]}').",
                "Such cookies can leak over http:// connections; a quality signal only.",
            ],
        ))

    # --- naive mixed-content scan on the (capped) body excerpt ----------------------
    if result.title is not None or (result.content_type and "html" in (result.content_type or "").lower()):
        body = getattr(result, "body_excerpt", None)
        if body and final_scheme == "https":
            hits = [m.group(0) for m in _SRC_HTTP_RE.finditer(body) if not _BENIGN_HTTP_RE.search(m.group(0))]
            if hits:
                findings.append(_finding(
                    "HEADER-MIXED-CONTENT", "HTTPS page references http:// resources", Severity.LOW,
                    [
                        f"{len(hits)} insecure reference(s) in the first bytes of the page "
                        f"(first: '{hits[0][:100]}').",
                        "Analysis covers only the capped body excerpt; attackers can also inject "
                        "content via JavaScript, which TrustLens never executes.",
                    ],
                ))
    return findings


def _cookie_names(set_cookie: Optional[str]) -> list[str]:
    """Cookie NAMES only (part before '='), comma-split. Values are discarded."""
    if not set_cookie:
        return []
    names: list[str] = []
    for part in set_cookie.split(","):
        # Skip Expires= segments' date commas: a date fragment has no '=' before ';'.
        candidate = part.strip()
        if "=" not in candidate:
            continue
        name = candidate.split("=", 1)[0].strip()
        if name and name.lower() not in ("expires",):
            names.append(name[:60])
    return names


def _secure_cookie_names(set_cookie: Optional[str]) -> set[str]:
    """Names of cookies whose attributes include Secure."""
    secured: set[str] = set()
    if not set_cookie:
        return secured
    for part in set_cookie.split(","):
        candidate = part.strip()
        if "=" not in candidate:
            continue
        name = candidate.split("=", 1)[0].strip().lower()
        if name and name != "expires" and "secure" in candidate.lower():
            secured.add(name)
    return secured


def headers_summary(result: SafeFetchResult, final_scheme: str) -> Optional[dict]:
    """Compact header summary for the report UI (only for successful fetches).

    Audit L4: Set-Cookie values are NEVER copied into the report — only the
    cookie count, names, and Secure-flag facts are retained."""
    if not result.success:
        return None
    interesting = [
        "strict-transport-security", "content-security-policy", "x-frame-options",
        "x-content-type-options", "server", "x-powered-by", "referrer-policy",
        "permissions-policy",
    ]
    present = {k: v[:160] for k, v in result.response_headers.items() if k.lower() in interesting}
    summary: dict = {
        "final_scheme": final_scheme,
        "present": present,
        "security_headers_present": [
            k for k in ("strict-transport-security", "content-security-policy",
                        "x-frame-options", "x-content-type-options")
            if k in present
        ],
    }
    set_cookie = result.response_headers.get("set-cookie")
    if set_cookie:
        names = _cookie_names(set_cookie)
        summary["set_cookie"] = {
            "count": len(names),
            "names": names[:5],
            "without_secure": [n for n in names if n.lower() not in _secure_cookie_names(set_cookie)][:5],
        }
    return summary
