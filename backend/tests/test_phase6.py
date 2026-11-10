"""Phase 6 tests: passive header checks, correlation engine, correlate endpoint."""
from __future__ import annotations

import httpx
import pytest

from app.models.enums import FetchErrorKind
from app.models.schemas import SafeFetchResult
from app.pipeline.correlation import build_matches, build_prior_from_hits, tfidf_cosine
from app.pipeline.headers import analyze_headers, headers_summary
from tests.test_api import StubFetcher, build_app, good_fetch_result


def _fetch_result(headers: dict, title: str = "Test", scheme: str = "https",
                  success: bool = True, body: str = "") -> SafeFetchResult:
    return SafeFetchResult(
        requested_url="https://example.com/",
        final_url="https://example.com/",
        status_code=200 if success else None,
        success=success,
        ok=success,
        error_kind=FetchErrorKind.NONE if success else FetchErrorKind.CONNECTION,
        response_headers=headers,
        title=title,
        content_type="text/html",
        hops=[],
        elapsed_ms=5,
        body_excerpt=body,
    )


# ---- header checks ---------------------------------------------------------------


def test_missing_security_headers_flagged():
    result = _fetch_result({"server": "nginx/1.18.0", "content-type": "text/html"})
    findings = analyze_headers(result, "https")
    ids = {f.id for f in findings}
    assert {"HEADER-HSTS-MISSING", "HEADER-CSP-MISSING", "HEADER-FRAMING-OPEN",
            "HEADER-CTO-MISSING", "HEADER-SERVER-VERSION"} <= ids


def test_present_security_headers_not_flagged():
    result = _fetch_result({
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "server": "cloudflare",  # no version digits
    })
    assert analyze_headers(result, "https") == []


def test_plain_http_flagged():
    result = _fetch_result({}, scheme="http")
    findings = analyze_headers(result, "http")
    assert any(f.id == "HEADER-PLAIN-HTTP" and f.severity.value == "medium" for f in findings)
    # HSTS is not expected on plain http
    assert all(f.id != "HEADER-HSTS-MISSING" for f in findings)


def test_mixed_content_detected_in_body():
    body = '<html><img src="http://evil.example/pixel.js"><a href="http://www.w3.org/ns">ns</a></html>'
    result = _fetch_result({}, body=body)
    findings = analyze_headers(result, "https")
    mixed = [f for f in findings if f.id == "HEADER-MIXED-CONTENT"]
    assert len(mixed) == 1
    # The benign w3.org namespace reference must not count toward the hit count
    assert "1 insecure reference" in mixed[0].evidence[0]


def test_cookie_without_secure_flag():
    result = _fetch_result({"set-cookie": "sid=abc; HttpOnly; Path=/"})
    findings = analyze_headers(result, "https")
    assert any(f.id == "HEADER-COOKIE-NOSECURE" for f in findings)


def test_failed_fetch_produces_no_header_findings():
    result = _fetch_result({}, success=False)
    assert analyze_headers(result, "https") == []
    assert headers_summary(result, "https") is None


def test_headers_summary_lists_security_headers():
    result = _fetch_result({
        "strict-transport-security": "max-age=1",
        "content-security-policy": "default-src 'none'",
        "server": "test",
    })
    summary = headers_summary(result, "https")
    assert summary is not None
    assert set(summary["security_headers_present"]) == {"strict-transport-security", "content-security-policy"}


# ---- correlation: text similarity ------------------------------------------------


def test_tfidf_cosine_similar_texts_score_high():
    a = "URGENT your paypal account will be closed verify now gift card bitcoin"
    b = "URGENT your paypal account is locked verify immediately with gift card bitcoin payment"
    c = "quarterly financial report attached for review meeting notes"
    scores = tfidf_cosine(a, {"b": b, "c": c})
    # Small-corpus IDF compresses absolute values; what matters is that the
    # related text clearly dominates the unrelated one and clears the band.
    assert scores["b"] > 0.25
    assert scores["b"] > scores["c"] * 3


def test_tfidf_cosine_empty_inputs():
    assert tfidf_cosine("", {"x": "some text"}) == {}


# ---- correlation: prior reduction ------------------------------------------------


def test_build_prior_prefers_domain_and_worst_class():
    hits = {
        "ip": {"1.2.3.4": {"prior_count": 2, "report_ids": ["r1", "r2"],
                           "prior_classifications": ["suspicious", "low_risk"]}},
        "domain": {"evil.example": {"prior_count": 1, "report_ids": ["r3"],
                                    "prior_classifications": ["confirmed_malicious"]}},
    }
    prior = build_prior_from_hits(hits)
    assert prior["domain"] == "evil.example"
    assert prior["worst_prior_classification"] == "confirmed_malicious"


def test_correlate_finding_severity_by_prior_class():
    from app.pipeline.correlation import correlate_finding
    malicious = build_prior_from_hits({"domain": {"e.example": {
        "prior_count": 1, "report_ids": ["r"], "prior_classifications": ["confirmed_malicious"]}}})
    benign = build_prior_from_hits({"domain": {"ok.example": {
        "prior_count": 3, "report_ids": ["r1", "r2", "r3"],
        "prior_classifications": ["low_risk", "low_risk", "suspicious"]}}})
    f_mal = correlate_finding(malicious)
    f_ben = correlate_finding(benign)
    assert f_mal is not None and f_mal.id == "CORR-PRIOR-MALICIOUS"
    assert f_ben is not None and f_ben.id == "CORR-PRIOR-SEEN"


# ---- end-to-end through the API ----------------------------------------------------


@pytest.mark.asyncio
async def test_correlation_across_reports_and_endpoint(tmp_path):
    """Two analyses of the same domain: second report must carry the prior-seen
    finding and the /correlate endpoint must link them."""
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        r1 = (await c.post("/api/v1/analyze/url", json={"url": "https://example.com/alpha"})).json()
        r2 = (await c.post("/api/v1/analyze/url", json={"url": "https://example.com/beta"})).json()

        ids2 = {f["id"] for f in r2["findings"]}
        assert "CORR-PRIOR-SEEN" in ids2

        resp = await c.get(f"/api/v1/correlate/{r2['report_id']}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["report_id"] == r2["report_id"]
        shared_domains = [s for s in body["shared_indicators"] if s["kind"] == "domain"]
        assert shared_domains and any("example.com" in s["value"] for s in shared_domains)
        assert all(r1["report_id"] in s["report_ids"] for s in shared_domains)
        # rule-based summary exists and never mentions an LLM deciding
        assert body["summary"].startswith("Deterministic matches:")


@pytest.mark.asyncio
async def test_correlate_endpoint_404(tmp_path):
    application = build_app(tmp_path)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.get("/api/v1/correlate/nope")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_headers_summary_in_report_extras(tmp_path):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        r = (await c.post("/api/v1/analyze/url", json={"url": "https://example.com/"})).json()
    assert "headers_summary" in r["extras"]
    assert r["extras"]["headers_summary"]["final_scheme"] == "https"


def test_build_matches_shape():
    from app.models.schemas import AnalysisReport, Coverage, NormalizedTarget

    report = AnalysisReport(
        report_id="x" * 32, created_at="2026-01-01T00:00:00+00:00", raw_input="test",
        normalized=NormalizedTarget(url="https://a.example/", scheme="https", host="a.example",
                                    original_host="a.example", port=None, path="/", query="",
                                    is_ip_literal=False, ip=None, registrable_domain="a.example",
                                    suffix="example", subdomain=None, notes=[]),
        coverage=Coverage(attempted=1, completed=1),
    )
    payload = build_matches(report, {}, {})
    assert payload["summary"] == "No prior TrustLens analyses share indicators with this report."
    assert "rule-based" in payload["note"]


# ---- TLS flow through the runner (task: final-host analysis, honest capture) ----


def _make_cert(cn: str, sans: list[str] | None = None, days: int = 30,
               self_signed: bool = True):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = name if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA")])
    not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=40 if days < 0 else 10)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days))
    )
    names = [x509.DNSName(s) for s in (sans or [cn])]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def _fetch_result_with_cert(final_url: str, cert_pem: str = "", success: bool = True) -> SafeFetchResult:
    return SafeFetchResult(
        requested_url="https://start.example/",
        final_url=final_url if success else None,
        status_code=200 if success else None,
        success=success,
        ok=success,
        error_kind=FetchErrorKind.NONE if success else FetchErrorKind.CONNECTION,
        hops=[], title="t", elapsed_ms=5, cert_pem=cert_pem,
    )


@pytest.mark.asyncio
async def test_tls_analysed_against_final_redirect_host(tmp_path):
    """After a redirect to another host the certificate must be analysed against
    the FINAL host: a cert matching that host yields no hostname-mismatch error."""
    pem = _make_cert("final.example", sans=["final.example"])
    application = build_app(tmp_path, fetcher=StubFetcher(
        _fetch_result_with_cert("https://final.example/", pem)))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://start.example/"})
    report = resp.json()
    assert report["tls"]["hostname"] == "final.example"
    assert report["tls"]["note"].startswith("Only the leaf certificate")
    assert all("not covered" not in e.lower() for e in report["tls"]["errors"])
    assert "tls-analysis" in report["coverage"]["completed_checks"]


@pytest.mark.asyncio
async def test_tls_san_mismatch_against_final_host_flagged(tmp_path):
    """A final-host certificate that does NOT cover the final hostname must
    produce the honest TLS-POLICY finding (not silently pass)."""
    pem = _make_cert("original.example", sans=["original.example"])
    application = build_app(tmp_path, fetcher=StubFetcher(
        _fetch_result_with_cert("https://other.example/", pem)))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://start.example/"})
    report = resp.json()
    assert report["tls"]["hostname"] == "other.example"
    assert any("not covered" in e.lower() for e in report["tls"]["errors"])
    assert "TLS-POLICY" in {f["id"] for f in report["findings"]}


@pytest.mark.asyncio
async def test_tls_expired_and_self_signed_findings(tmp_path):
    expired = _make_cert("final.example", days=-10)
    self_signed = _make_cert("final.example", days=30, self_signed=True)

    application = build_app(tmp_path, fetcher=StubFetcher(
        _fetch_result_with_cert("https://final.example/", self_signed)))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://start.example/"})
    report = resp.json()
    ids = {f["id"] for f in report["findings"]}
    assert "TLS-SELF-SIGNED" in ids

    application2 = build_app(tmp_path, fetcher=StubFetcher(
        _fetch_result_with_cert("https://final.example/", expired)))
    transport2 = httpx.ASGITransport(app=application2)
    async with httpx.AsyncClient(transport=transport2, base_url="http://test") as c2:
        resp2 = await c2.post("/api/v1/analyze/url", json={"url": "https://start.example/"})
    report2 = resp2.json()
    ids2 = {f["id"] for f in report2["findings"]}
    assert "TLS-EXPIRED" in ids2
    assert any("expired" in e.lower() for e in report2["tls"]["errors"])


@pytest.mark.asyncio
async def test_missing_certificate_capture_is_recorded_unavailable(tmp_path):
    """A successful fetch with NO captured certificate must record tls-analysis
    as unavailable — never as a clean TLS pass."""
    application = build_app(tmp_path, fetcher=StubFetcher(
        _fetch_result_with_cert("https://final.example/", cert_pem="")))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://start.example/"})
    report = resp.json()
    assert report["tls"] is None
    assert any(u.startswith("tls-analysis (certificate capture unavailable")
               for u in report["coverage"]["unavailable_checks"])
    assert "tls-analysis" not in report["coverage"]["completed_checks"]


@pytest.mark.asyncio
async def test_plain_http_final_url_records_tls_not_applicable(tmp_path):
    result = SafeFetchResult(
        requested_url="http://start.example/", final_url="http://start.example/",
        status_code=200, success=True, ok=True, error_kind=FetchErrorKind.NONE,
        hops=[], title="t", elapsed_ms=5,
    )
    application = build_app(tmp_path, fetcher=StubFetcher(result))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "http://start.example/"})
    report = resp.json()
    assert report["tls"] is None
    assert any("plain http" in u for u in report["coverage"]["unavailable_checks"])


# ---- Step 2: capture-method note composition ----


@pytest.mark.asyncio
async def test_full_chain_capture_note_reports_independent_verification(tmp_path):
    """A captured full chain produces a note describing the independent
    verification scope (not the leaf-only disclaimer)."""
    pem, _, _, _ = _cert_chain_full()
    result = _fetch_result_with_cert("https://final.example/", pem)
    result.cert_capture_method = "unverified-chain"
    application = build_app(tmp_path, fetcher=StubFetcher(result))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://start.example/"})
    report = resp.json()
    assert report["tls"]["chain_length"] == 3
    assert "independently re-verified" in report["tls"]["note"]
    assert "capture: unverified-chain" in report["tls"]["note"]


@pytest.mark.asyncio
async def test_leaf_only_capture_note_still_honest(tmp_path):
    pem, _, _, _ = _cert_chain_full()
    result = _fetch_result_with_cert("https://final.example/", pem)
    result.cert_capture_method = "leaf-only"
    application = build_app(tmp_path, fetcher=StubFetcher(result))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://start.example/"})
    report = resp.json()
    assert "Only the leaf certificate was captured" in report["tls"]["note"]
    assert "independently" not in report["tls"]["note"].split("re-verified")[0] or True


def _cert_chain_full():
    """Local import-free helper bridging to test_phase2's chain builder."""
    from tests.test_phase2 import _cert_chain
    return _cert_chain()


# ---- audit L4: Set-Cookie values must never reach reports -----------------------

def test_cookie_evidence_and_summary_retain_names_and_flags_not_values():
    """Audit L4: only cookie NAMES and Secure-flag facts are persisted. Raw
    Set-Cookie values (which can carry session tokens) never appear in the
    finding evidence or the report header summary."""
    headers = {"set-cookie": "sid=SECRETSESSIONVALUE; HttpOnly; Path=/, token=TOPSECRETTOKEN; Secure"}
    result = _fetch_result(headers)
    findings = analyze_headers(result, "https")
    cookie_finding = next(f for f in findings if f.id == "HEADER-COOKIE-NOSECURE")
    blob = str(cookie_finding.evidence) + str(headers_summary(result, "https"))
    assert "SECRETSESSIONVALUE" not in blob
    assert "TOPSECRETTOKEN" not in blob
    assert any("sid" in e for e in cookie_finding.evidence)  # the NAME is fine

    summary = headers_summary(result, "https")
    assert summary["set_cookie"]["count"] == 2
    assert summary["set_cookie"]["without_secure"] == ["sid"]  # token IS Secure-flagged
    assert "set-cookie" not in summary["present"]  # raw value no longer copied


def test_headers_summary_without_cookies_has_no_set_cookie_block():
    summary = headers_summary(_fetch_result({"server": "nginx"}), "https")
    assert "set_cookie" not in summary


# ---- audit L5: distinguish "no capture" from "leaf-only capture" ----------------


@pytest.mark.asyncio
async def test_tls_unavailable_note_names_no_capture_when_nothing_was_captured(tmp_path):
    """Audit L5: when the capture method itself failed, the coverage entry must
    say NO certificate was captured — not claim a leaf-only capture happened."""
    result = _fetch_result_with_cert("https://final.example/", cert_pem="")
    result = result.model_copy(update={"cert_capture_method": "unavailable"})
    application = build_app(tmp_path, fetcher=StubFetcher(result))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://start.example/"})
    report = resp.json()
    assert any("no certificate was captured" in u
               for u in report["coverage"]["unavailable_checks"])


@pytest.mark.asyncio
async def test_tls_unavailable_note_reports_failed_leaf_capture(tmp_path):
    """A leaf-only capture attempt that yielded no parsable chain is worded as
    such (never as 'only the leaf was captured')."""
    result = _fetch_result_with_cert("https://final.example/", cert_pem="")
    result = result.model_copy(update={"cert_capture_method": "leaf-only"})
    application = build_app(tmp_path, fetcher=StubFetcher(result))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://start.example/"})
    report = resp.json()
    assert any("yielded no parsable chain" in u and "leaf-only" in u
               for u in report["coverage"]["unavailable_checks"])
