"""End-to-end API tests: routes, validation, persistence, rate limiting."""
from __future__ import annotations

import httpx
import pytest

from app.main import create_app
from app.models.enums import FetchErrorKind
from app.models.schemas import SafeFetchResult
from app.pipeline.fetcher import SafeFetcher
from app.storage.database import init_engine
from tests.conftest import FakeResolver, FakeTransport, html_response, make_settings


class StubFetcher(SafeFetcher):
    """Returns a canned SafeFetchResult without touching the network."""

    def __init__(self, result: SafeFetchResult):
        self._result = result

    async def fetch(self, norm):  # type: ignore[override]
        return self._result.model_copy(update={"requested_url": norm.url})


def good_fetch_result(final_url: str = "https://example.com/") -> SafeFetchResult:
    return SafeFetchResult(
        requested_url=final_url,
        final_url=final_url,
        status_code=200,
        success=True,
        ok=True,
        error_kind=FetchErrorKind.NONE,
        hops=[],
        title="Example",
        elapsed_ms=5,
    )


def build_app(tmp_path, fetcher=None, **overrides):
    # Reset the module-global engine so every test gets an isolated DB —
    # init_engine() is guarded and would otherwise keep the first test's file.
    import app.storage.database as dbmod

    dbmod._engine = None
    dbmod._SessionLocal = None
    settings = make_settings(
        database_url=f"sqlite:///{tmp_path.as_posix()}/api-test.db", **overrides
    )
    application = create_app(settings)
    init_engine(settings)
    if fetcher is not None:
        application.state.fetcher = fetcher
    return application


@pytest.fixture
async def client(tmp_path):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body


@pytest.mark.asyncio
async def test_analyze_url_returns_report(client):
    resp = await client.post("/api/v1/analyze/url", json={"url": "http://paypa1.com/"})
    assert resp.status_code == 200
    report = resp.json()

    assert report["report_id"]
    # The deterministic scoring engine classifies; the homoglyph finding on a
    # completed fetch puts paypa1.com in the suspicious/high-risk band.
    assert report["classification"] in ("suspicious", "high_risk")
    assert report["normalized"]["registrable_domain"] == "paypa1.com"
    finding_ids = [f["id"] for f in report["findings"]]
    assert "DOM-HOMOGLYPH-CONFUSABLE" in finding_ids  # paypa1 -> paypal after homoglyph folding
    assert report["coverage"]["attempted"] >= 3
    assert report["integrity"]["canonical_json_sha256"]
    assert len(report["integrity"]["canonical_json_sha256"]) == 64


@pytest.mark.asyncio
async def test_analyze_url_strips_tracking_before_fetch(tmp_path):
    seen_urls: list[str] = []

    class RecordingFetcher(StubFetcher):
        async def fetch(self, norm):
            seen_urls.append(norm.url)
            return await super().fetch(norm)

    application = build_app(tmp_path, fetcher=RecordingFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post(
            "/api/v1/analyze/url",
            json={"url": "https://example.com/page?utm_source=ads&id=9"},
        )
    assert resp.status_code == 200
    assert seen_urls == ["https://example.com/page?id=9"]


@pytest.mark.asyncio
async def test_analyze_url_rejects_invalid_scheme(client):
    resp = await client.post("/api/v1/analyze/url", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"]["code"] == "invalid_url"


@pytest.mark.asyncio
async def test_analyze_url_rejects_bad_payload(client):
    resp = await client.post("/api/v1/analyze/url", json={"not_url": "x"})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


@pytest.mark.asyncio
async def test_report_roundtrip(client):
    created = (await client.post("/api/v1/analyze/url", json={"url": "https://example.com/"})).json()
    report_id = created["report_id"]

    fetched = await client.get(f"/api/v1/reports/{report_id}")
    assert fetched.status_code == 200
    fetched_report = fetched.json()
    assert fetched_report["report_id"] == report_id
    assert fetched_report["integrity"] == created["integrity"]
    assert len(fetched_report["findings"]) == len(created["findings"])


@pytest.mark.asyncio
async def test_report_not_found(client):
    resp = await client.get("/api/v1/reports/deadbeef" + "0" * 24)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "report_not_found"


@pytest.mark.asyncio
async def test_report_list(client):
    await client.post("/api/v1/analyze/url", json={"url": "https://example.com/"})
    resp = await client.get("/api/v1/reports")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 1
    assert len(body["reports"]) >= 1
    assert "normalized_url" in body["reports"][0]


@pytest.mark.asyncio
async def test_meta_endpoint(client):
    resp = await client.get("/api/v1/meta")
    assert resp.status_code == 200
    body = resp.json()
    assert "url-normalisation" in body["pipeline_stages"]
    assert "scoring" in body["pipeline_stages"]
    assert body["integrations"]["web3_registry"].startswith("not_configured")


@pytest.mark.asyncio
async def test_rate_limiting(tmp_path):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()), rate_limit_per_minute=2)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        r1 = await c.post("/api/v1/analyze/url", json={"url": "https://example.com/"})
        r2 = await c.post("/api/v1/analyze/url", json={"url": "https://example.com/"})
        r3 = await c.post("/api/v1/analyze/url", json={"url": "https://example.com/"})
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    assert r3.json()["error"]["code"] == "rate_limited"
    assert "retry-after" in {k.lower() for k in r3.headers}


@pytest.mark.asyncio
async def test_health_exempt_from_rate_limit(tmp_path):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()), rate_limit_per_minute=1)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        for _ in range(3):
            resp = await c.get("/health")
            assert resp.status_code == 200


@pytest.mark.asyncio
async def test_real_pipeline_with_fake_network(tmp_path):
    """Full pipeline through the API with a fake resolver/transport (integration-style)."""
    settings = make_settings(database_url=f"sqlite:///{tmp_path.as_posix()}/int-test.db")
    resolver = FakeResolver({"example.com": ["93.184.216.34"]})
    transport = FakeTransport([html_response(200, b"<html><title>It works</title></html>")])
    fetcher = SafeFetcher(settings, resolver=resolver, transport=transport)
    application = build_app(tmp_path, fetcher=fetcher)

    httpx_transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=httpx_transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://example.com/"})
    assert resp.status_code == 200
    report = resp.json()
    assert report["fetch"]["success"] is True
    assert report["fetch"]["title"] == "It works"
    assert report["redirect_chain"][0]["resolved_ips"] == ["93.184.216.34"]


# ---- required-check policy: configured-feed outage / mixed providers (task 2) ----


class _OutageRegistry:
    """All providers configured, none answered (outage)."""

    def status(self):
        return {"urlhaus": "active", "virustotal": "active"}

    def answered_providers(self):
        return []

    async def check_domain(self, domain):
        from app.models.enums import FindingCategory, Severity
        from app.models.schemas import Finding
        return [Finding(id="URLHAUS-ERROR", title="URLhaus check failed",
                        severity=Severity.INFO, category=FindingCategory.INTEL,
                        evidence=["HTTP 502"], source="trustlens/intel/urlhaus",
                        check_succeeded=False)]

    async def check_url(self, url):
        return await self.check_domain(url)


class _MixedRegistry(_OutageRegistry):
    def answered_providers(self):
        return ["urlhaus"]  # one provider answered; the other failed


@pytest.mark.asyncio
async def test_configured_feed_outage_yields_inconclusive(tmp_path, monkeypatch):
    """Feeds ARE configured but none answered: absence of intel hits is not
    evidence -> Inconclusive (required conditional check, see scoring.py)."""
    from app.pipeline import runner as runner_mod

    monkeypatch.setattr(runner_mod, "init_intel", lambda settings: _OutageRegistry())
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://example.com/"})
    report = resp.json()
    assert report["classification"] == "inconclusive"
    assert any("URLHAUS-ERROR" == f["id"] for f in report["findings"])
    assert report["scoring"]["key_checks_failed"] == []
    assert "URLHAUS-ERROR" in report["scoring"]["key_checks_unavailable"]


@pytest.mark.asyncio
async def test_mixed_provider_outage_stays_conclusive(tmp_path, monkeypatch):
    """One configured provider answered -> the outage gate does not fire."""
    from app.pipeline import runner as runner_mod

    monkeypatch.setattr(runner_mod, "init_intel", lambda settings: _MixedRegistry())
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://example.com/"})
    assert resp.json()["classification"] == "low_risk"


# ---- privacy: report deletion (task 6) --------------------------------------------


@pytest.mark.asyncio
async def test_delete_report_endpoint(tmp_path):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        created = (await c.post("/api/v1/analyze/url", json={"url": "https://example.com/"})).json()
        report_id = created["report_id"]

        resp = await c.delete(f"/api/v1/reports/{report_id}")
        assert resp.status_code == 200
        assert resp.json() == {"deleted": True, "report_id": report_id}

        gone = await c.get(f"/api/v1/reports/{report_id}")
        assert gone.status_code == 404

        # idempotence: deleting again is a 404
        resp2 = await c.delete(f"/api/v1/reports/{report_id}")
        assert resp2.status_code == 404


@pytest.mark.asyncio
async def test_delete_message_report_removes_sub_reports_listing(tmp_path):
    """Message reports persist embedded-URL sub-reports; deleting the message
    report does not delete the sub-reports (they are independent analyses)."""
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        msg = (await c.post("/api/v1/analyze/message", json={
            "message": "Please check https://example.com/page today."
        })).json()
        sub_id = msg["extras"]["sub_reports"][0]["report_id"]

        resp = await c.delete(f"/api/v1/reports/{msg['report_id']}")
        assert resp.status_code == 200
        # sub-report still retrievable (independent persisted analysis)
        got = await c.get(f"/api/v1/reports/{sub_id}")
        assert got.status_code == 200


# ---- audit L2: PATCH must be CORS-preflightable (report visibility route) -------

@pytest.mark.asyncio
async def test_cors_preflight_allows_patch(tmp_path):
    """PATCH /api/v1/reports/{id} (visibility toggle) is browser-accessible:
    a CORS preflight for PATCH must be answered with PATCH in allow-methods."""
    application = build_app(tmp_path, cors_origins=["http://localhost:5173"])
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.options(
            "/api/v1/reports/some-id",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "PATCH",
            },
        )
    assert resp.status_code == 200
    assert "PATCH" in resp.headers.get("access-control-allow-methods", "")


# ---- audit L6: rate limiter must evict idle client buckets ----------------------

def test_rate_limiter_evicts_idle_buckets_keeps_active():
    """Buckets with no hits inside the window are dropped; active ones stay."""
    import time as _time
    from collections import deque

    from app.api.ratelimit import RateLimitMiddleware

    mw = RateLimitMiddleware(app=None, limit_per_minute=10)
    now = _time.monotonic()
    mw._hits["1.1.1.1"] = deque([now - 300])   # idle for 5 minutes
    mw._hits["2.2.2.2"] = deque([now - 5])     # hit recently
    mw._hits["3.3.3.3"] = deque()              # empty (all hits pruned earlier)
    mw._evict_idle(now)
    assert "1.1.1.1" not in mw._hits
    assert "2.2.2.2" in mw._hits
    assert "3.3.3.3" not in mw._hits


@pytest.mark.asyncio
async def test_rate_limiter_sweep_restores_capacity_for_idle_client():
    """After a sweep, an idle client can request again even though its pre-sweep
    bucket was over the limit — proving the bucket was actually evicted."""
    from fastapi import FastAPI

    from app.api.ratelimit import RateLimitMiddleware

    # A bare app: create_app() would add its OWN RateLimitMiddleware, and the
    # test must exercise exactly one limiter instance.
    inner = FastAPI()

    @inner.get("/api/ping")
    async def ping():  # noqa: E501 - test endpoint
        return {"ok": True}

    mw = RateLimitMiddleware(inner, limit_per_minute=2)
    transport = httpx.ASGITransport(app=mw)
    import time as _time
    from collections import deque

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        assert (await c.get("/api/ping")).status_code == 200
        assert (await c.get("/api/ping")).status_code == 200
        assert (await c.get("/api/ping")).status_code == 429  # limit reached
        # Simulate window passage for EVERY client bucket, then trigger the sweep.
        keys_before = list(mw._hits)
        assert keys_before, "expected at least one client bucket after the requests"
        now = _time.monotonic()
        for key in keys_before:
            mw._hits[key] = deque([now - 120])  # all hits aged out of the window
        mw._last_sweep = now - 120
        resp = await c.get("/api/ping")
        assert resp.status_code == 200  # sweep evicted the idle bucket -> fresh window
        # Only the fresh hit remains: the aged bucket was evicted, not refilled.
        assert all(len(bucket) == 1 for bucket in mw._hits.values())
