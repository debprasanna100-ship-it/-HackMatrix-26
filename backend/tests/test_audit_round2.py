"""Regression tests for the 2026-11-09 audit-fix round (findings M-A … L-K).

Every test pins a defect that a previous audit round identified and this
round fixed; each names its finding ID. All network/chain boundaries are
stubbed — the suite stays hermetic.
"""
from __future__ import annotations

import asyncio
import ipaddress

import httpx
import pytest

from app.models.enums import FindingCategory, Severity
from app.models.schemas import Finding
from tests.conftest import make_settings
from tests.test_api import StubFetcher, build_app, good_fetch_result

_SECRET = "test-secret-with-at-least-32-bytes-length"


# ---- shared stubs ------------------------------------------------------------------


class SequencedIntelRegistry:
    """Intel registry stub handing out a queued list of findings per check_url
    call (so two embedded URLs can produce same-id/different-strength
    findings), with canned domain findings for every call."""

    def __init__(self, url_findings_per_call=None, domain_findings=None,
                 domain_delay: float = 0.0, url_delay: float = 0.0):
        self.url_queue = [list(x) for x in (url_findings_per_call or [])]
        self.domain_findings = list(domain_findings or [])
        self.domain_delay = domain_delay
        self.url_delay = url_delay
        self._answered: set[str] = set()

    async def check_domain(self, domain: str):
        await asyncio.sleep(self.domain_delay)
        self._answered.add("stub")
        return list(self.domain_findings)

    async def check_url(self, url: str):
        await asyncio.sleep(self.url_delay)
        self._answered.add("stub")
        return self.url_queue.pop(0) if self.url_queue else []

    def status(self) -> dict:
        return {"stub": "active"}

    def answered_providers(self) -> list[str]:
        return sorted(self._answered)


def _vt_match(target: str, positives: int) -> Finding:
    """Mimic the real VT v3 evidence shape: target line first, then the
    positives counter the scoring engine's authority rule parses."""
    return Finding(
        id="VT-MATCH", title="VirusTotal flags this URL",
        severity=Severity.HIGH, category=FindingCategory.INTEL,
        evidence=[f"target={target}", f"positives={positives}/93", "malicious=9"],
        source="trustlens/intel/virustotal", check_succeeded=True,
    )


def _client(application):
    transport = httpx.ASGITransport(app=application)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


# ---- M-A: message dedup must not drop a stronger same-id finding -------------------


@pytest.mark.asyncio
async def test_message_dedup_keeps_stronger_same_id_finding(tmp_path, monkeypatch):
    """Audit M-A: URL A produces VT-MATCH positives=3 (same id, NOT
    authoritative) BEFORE URL B's VT-MATCH positives=9 (authoritative).
    Deduplicating by id alone dropped B before scoring and dampened
    confirmed_malicious to high_risk; keying on (id, evidence) keeps both."""
    fake = SequencedIntelRegistry(url_findings_per_call=[
        [_vt_match("https://example.com/a", 3)],
        [_vt_match("https://example.org/b", 9)],
    ])
    monkeypatch.setattr("app.pipeline.message.init_intel", lambda settings: fake)
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    async with _client(application) as c:
        resp = await c.post("/api/v1/analyze/message", json={
            "message": "Verify https://example.com/a and https://example.org/b "
                       "immediately, your account depends on it."
        })
    assert resp.status_code == 200
    report = resp.json()

    vt_findings = [f for f in report["findings"] if f["id"] == "VT-MATCH"]
    assert len(vt_findings) == 2, "both same-id findings must survive the dedup"
    assert any("positives=9" in e for f in vt_findings for e in f["evidence"])

    # The authoritative hit from URL B now drives the verdict.
    assert report["classification"] == "confirmed_malicious"
    assert report["scoring"]["authoritative_hits"] == 1
    assert report["threat_intel"]["authoritative_hits"] == ["VT-MATCH"]
    assert report["threat_intel"]["total_findings"] == 2


@pytest.mark.asyncio
async def test_message_dedup_still_collapses_identical_evidence(tmp_path, monkeypatch):
    """The other half of M-A: identical (id, evidence) findings from two
    sub-reports still collapse, so scores don't multiply-count duplicates.
    The two embedded URLs differ; the intel stub answers BOTH with the exact
    same finding (id + evidence), mirroring e.g. two links on the same domain
    hitting the same feed row."""
    fake = SequencedIntelRegistry(url_findings_per_call=[
        [_vt_match("https://example.com/same", 9)],
        [_vt_match("https://example.com/same", 9)],
    ])
    monkeypatch.setattr("app.pipeline.message.init_intel", lambda settings: fake)
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    async with _client(application) as c:
        resp = await c.post("/api/v1/analyze/message", json={
            "message": "Open https://example.com/same and https://example.org/same "
                       "now, urgently."
        })
    report = resp.json()
    assert len([f for f in report["findings"] if f["id"] == "VT-MATCH"]) == 1
    assert report["threat_intel"]["total_findings"] == 1
    assert report["classification"] == "confirmed_malicious"


# ---- L-A: the intel note reflects the ACTUAL provider statuses ---------------------


@pytest.mark.asyncio
async def test_intel_note_reports_unconfigured_providers(tmp_path):
    """Audit L-A: the note must never claim providers are 'unavailable in this
    build by default' when the providers dict right next to it says otherwise."""
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    async with _client(application) as c:
        resp = await c.post("/api/v1/analyze/message", json={
            "message": "Plain message, nothing suspicious here at all."
        })
    tsum = resp.json()["threat_intel"]
    assert set(tsum["providers"].values()) == {"unconfigured"}
    assert "Absence of intel hits is not proof of safety." in tsum["note"]
    assert "no API key configured for:" in tsum["note"]
    assert "unavailable in this build" not in tsum["note"]


@pytest.mark.asyncio
async def test_intel_note_reports_operational_providers(tmp_path, monkeypatch):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    monkeypatch.setattr("app.pipeline.message.init_intel",
                        lambda settings: SequencedIntelRegistry())
    async with _client(application) as c:
        resp = await c.post("/api/v1/analyze/message", json={
            "message": "Plain message, nothing suspicious here at all."
        })
    note = resp.json()["threat_intel"]["note"]
    assert note == ("Absence of intel hits is not proof of safety. All 1 configured "
                    "providers were operational during this analysis.")


# ---- L-B: message fetch.success is truthful when every fetch failed ----------------


@pytest.mark.asyncio
async def test_message_fetch_summary_false_when_every_fetch_failed(
        tmp_path, monkeypatch):
    """Audit L-B: a message whose embedded URLs all fail to fetch must not
    report fetch.success=True (the verdict gate was already correct; the
    persisted summary lied)."""

    class AlwaysFailingFetcher(StubFetcher):
        async def fetch(self, norm):
            result = await super().fetch(norm)
            return result.model_copy(update={
                "success": False, "ok": False, "status_code": None, "final_url": None,
            })

    monkeypatch.setattr("app.pipeline.message.init_intel",
                        lambda settings: SequencedIntelRegistry())
    application = build_app(tmp_path, fetcher=AlwaysFailingFetcher(good_fetch_result()))
    async with _client(application) as c:
        resp = await c.post("/api/v1/analyze/message", json={
            "message": "Check https://example.com/x and https://example.org/y "
                       "right now, urgent verification needed."
        })
    report = resp.json()
    assert report["extras"]["sub_reports"], "sub-reports exist (fetches attempted)"
    assert report["fetch"]["success"] is False
    assert report["classification"] == "inconclusive"  # every embedded fetch failed


# ---- L-C: a budget-expired intel stage is not "completed" coverage -----------------


@pytest.mark.asyncio
async def test_intel_budget_expiry_is_failed_coverage_not_completed(tmp_path, monkeypatch):
    """Audit L-C: when the intel stage is cancelled by its budget it must not
    appear in coverage.completed_checks, and the provider rows must reflect
    the post-call (not pre-call) statuses."""
    fake = SequencedIntelRegistry(domain_delay=5.0)  # far beyond the budget
    monkeypatch.setattr("app.pipeline.runner.init_intel", lambda settings: fake)
    settings = make_settings(intel_budget_seconds=0.1)
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()),
                            intel_budget_seconds=0.1)
    async with _client(application) as c:
        resp = await c.post("/api/v1/analyze/url", json={"url": "https://example.com/"})
    report = resp.json()
    ids = {f["id"] for f in report["findings"]}
    assert "INTEL-BUDGET-EXCEEDED" in ids
    assert "threat-intel" not in report["coverage"]["completed_checks"]
    assert any("budget" in u for u in report["coverage"]["unavailable_checks"])


# ---- M-B: the documented seed CLI actually works -----------------------------------


def test_seed_cli_creates_admin_and_mints_reset_token(tmp_path, monkeypatch, capsys):
    """Audit M-B: `python -m app.storage.seed` crashed with 'call init_engine()
    first' whenever admin credentials were configured — the CLI ran outside
    the app lifespan. Both documented entry points must work end-to-end."""
    import app.storage.database as dbmod
    from app.storage import repository
    from app.storage.seed import main as seed_main

    dbmod._engine = None
    dbmod._SessionLocal = None
    db_file = tmp_path.as_posix() + "/seed-cli.db"
    monkeypatch.setenv("TRUSTLENS_DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("TRUSTLENS_INITIAL_ADMIN_EMAIL", "root@example.com")
    monkeypatch.setenv("TRUSTLENS_INITIAL_ADMIN_PASSWORD", "root-password-1")
    # Pin a JWT secret via env (env vars beat backend/.env in pydantic-settings)
    # so the minted reset token is deterministically decodable in this process.
    monkeypatch.setenv("TRUSTLENS_JWT_SECRET", _SECRET)

    assert seed_main([]) == 0
    assert "Admin created: root@example.com" in capsys.readouterr().out
    admin = repository.get_user_by_email("root@example.com")
    assert admin is not None and admin["role"] == "admin"

    # Idempotent second run leaves the account untouched.
    assert seed_main([]) == 0
    assert "already exists" in capsys.readouterr().out

    # The operator reset-token entry point mints a VALID password-reset token.
    assert seed_main(["--reset-token", "root@example.com"]) == 0
    token = capsys.readouterr().out.strip()
    from app.api.auth import decode_purpose_token
    from app.config import Settings
    assert decode_purpose_token(token, Settings(jwt_secret=_SECRET),
                                "password_reset") == admin["id"]


# ---- M-C: closed registration must not leak email existence ------------------------


@pytest.mark.asyncio
async def test_closed_registration_does_not_reveal_known_emails(tmp_path):
    """Audit M-C: the duplicate-email 409 used to run BEFORE the
    registration_closed 403, so anonymous callers could enumerate registered
    addresses on closed deployments (409 vs 403). The policy check now runs
    first: known and unknown emails are indistinguishable."""
    import app.storage.database as dbmod
    from app.main import create_app
    from app.storage.database import init_engine
    from app.storage.seed import seed_initial_admin

    settings = make_settings(
        database_url=f"sqlite:///{tmp_path.as_posix()}/closed2.db",
        auth_required=True, jwt_secret=_SECRET,
        initial_admin_email="root@example.com", initial_admin_password="root-password-1",
    )
    dbmod._engine = None
    dbmod._SessionLocal = None
    application = create_app(settings)
    init_engine(settings)
    application.state.fetcher = StubFetcher(good_fetch_result())
    seed_initial_admin(settings)
    async with _client(application) as c:
        for email in ("root@example.com", "ghost@example.com"):  # known, unknown
            resp = await c.post("/api/v1/auth/register", json={
                "email": email, "password": "whatever-password-1"})
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "registration_closed"


@pytest.mark.asyncio
async def test_open_registration_still_answers_409_for_duplicates(tmp_path):
    """In demo mode (registration open) the duplicate check still answers 409."""
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    async with _client(application) as c:
        first = await c.post("/api/v1/auth/register", json={
            "email": "dup@example.com", "password": "dup-password-1"})
        assert first.status_code == 200
        second = await c.post("/api/v1/auth/register", json={
            "email": "dup@example.com", "password": "dup-password-2"})
        assert second.status_code == 409
        assert second.json()["error"]["code"] == "email_taken"


# ---- M-D: correlation lookups are visibility-scoped in multi-tenant mode -----------


async def _auth_app_with_users(tmp_path):
    """Auth-enabled app + two registered users (fresh isolated DB)."""
    import app.storage.database as dbmod
    from app.main import create_app
    from app.storage.database import init_engine

    settings = make_settings(
        database_url=f"sqlite:///{tmp_path.as_posix()}/corr.db",
        auth_required=True, jwt_secret=_SECRET,
        initial_admin_email="admin@example.com",
        initial_admin_password="admin-password-1",
        allow_open_registration=True,
    )
    dbmod._engine = None
    dbmod._SessionLocal = None
    application = create_app(settings)
    init_engine(settings)
    application.state.fetcher = StubFetcher(good_fetch_result())
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=application),
                               base_url="http://test")
    await client.__aenter__()

    tokens: dict[str, str] = {}
    for name in ("alice", "bob"):
        resp = await client.post("/api/v1/auth/register", json={
            "email": f"{name}@example.com", "password": f"{name}-password-1"})
        assert resp.status_code == 200, resp.text
        tokens[name] = resp.json()["access_token"]
    headers = {name: {"Authorization": f"Bearer {tok}"} for name, tok in tokens.items()}
    return application, settings, client, headers


@pytest.mark.asyncio
async def test_correlate_hides_foreign_private_reports(tmp_path, monkeypatch):
    """Audit M-D: the indicator/text lookups behind /correlate (and the
    analysis-time snapshot) scan shared tables. Without a visibility scope,
    any authenticated user could harvest foreign private report IDs — the
    capability addresses that gate anonymous reads — plus classifications."""
    monkeypatch.setattr("app.pipeline.runner.init_intel",
                        lambda settings: SequencedIntelRegistry())
    monkeypatch.setattr("app.pipeline.message.init_intel",
                        lambda settings: SequencedIntelRegistry())
    application, settings, c, headers = await _auth_app_with_users(tmp_path)
    try:
        # Both users analyse the SAME domain → shared correlation indicator.
        ra = await c.post("/api/v1/analyze/url", json={"url": "https://example.com/alice"},
                          headers=headers["alice"])
        rb = await c.post("/api/v1/analyze/url", json={"url": "https://example.com/bob"},
                          headers=headers["bob"])
        assert ra.status_code == 200 and rb.status_code == 200
        report_a, report_b = ra.json(), rb.json()

        # B's persisted correlation snapshot must NOT name A's private report.
        b_corr = report_b["extras"]["correlation"]
        assert report_a["report_id"] not in str(b_corr)
        assert not b_corr["shared_indicators"]

        # The endpoint must not leak it either.
        corr_b = (await c.get(f"/api/v1/correlate/{report_b['report_id']}",
                              headers=headers["bob"])).json()
        assert report_a["report_id"] not in str(corr_b)

        # A's OWN report does see B's report through the same indicator —
        # until that is, B's report is private and A is foreign...
        corr_a = (await c.get(f"/api/v1/correlate/{report_a['report_id']}",
                              headers=headers["alice"])).json()
        assert report_b["report_id"] not in str(corr_a), \
            "foreign PRIVATE reports must be invisible to correlation"

        # ...but once B makes the report public, it becomes correlatable.
        patch = await c.patch(f"/api/v1/reports/{report_b['report_id']}",
                              json={"is_public": True}, headers=headers["bob"])
        assert patch.status_code == 200
        corr_a2 = (await c.get(f"/api/v1/correlate/{report_a['report_id']}",
                               headers=headers["alice"])).json()
        assert report_b["report_id"] in str(corr_a2)
    finally:
        await c.aclose()


# ---- M-E: proxy-mode rate limiting keys on the RIGHTMOST XFF entry -----------------


def test_rate_limiter_uses_rightmost_forwarded_for_entry():
    """Audit M-E: a trusted proxy APPENDS the real client IP; the leftmost
    entry is client-controlled, so keying on it let clients rotate buckets."""
    from app.api.ratelimit import RateLimitMiddleware

    proxy_mw = RateLimitMiddleware(app=None, limit_per_minute=10, trust_proxy=True)
    spoofed = type("R", (), {"headers": {"x-forwarded-for": "6.6.6.6, 10.0.0.9"},
                             "client": None})()
    assert proxy_mw._client_ip(spoofed) == "10.0.0.9"

    direct_mw = RateLimitMiddleware(app=None, limit_per_minute=10, trust_proxy=False)
    assert direct_mw._client_ip(spoofed) == "unknown"  # header ignored without trust
    direct = type("R", (), {"headers": {}, "client": type("C", (), {"host": "8.8.8.8"})()})()
    assert direct_mw._client_ip(direct) == "8.8.8.8"


# ---- L-K: SSRF range additions ------------------------------------------------------


def test_ssrf_blocks_ipv4_compatible_and_6to4_relay_ranges():
    """Audit L-K: the deprecated IPv4-compatible IPv6 form (::a.b.c.d, inside
    the reserved ::/8) and the deprecated 6to4 relay-anycast prefix must be
    blocked; mapped/public addresses are unaffected."""
    from app.pipeline.ssrf import classify_ip

    assert classify_ip(ipaddress.ip_address("::7f00:1")) is not None
    assert classify_ip(ipaddress.ip_address("::1")) is not None
    assert classify_ip(ipaddress.ip_address("192.88.99.1")) is not None
    # unchanged behaviour
    assert classify_ip(ipaddress.ip_address("::ffff:8.8.8.8")) is None  # unwrap → public
    assert classify_ip(ipaddress.ip_address("2606:4700:4700::1111")) is None
    assert classify_ip(ipaddress.ip_address("8.8.8.8")) is None
