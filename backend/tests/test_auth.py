"""Multi-tenant authentication & authorization tests.

Covers: password hashing, purpose-scoped JWTs, API-key auth, the auth_required
gate, ownership on analyze/list/get/delete/commit, public reports, the
auth-disabled demo-mode behaviour, and the hardened user lifecycle (seeded
admin bootstrap, registration gating, password reset, email verification).
"""
from __future__ import annotations

import base64
import json
import time

import httpx
import pytest

from app.api.auth import (
    create_access_token,
    create_purpose_token,
    decode_access_token,
    decode_purpose_token,
    generate_api_key,
    hash_api_key,
    hash_password,
    verify_password,
)
from app.config import Settings
from app.storage.seed import seed_initial_admin
from tests.conftest import make_settings
from tests.test_api import StubFetcher, build_app, good_fetch_result

_SECRET = "test-secret-with-at-least-32-bytes-length"


# ---- primitives -------------------------------------------------------------------


def test_password_hash_roundtrip():
    stored = hash_password("correct horse battery staple")
    assert stored.startswith("pbkdf2_sha256$")
    assert verify_password("correct horse battery staple", stored)
    assert not verify_password("wrong password", stored)
    # unique salts -> unique hashes
    assert hash_password("x") != hash_password("x")


def test_password_hash_rejects_malformed_stored_value():
    assert not verify_password("x", "not-a-valid-hash")
    assert not verify_password("x", "")


def test_jwt_roundtrip_and_expiry():
    settings = Settings(jwt_secret=_SECRET, access_token_expiry_minutes=5)
    token = create_access_token("user-123", settings)
    assert decode_access_token(token, settings) == "user-123"

    # wrong secret -> None
    assert decode_access_token(token, Settings(jwt_secret="other-secret-with-32-bytes-length!!")) is None

    # expired -> None
    expired_settings = Settings(jwt_secret=_SECRET, access_token_expiry_minutes=-1)
    expired = create_access_token("user-123", expired_settings)
    assert decode_access_token(expired, Settings(jwt_secret=_SECRET)) is None

    # tampered payload -> None
    header, payload, sig = token.split(".")
    forged_payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "victim", "purpose": "access", "exp": int(time.time()) + 3600}).encode()
    ).rstrip(b"=")
    assert decode_access_token(f"{header}.{forged_payload.decode()}.{sig}",
                               Settings(jwt_secret=_SECRET)) is None


def test_purpose_scoped_tokens_never_cross_domains():
    """A token minted for one purpose must not validate for another."""
    settings = Settings(jwt_secret=_SECRET)
    access = create_purpose_token("u1", settings, purpose="access", minutes=5)
    reset = create_purpose_token("u1", settings, purpose="password_reset", minutes=5)
    verify = create_purpose_token("u1", settings, purpose="email_verify", minutes=5)
    assert decode_purpose_token(access, settings, "access") == "u1"
    assert decode_purpose_token(reset, settings, "password_reset") == "u1"
    assert decode_purpose_token(verify, settings, "email_verify") == "u1"
    # cross-purpose usage is rejected
    assert decode_purpose_token(reset, settings, "access") is None
    assert decode_purpose_token(verify, settings, "password_reset") is None
    assert decode_purpose_token(access, settings, "email_verify") is None


def test_api_key_generation_and_hashing():
    key = generate_api_key()
    assert key.startswith("tl_") and len(key) > 40
    assert hash_api_key(key) != key
    assert hash_api_key(key) == hash_api_key(key)
    assert generate_api_key() != generate_api_key()


# ---- auth-disabled demo mode (default) --------------------------------------------


@pytest.mark.asyncio
async def test_demo_mode_unchanged(tmp_path):
    """auth_required=False (default): everything works without credentials and
    reports are visible to everyone — frictionless local/demo behaviour."""
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        created = (await c.post("/api/v1/analyze/url", json={"url": "https://example.com/"}))
        assert created.status_code == 200
        report = created.json()
        assert (await c.get(f"/api/v1/reports/{report['report_id']}")).status_code == 200
        assert (await c.get("/api/v1/reports")).json()["count"] >= 1
        assert (await c.delete(f"/api/v1/reports/{report['report_id']}")).status_code == 200
        me = (await c.get("/api/v1/auth/me")).json()
        assert me == {"authenticated": False, "mode": "auth_disabled"}


@pytest.mark.asyncio
async def test_demo_mode_invalid_credentials_still_rejected(tmp_path):
    """Presenting a BAD credential is a 401 even in demo mode (never silently
    treated as anonymous)."""
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.get("/api/v1/reports", headers={"X-API-Key": "tl_nope"})
        assert resp.status_code == 401


# ---- auth-enabled multi-tenant mode ------------------------------------------------


def _auth_app(tmp_path, **overrides):
    """Build an auth-enabled app with a fresh isolated database."""
    import app.storage.database as dbmod
    from app.main import create_app
    from app.storage.database import init_engine

    settings = make_settings(
        database_url=f"sqlite:///{tmp_path.as_posix()}/auth.db",
        auth_required=True,
        jwt_secret=_SECRET,
        initial_admin_email="admin@example.com",
        initial_admin_password="admin-password-1",
        allow_open_registration=True,
        **overrides,
    )
    dbmod._engine = None
    dbmod._SessionLocal = None
    application = create_app(settings)
    init_engine(settings)
    application.state.fetcher = StubFetcher(good_fetch_result())
    return application, settings


class AuthApp:
    """App with auth enabled + a SEEDED admin + two self-registered users.

    The admin comes from the seed hook (env-equivalent), never from the first
    registration. Open registration is enabled so the two regular users can
    self-register; the closed-registration behaviour is covered separately.
    """

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path

    async def __aenter__(self):
        self.application, self.settings = _auth_app(self.tmp_path)
        self.transport = httpx.ASGITransport(app=self.application)
        self.client = httpx.AsyncClient(transport=self.transport, base_url="http://test")
        await self.client.__aenter__()
        # seed the admin exactly as the lifespan would
        seed_initial_admin(self.settings)
        # admin logs in with the seeded password
        login = await self.client.post("/api/v1/auth/token", json={
            "email": "admin@example.com", "password": "admin-password-1"})
        self.admin = {"email": "admin@example.com", "role": "admin",
                      "access_token": login.json()["access_token"]}
        # two self-registered regular users (open registration)
        self.user = (await self.client.post("/api/v1/auth/register", json={
            "email": "user@example.com", "password": "user-password-1"})).json()
        self.other = (await self.client.post("/api/v1/auth/register", json={
            "email": "other@example.com", "password": "other-password-1"})).json()
        return self

    async def __aexit__(self, *exc):
        await self.client.__aexit__(*exc)

    def bearer(self, who):
        return {"Authorization": f"Bearer {who['access_token']}"}

    def api_key_headers(self, who):
        return {"X-API-Key": who["api_key"]}


@pytest.mark.asyncio
async def test_analyze_requires_credentials_when_auth_enabled(tmp_path):
    async with AuthApp(tmp_path) as app:
        resp = await app.client.post("/api/v1/analyze/url", json={"url": "https://example.com/"})
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "auth_required"


@pytest.mark.asyncio
async def test_analyze_attaches_owner_via_bearer_and_api_key(tmp_path):
    async with AuthApp(tmp_path) as app:
        r1 = await app.client.post("/api/v1/analyze/url", json={"url": "https://example.com/"},
                                   headers=app.bearer(app.user))
        assert r1.status_code == 200
        report = r1.json()

        # owner sees it in their list; the other user does not; admin sees all
        mine = (await app.client.get("/api/v1/reports", headers=app.bearer(app.user))).json()
        other = (await app.client.get("/api/v1/reports", headers=app.bearer(app.other))).json()
        admin = (await app.client.get("/api/v1/reports", headers=app.bearer(app.admin))).json()
        assert any(r["report_id"] == report["report_id"] for r in mine["reports"])
        assert not any(r["report_id"] == report["report_id"] for r in other["reports"])
        assert any(r["report_id"] == report["report_id"] for r in admin["reports"])

        # API-key path works too
        r2 = await app.client.post("/api/v1/analyze/url", json={"url": "https://example.com/two"},
                                   headers=app.api_key_headers(app.user))
        assert r2.status_code == 200
        mine2 = (await app.client.get("/api/v1/reports", headers=app.api_key_headers(app.user))).json()
        assert mine2["count"] == 2


@pytest.mark.asyncio
async def test_report_read_owner_or_public_others_get_404(tmp_path):
    async with AuthApp(tmp_path) as app:
        report = (await app.client.post("/api/v1/analyze/url", json={"url": "https://example.com/"},
                                        headers=app.bearer(app.user))).json()
        rid = report["report_id"]

        # owner can read
        assert (await app.client.get(f"/api/v1/reports/{rid}", headers=app.bearer(app.user))).status_code == 200
        # unrelated non-owner user: 404 (existence not leaked)
        resp = await app.client.get(f"/api/v1/reports/{rid}", headers=app.bearer(app.other))
        assert resp.status_code == 404
        # the admin sees everything (spec: "or return all for admins")
        assert (await app.client.get(f"/api/v1/reports/{rid}", headers=app.bearer(app.admin))).status_code == 200

        # making it public lets the unrelated user read it
        patch = await app.client.patch(f"/api/v1/reports/{rid}", json={"is_public": True},
                                       headers=app.bearer(app.user))
        assert patch.status_code == 200
        assert (await app.client.get(f"/api/v1/reports/{rid}", headers=app.bearer(app.other))).status_code == 200


@pytest.mark.asyncio
async def test_delete_and_commit_strict_ownership_403(tmp_path):
    async with AuthApp(tmp_path) as app:
        report = (await app.client.post("/api/v1/analyze/url", json={"url": "http://paypa1.com/"},
                                        headers=app.bearer(app.user))).json()
        rid = report["report_id"]

        # an unrelated user cannot delete or commit (403, even though public
        # read would be allowed)
        resp = await app.client.delete(f"/api/v1/reports/{rid}", headers=app.bearer(app.other))
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "forbidden"
        resp = await app.client.post(f"/api/v1/reports/{rid}/commit", headers=app.bearer(app.other))
        assert resp.status_code == 403

        # owner CAN delete
        assert (await app.client.delete(f"/api/v1/reports/{rid}",
                                        headers=app.bearer(app.user))).status_code == 200


@pytest.mark.asyncio
async def test_verify_endpoints_stay_public(tmp_path):
    async with AuthApp(tmp_path) as app:
        report = (await app.client.post("/api/v1/analyze/url", json={"url": "https://example.com/"},
                                        headers=app.bearer(app.user))).json()
        # no credentials at all: verification must work for third parties
        resp = await app.client.get(f"/api/v1/verify/{report['report_id']}")
        assert resp.status_code == 200
        assert resp.json()["integrity_match"] is True
        resp = await app.client.post("/api/v1/verify/report", json={"report": report})
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_login_flow_and_token_expiry_rejection(tmp_path):
    async with AuthApp(tmp_path) as app:
        login = await app.client.post("/api/v1/auth/token", json={
            "email": "user@example.com", "password": "user-password-1"})
        assert login.status_code == 200
        token = login.json()["access_token"]
        me = await app.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.json()["authenticated"] is True and me.json()["role"] == "user"

        bad = await app.client.post("/api/v1/auth/token", json={
            "email": "user@example.com", "password": "wrong-password"})
        assert bad.status_code == 401

        forged = {"Authorization": f"Bearer {token[:-4]}AAAA"}
        resp = await app.client.get("/api/v1/reports", headers=forged)
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_key_rotation_disables_old_key(tmp_path):
    async with AuthApp(tmp_path) as app:
        old_key = app.user["api_key"]
        rotate = await app.client.post("/api/v1/auth/api-key", json={"enable": True},
                                       headers=app.bearer(app.user))
        assert rotate.status_code == 200
        new_key = rotate.json()["api_key"]
        assert new_key != old_key
        assert (await app.client.get("/api/v1/reports",
                                     headers={"X-API-Key": old_key})).status_code == 401
        assert (await app.client.get("/api/v1/reports",
                                     headers={"X-API-Key": new_key})).status_code == 200


@pytest.mark.asyncio
async def test_duplicate_email_registration_conflict(tmp_path):
    async with AuthApp(tmp_path) as app:
        resp = await app.client.post("/api/v1/auth/register", json={
            "email": "user@example.com", "password": "whatever-123"})
        assert resp.status_code == 409


@pytest.mark.asyncio
async def test_message_report_sub_reports_inherit_owner(tmp_path):
    async with AuthApp(tmp_path) as app:
        msg = (await app.client.post("/api/v1/analyze/message", json={
            "message": "Please check https://example.com/page today."},
            headers=app.bearer(app.user))).json()
        sub_id = msg["extras"]["sub_reports"][0]["report_id"]
        assert (await app.client.get(f"/api/v1/reports/{sub_id}",
                                     headers=app.bearer(app.user))).status_code == 200
        assert (await app.client.get(f"/api/v1/reports/{sub_id}",
                                     headers=app.bearer(app.other))).status_code == 404


# ---- hardened bootstrap & user lifecycle ------------------------------------------


def test_seed_creates_admin_without_touching_existing(tmp_path):
    import app.storage.database as dbmod
    dbmod._engine = None
    dbmod._SessionLocal = None
    settings = Settings(database_url=f"sqlite:///{tmp_path.as_posix()}/seed.db",
                        initial_admin_email="root@example.com",
                        initial_admin_password="root-password-1")
    from app.storage.database import init_engine
    init_engine(settings)

    user = seed_initial_admin(settings)
    assert user is not None and user["role"] == "admin"
    assert user["email_verified"] is True  # bootstrapped from operator config

    # idempotent: existing account is left untouched (password not clobbered)
    assert seed_initial_admin(settings) is None
    user = _repo_user("root@example.com")
    assert verify_password("root-password-1", user["hashed_password"])


def _repo_user(email):
    from app.storage import repository
    return repository.get_user_by_email(email)


@pytest.mark.asyncio
async def test_registration_closed_without_open_registration(tmp_path):
    """auth_required + allow_open_registration=False (defaults): self-
    registration is 403; the seeded admin CAN create users; the bootstrap
    exception applies only when the user table is empty."""
    settings = make_settings(
        database_url=f"sqlite:///{tmp_path.as_posix()}/closed.db",
        auth_required=True, jwt_secret=_SECRET,
        initial_admin_email="root@example.com", initial_admin_password="root-password-1",
    )
    import app.storage.database as dbmod
    dbmod._engine = None
    dbmod._SessionLocal = None
    from app.main import create_app
    from app.storage.database import init_engine
    application = create_app(settings)
    init_engine(settings)
    application.state.fetcher = StubFetcher(good_fetch_result())
    seed_initial_admin(settings)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        # anonymous registration -> closed
        resp = await c.post("/api/v1/auth/register", json={
            "email": "alice@example.com", "password": "alice-password-1"})
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "registration_closed"

        # the seeded admin CAN register a user (role user, never auto-admin)
        login = await c.post("/api/v1/auth/token", json={
            "email": "root@example.com", "password": "root-password-1"})
        admin_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        resp = await c.post("/api/v1/auth/register", json={
            "email": "bob@example.com", "password": "bob-password-123"},
            headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["role"] == "user"


@pytest.mark.asyncio
async def test_bootstrap_registration_allowed_on_empty_user_table(tmp_path):
    """A fresh auth-enabled deployment with no seeded admin and closed
    registration still allows ONE registration (role user) — no deadlock."""
    settings = make_settings(
        database_url=f"sqlite:///{tmp_path.as_posix()}/bootstrap.db",
        auth_required=True, jwt_secret=_SECRET,
    )
    import app.storage.database as dbmod
    dbmod._engine = None
    dbmod._SessionLocal = None
    from app.main import create_app
    from app.storage.database import init_engine
    application = create_app(settings)
    init_engine(settings)
    application.state.fetcher = StubFetcher(good_fetch_result())
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        first = await c.post("/api/v1/auth/register", json={
            "email": "first@example.com", "password": "first-password-1"})
        assert first.status_code == 200
        assert first.json()["role"] == "user"  # NEVER auto-admin
        # the table is no longer empty: the next registration is closed
        second = await c.post("/api/v1/auth/register", json={
            "email": "second@example.com", "password": "second-password-1"})
        assert second.status_code == 403


@pytest.mark.asyncio
async def test_password_reset_flow(tmp_path):
    async with AuthApp(tmp_path) as app:
        req = await app.client.post("/api/v1/auth/password-reset/request", json={
            "email": "user@example.com"})
        assert req.status_code == 200 and req.json()["sent"] is True
        reset_token = req.json().get("reset_token")
        assert reset_token, "dev mode must surface the stub reset token"

        confirm = await app.client.post("/api/v1/auth/password-reset/confirm", json={
            "token": reset_token, "new_password": "brand-new-password-1"})
        assert confirm.status_code == 200

        old = await app.client.post("/api/v1/auth/token", json={
            "email": "user@example.com", "password": "user-password-1"})
        assert old.status_code == 401
        new = await app.client.post("/api/v1/auth/token", json={
            "email": "user@example.com", "password": "brand-new-password-1"})
        assert new.status_code == 200

        # unknown email -> same response shape (no enumeration)
        unknown = await app.client.post("/api/v1/auth/password-reset/request", json={
            "email": "ghost@example.com"})
        assert unknown.status_code == 200 and unknown.json()["sent"] is True
        assert "reset_token" not in unknown.json()


@pytest.mark.asyncio
async def test_email_verification_flow(tmp_path):
    async with AuthApp(tmp_path) as app:
        registered = (await app.client.post("/api/v1/auth/register", json={
            "email": "verify@example.com", "password": "verify-password-1"})).json()
        assert registered.get("verification_token")
        me = await app.client.get("/api/v1/auth/me", headers=app.bearer(registered))
        assert me.json()["email_verified"] is False

        verified = await app.client.post("/api/v1/auth/verify-email", json={
            "token": registered["verification_token"]})
        assert verified.status_code == 200 and verified.json() == {"verified": True}

        me = await app.client.get("/api/v1/auth/me", headers=app.bearer(registered))
        assert me.json()["email_verified"] is True

        # an ACCESS token must not work as a verification token (purpose scoping)
        wrong = await app.client.post("/api/v1/auth/verify-email", json={
            "token": registered["access_token"]})
        assert wrong.status_code == 400


def test_settings_auth_defaults():
    s = Settings()
    assert s.auth_required is False
    assert s.access_token_expiry_minutes == 480
    assert s.allow_open_registration is False
    assert s.initial_admin_email == "" and s.initial_admin_password == ""
    assert s.vt_submit_max_per_hour == 10
