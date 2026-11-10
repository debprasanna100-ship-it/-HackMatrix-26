"""Configuration-loading and provider-status regression tests.

Regression context: Settings used a CWD-relative env_file=".env", so a server
launched anywhere other than backend/ silently loaded NO provider keys, and a
long-running server kept its startup-time settings after backend/.env edits.
These tests pin the fixed behaviour (absolute env_file derived from the config
module's location, env-var precedence, provider->adapter mapping, opt-in
OpenPhish, and status reporting that never exposes key material).

Everything here is hermetic: dummy dotenv values in tmp_path, no real
backend/.env is read, and no network request is issued.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import httpx
import pytest

import app.config as app_config
from app.config import ENV_FILE, Settings
from app.main import create_app
from app.pipeline.intel import IntelRegistry, OpenPhish
from app.storage.database import init_engine
from tests.conftest import make_settings

PROVIDER_FIELDS = {
    "google_safe_browsing": "google_safe_browsing_api_key",
    "urlhaus": "urlhaus_api_key",
    "openphish": "openphish_api_key",
    "phishtank": "phishtank_api_key",
    "virustotal": "virustotal_api_key",
}
VALID_STATUSES = {"active", "unconfigured", "failed", "rate_limited"}


def scrub_trustlens_env(monkeypatch) -> None:
    """Remove inherited TRUSTLENS_* process variables so assertions only see
    the dotenv values under test."""
    for name in list(os.environ):
        if name.startswith("TRUSTLENS_"):
            monkeypatch.delenv(name, raising=False)


def write_env(tmp_path: Path, body: str) -> str:
    env = tmp_path / ".env"
    env.write_text(body, encoding="utf-8")
    return str(env)


def env_line(field: str, value: str) -> str:
    """Full env var line with the settings prefix: field -> TRUSTLENS_FIELD=value."""
    return f"TRUSTLENS_{field.upper()}={value}\n"


def test_default_env_file_is_absolute_and_points_at_backend_dotenv():
    # The CWD-bug fix: the default dotenv must be an absolute path derived
    # from the config module's own location (backend/.env), never relative to
    # whatever directory uvicorn was started from.
    assert ENV_FILE.is_absolute()
    assert ENV_FILE.name == ".env"
    assert ENV_FILE.parent == Path(app_config.__file__).resolve().parent.parent


def test_settings_load_env_file_from_any_launch_directory(tmp_path, monkeypatch):
    """Launching from the repository root, from backend/, or anywhere else all
    load the same dotenv file (simulated with the real default env_file value
    swapped for a dummy absolute path — the real backend/.env is never read)."""
    scrub_trustlens_env(monkeypatch)
    dummy = write_env(tmp_path, 'TRUSTLENS_URLHAUS_API_KEY="dummy-urlhaus-key"\n')
    backend_dir = Path(app_config.__file__).resolve().parent.parent
    repo_root = backend_dir.parent
    cfg = dict(Settings.model_config)
    cfg["env_file"] = dummy  # same absolute-path mechanism as the fixed default
    monkeypatch.setattr(Settings, "model_config", cfg)

    for cwd in (repo_root, backend_dir, tmp_path):
        monkeypatch.chdir(cwd)
        s = Settings()
        assert s.urlhaus_api_key == "dummy-urlhaus-key", f"cwd={cwd}"


def test_settings_load_explicit_env_file_regardless_of_cwd(tmp_path, monkeypatch):
    scrub_trustlens_env(monkeypatch)
    path = write_env(tmp_path, "TRUSTLENS_OPENPHISH_API_KEY=dummy-optin\n")
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)
    assert Settings(_env_file=path).openphish_api_key == "dummy-optin"


def test_process_env_overrides_env_file(tmp_path, monkeypatch):
    scrub_trustlens_env(monkeypatch)
    path = write_env(tmp_path, "TRUSTLENS_VIRUSTOTAL_API_KEY=dummy-from-file\n")
    monkeypatch.setenv("TRUSTLENS_VIRUSTOTAL_API_KEY", "dummy-from-env")
    assert Settings(_env_file=path).virustotal_api_key == "dummy-from-env"
    monkeypatch.delenv("TRUSTLENS_VIRUSTOTAL_API_KEY")
    assert Settings(_env_file=path).virustotal_api_key == "dummy-from-file"


def test_provider_settings_map_to_the_correct_adapters(tmp_path, monkeypatch):
    scrub_trustlens_env(monkeypatch)
    body = "".join(
        env_line(field, f"dummy-{field}") for field in PROVIDER_FIELDS.values()
    )
    settings = Settings(_env_file=write_env(tmp_path, body))
    registry = IntelRegistry(settings)
    for name, field in PROVIDER_FIELDS.items():
        assert registry._keys[name] == f"dummy-{field}"
    status = registry.status()
    assert set(status) == set(PROVIDER_FIELDS)
    assert all(state == "active" for state in status.values())


def test_missing_and_blank_values_report_unconfigured(tmp_path, monkeypatch):
    scrub_trustlens_env(monkeypatch)
    body = "TRUSTLENS_URLHAUS_API_KEY=\nTRUSTLENS_VIRUSTOTAL_API_KEY=dummy-vt\n"
    settings = Settings(_env_file=write_env(tmp_path, body))
    status = IntelRegistry(settings).status()
    assert status["urlhaus"] == "unconfigured"    # present but blank
    assert status["phishtank"] == "unconfigured"  # absent entirely
    assert status["virustotal"] == "active"


def test_unconfigured_findings_name_the_env_var_never_the_value(tmp_path, monkeypatch):
    scrub_trustlens_env(monkeypatch)
    settings = Settings(_env_file=write_env(tmp_path, ""))  # no keys at all
    registry = IntelRegistry(settings)
    findings = asyncio.run(registry.check_url("https://unconfigured.example/"))
    by_provider = {f.source.rsplit("/", 1)[-1]: f for f in findings}
    assert set(by_provider) == set(PROVIDER_FIELDS)
    for name, finding in by_provider.items():
        assert finding.check_succeeded is False
        assert finding.evidence == [f"{name} requires TRUSTLENS_{name.upper()}_API_KEY"]
        assert "dummy" not in json.dumps(finding.model_dump(mode="json")).lower()


def test_openphish_setting_is_an_opt_in_switch_not_a_credential(tmp_path, monkeypatch):
    scrub_trustlens_env(monkeypatch)
    # Any non-empty value opts in; the value itself is never sent anywhere.
    for opt_in_value in ("community", "junk-value"):
        path = write_env(tmp_path, f"TRUSTLENS_OPENPHISH_API_KEY={opt_in_value}\n")
        registry = IntelRegistry(Settings(_env_file=path))
        assert registry.status()["openphish"] == "active"
    # The adapter targets the official keyless feed: no query string, no
    # credentials in the URL, and the opt-in value appears nowhere in it.
    assert OpenPhish.FEED_URL == "https://feed.openphish.com/v3/feed.txt"
    assert "?" not in OpenPhish.FEED_URL and "@" not in OpenPhish.FEED_URL
    assert opt_in_value not in OpenPhish.FEED_URL
    # A check runs without transmitting any key material (feed pre-stubbed so
    # no request is issued at all).
    monkeypatch.setattr(OpenPhish, "_load_feed", lambda self: True)
    monkeypatch.setattr(OpenPhish, "_feed_urls", {"https://phished.example"})
    adapter = OpenPhish("dummy-optin", None)
    # OpenPhish.check_url is synchronous; the registry dispatches it via
    # asyncio.to_thread.
    hits = adapter.check_url("https://phished.example/")
    assert len(hits) == 1 and hits[0].check_succeeded is True


def test_status_and_meta_never_expose_secret_values(tmp_path, monkeypatch):
    scrub_trustlens_env(monkeypatch)
    canaries = {field: f"CANARY-SECRET-{field}" for field in PROVIDER_FIELDS.values()}
    body = "".join(env_line(field, value) for field, value in canaries.items())
    settings = Settings(_env_file=write_env(tmp_path, body))
    registry = IntelRegistry(settings)

    status = registry.status()
    assert set(status.values()) <= VALID_STATUSES
    status_blob = json.dumps(status)
    for value in canaries.values():
        assert value not in status_blob

    # The /api/v1/meta diagnostic reports the same statuses, never values,
    # and performs no provider network requests.
    import app.storage.database as dbmod

    dbmod._engine = None
    dbmod._SessionLocal = None
    application = create_app(make_settings(
        database_url=f"sqlite:///{tmp_path.as_posix()}/intel-status-test.db",
        **canaries,
    ))
    init_engine(application.state.settings)

    async def fetch_meta() -> httpx.Response:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            return await c.get("/api/v1/meta")

    resp = asyncio.run(fetch_meta())
    assert resp.status_code == 200
    meta = resp.json()
    assert set(meta["intel_providers"]) == set(PROVIDER_FIELDS)
    assert set(meta["intel_providers"].values()) <= VALID_STATUSES
    assert all(state == "active" for state in meta["intel_providers"].values())
    for value in canaries.values():
        assert value not in resp.text


def test_meta_reports_unconfigured_providers_without_keys(tmp_path, monkeypatch):
    scrub_trustlens_env(monkeypatch)
    dbmod = __import__("app.storage.database", fromlist=["_engine"])
    dbmod._engine = None
    dbmod._SessionLocal = None
    application = create_app(make_settings(
        database_url=f"sqlite:///{tmp_path.as_posix()}/intel-status-empty.db",
        phishtank_api_key="",
    ))
    init_engine(application.state.settings)

    async def fetch_meta() -> httpx.Response:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            return await c.get("/api/v1/meta")

    meta = asyncio.run(fetch_meta()).json()
    providers = meta["intel_providers"]
    assert providers["phishtank"] == "unconfigured"
    assert set(providers.values()) <= VALID_STATUSES


# ---- audit C3: meta must report the EFFECTIVE registry address ------------------


def test_meta_reports_effective_registry_address_from_deployment_file(tmp_path):
    """Audit C3: when TRUSTLENS_REGISTRY_ADDRESS is empty but the deployment
    JSON supplies the address (compose wiring), /api/v1/meta must show the
    effective address instead of 'configured at ' with an empty value."""
    import json as _json

    import app.storage.database as dbmod

    dep = tmp_path / "deployment.localhost.json"
    address = "0x" + "ab" * 20
    dep.write_text(_json.dumps({"contract": "ThreatRegistry", "address": address}),
                   encoding="utf-8")
    dbmod._engine = None
    dbmod._SessionLocal = None
    application = create_app(make_settings(
        database_url=f"sqlite:///{tmp_path.as_posix()}/meta-registry-test.db",
        registry_address="",
        deployment_file=str(dep),
    ))
    init_engine(application.state.settings)

    async def fetch_meta() -> httpx.Response:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            return await c.get("/api/v1/meta")

    meta = asyncio.run(fetch_meta()).json()
    assert meta["integrations"]["web3_registry"] == f"configured at {address}"
