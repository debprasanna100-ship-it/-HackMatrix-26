"""Application settings, loaded from environment variables (TRUSTLENS_* prefix)."""
from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/.env is resolved from THIS module's location, not the process working
# directory: a relative env_file=".env" only resolves when uvicorn happens to be
# launched from backend/ itself and is silently missed on any other launch
# (e.g. from the repository root). Process environment variables still take
# precedence over the file (pydantic-settings source order), so deployment
# overrides behave exactly as before. If the file does not exist, it is skipped.
BACKEND_DIR = Path(__file__).resolve().parent.parent
ENV_FILE: Path = BACKEND_DIR / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TRUSTLENS_",
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "TrustLens"
    version: str = "0.1.0"
    environment: str = "development"  # development | production

    # Storage: PostgreSQL in production, SQLite for local dev (default).
    # Example Postgres URL: postgresql+psycopg://trustlens:secret@localhost:5432/trustlens
    database_url: str = "sqlite:///./trustlens.db"

    # CORS origins for the frontend dev server (JSON list when set via env).
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Simple in-process sliding-window rate limit (requests/minute per client IP
    # on /api/* routes). Redis-backed limiting is a later-phase upgrade.
    rate_limit_per_minute: int = 10
    trust_proxy_headers: bool = False  # only enable behind a trusted reverse proxy

    # Safe-fetch pipeline limits.
    fetch_max_redirects: int = 5
    fetch_connect_timeout: float = 5.0
    fetch_read_timeout: float = 10.0
    fetch_total_budget: float = 40.0  # seconds for the whole redirect chain
    fetch_max_bytes: int = 1_000_000  # cap on bytes read of any single response

    # Only these ports may be requested; anything else is refused by policy.
    allowed_fetch_ports: list[int] = [80, 443]

    # --- Threat-intel provider keys (Phase 2+). Empty = provider unconfigured:
    # it is reported as UNAVAILABLE (never as "clean") and never contacted. ---
    google_safe_browsing_api_key: str = ""
    urlhaus_api_key: str = ""
    openphish_api_key: str = ""
    phishtank_api_key: str = ""
    virustotal_api_key: str = ""

    # --- Web3 threat registry (Phase 4) ---
    # Local Hardhat node by default; Sepolia optional. Chain features activate
    # only when registry_address is set (and chain_enabled is true).
    # Reads CONTRACTS_URL when deployed with Vercel service bindings.
    chain_rpc_url: str = os.getenv("CONTRACTS_URL") or "http://127.0.0.1:8545"
    registry_address: str = ""
    # Funded test-account private key — LOCAL TEST CHAINS ONLY, never a real key.
    chain_private_key: str = ""
    chain_enabled: bool = True
    chain_tx_timeout: int = 120  # seconds to wait for a receipt
    # Optional path to a Hardhat deployment JSON (docker-compose wiring): when
    # registry_address is empty and this file exists, the address is read from it.
    deployment_file: str = ""

    # --- AI layer (Phase 5) ---
    # Provider-agnostic OpenAI-compatible endpoint. Any of these work by changing
    # base_url/model: api.openai.com, api.deepseek.com, api.moonshot.cn,
    # open.bigmodel.cn, openrouter.ai/api/v1, http://localhost:11434/v1 (Ollama).
    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = 25.0

    # --- Report retention / privacy ---
    # 0 keeps stored reports indefinitely. Any positive value makes the app
    # purge reports (plus their correlation indicators and chain commitments)
    # older than that many days at startup. Deletion of a single report is also
    # available via DELETE /api/v1/reports/{report_id}.
    report_retention_days: int = 0

    # --- DNS resolution (passive record checks) ---
    # When the system resolver (UDP/TCP port 53) times out or fails, the
    # passive DNS-records check can fall back to RFC 8484 DNS-over-HTTPS
    # (standard port 443) via public resolvers. This applies ONLY to the
    # passive record checks — the SSRF-safe fetcher's pinning resolver
    # deliberately keeps using the system resolver.
    dns_use_doh: bool = True
    dns_timeout: float = 3.0

    # --- VirusTotal v3 fallback policy ---
    # When GET /api/v3/urls/{id} answers 404 (URL never analysed by VT):
    # vt_domain_fallback  — passively query /api/v3/domains/{host} instead
    #                       (default; 100% passive, no submission quota).
    # vt_submit_on_miss   — OPT-IN active behaviour: POST the unknown URL to
    #                       /api/v3/urls for scanning, then re-check. Costs
    #                       submission quota; default off.
    vt_domain_fallback: bool = True
    vt_submit_on_miss: bool = False

    # --- Multi-tenant authentication (Step 4) ---
    # False (default): local/single-user/demo mode — no credentials required,
    # all stored reports remain accessible exactly as before.
    # True: every /api/v1/analyze and reports-management route requires a
    # Bearer JWT (dashboard users) or an X-API-Key header (programmatic
    # users); report reads are owner-or-public, deletes/commits owner-only.
    auth_required: bool = False
    # HS256 secret for access tokens. If empty while auth_required is on, an
    # ephemeral random secret is generated at startup (tokens do not survive
    # restarts) and a warning is logged — set a stable secret for real use.
    jwt_secret: str = ""
    access_token_expiry_minutes: int = 480

    # --- User lifecycle / bootstrap (hardened auth MVP) ---
    # Admins are NEVER granted to the first arbitrary registration. Bootstrap
    # the administrator explicitly via these env vars (applied at startup,
    # idempotent) or the CLI: `python -m app.storage.seed`.
    # Open self-registration: off by default whenever auth is required; admins
    # can always create users. Demo mode (auth_required=false) is unaffected.
    allow_open_registration: bool = False
    initial_admin_email: str = ""
    initial_admin_password: str = ""

    # --- Threat-intel time budget (audit M2) ---
    # Total wall-clock budget (seconds) for the threat-intel stage of ONE URL
    # analysis (domain pass + URL pass combined). Provider calls are sequential;
    # without a budget, five slow/unreachable providers can hold a single
    # analysis for well over two minutes. When the budget expires, remaining
    # provider checks are cancelled and reported as failed/unavailable coverage
    # (never as a clean answer); findings and authoritative matches obtained
    # before the timeout are preserved. 0 disables the budget.
    intel_budget_seconds: float = 60.0

    # --- Message embedded-URL budget (audit M2) ---
    # Aggregate wall-clock budget (seconds) for running embedded URLs of ONE
    # message through the full URL pipeline. Without it, a message with N links
    # multiplies the per-URL cost (fetch + CT + DNS + intel) without bound.
    # URLs past the deadline are skipped and reported as failed coverage
    # (MSG-URL-SKIPPED), never as clean results. 0 disables the budget.
    message_url_budget_seconds: float = 240.0

    # --- VirusTotal submit-on-miss budget ---
    # Upper bound on ACTIVE URL submissions per rolling hour when
    # TRUSTLENS_VT_SUBMIT_ON_MISS is enabled (submission quota protection).
    vt_submit_max_per_hour: int = 10


@lru_cache
def get_settings() -> Settings:
    return Settings()
