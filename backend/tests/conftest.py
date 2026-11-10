"""Shared test fixtures: fake resolvers/transports so no unit test touches the network."""
from __future__ import annotations

import httpx
import pytest

from app.config import Settings
from app.pipeline.fetcher import SafeFetcher
from app.pipeline.normalizer import normalize_url
from app.pipeline.ssrf import DnsFailure


class FakeResolver:
    """Deterministic resolver: maps host -> list of IPs; unknown hosts raise DnsFailure."""

    def __init__(self, mapping: dict[str, list[str]]):
        self.mapping = {k.lower(): v for k, v in mapping.items()}
        self.calls: list[str] = []

    async def resolve(self, host: str) -> list[str]:
        self.calls.append(host)
        key = host.lower().rstrip(".")
        if key in self.mapping:
            return list(self.mapping[key])
        raise DnsFailure(host, "no record (fake resolver)")

    async def resolve_and_validate(self, host: str) -> list[str]:
        from app.pipeline.ssrf import SSRFPolicyError, check_hostname_allowed, classify_ip
        import ipaddress

        check_hostname_allowed(host)
        try:
            literal = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            literal = None
        if literal is not None:
            reason = classify_ip(literal)
            if reason:
                raise SSRFPolicyError(f"IP address {literal} is in a blocked range: {reason}", host=host)
            return [str(literal)]
        ips = await self.resolve(host)
        blocked = []
        allowed = []
        for ip_text in ips:
            reason = classify_ip(ipaddress.ip_address(ip_text))
            (blocked if reason else allowed).append(f"{ip_text} ({reason})" if reason else ip_text)
        if blocked:
            raise SSRFPolicyError(f"host '{host}' resolves to blocked address(es): {', '.join(blocked)}",
                                  host=host, blocked=blocked)
        return allowed


class FakeTransport(httpx.AsyncBaseTransport):
    """Canned-response transport. Entries may be httpx.Response or Exception."""

    def __init__(self, responses: list):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not self.responses:
            raise AssertionError("FakeTransport ran out of canned responses")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_settings(**overrides) -> Settings:
    defaults = dict(
        database_url="sqlite:///./test-trustlens.db",
        rate_limit_per_minute=1000,
        cors_origins=[],
        # Pin environment-dependent features so tests are deterministic even
        # when a local .env configures chain/LLM/threat-intel integrations.
        registry_address="",
        chain_private_key="",
        llm_api_key="",
        google_safe_browsing_api_key="",
        urlhaus_api_key="",
        openphish_api_key="",
        phishtank_api_key="",
        virustotal_api_key="",
    )
    defaults.update(overrides)
    return Settings(**defaults)


def make_fetcher(settings: Settings, resolver: FakeResolver, transport: FakeTransport) -> SafeFetcher:
    return SafeFetcher(settings, resolver=resolver, transport=transport)


def html_response(status: int = 200, body: bytes = b"<html><title>OK</title></html>", headers: dict | None = None) -> httpx.Response:
    hdrs = {"content-type": "text/html; charset=utf-8"}
    hdrs.update(headers or {})
    return httpx.Response(status, headers=hdrs, content=body)


@pytest.fixture(autouse=True)
def offline_ct(monkeypatch):
    """Keep unit tests hermetic: stub the runner's CT stage so no test issues a
    real crt.sh request (CT behaviour itself is covered by dataclass-level tests)."""
    from app.pipeline import runner as _runner

    async def _no_ct(registrable_domain, cert_sha256="", max_records=2000):
        return [], {"records_found": 0, "most_recent": None}

    monkeypatch.setattr(_runner, "analyze_ct", _no_ct)


@pytest.fixture(autouse=True)
def offline_dns_records(monkeypatch):
    """Keep unit tests hermetic: stub the runner's passive DNS-records stage so
    no test issues real DNS queries (the checker itself is covered by
    test_dns_records.py with an injected query function)."""
    from app.pipeline import runner as _runner

    async def _no_dns(registrable_domain, timeout=3.0, query=None, use_doh=True):
        return [], {"domain": registrable_domain, "A": 0, "MX": 0, "NS": 0, "TXT": 0,
                    "spf": False, "failed_types": [], "error": None}

    monkeypatch.setattr(_runner, "analyze_dns_records", _no_dns)


@pytest.fixture
def sample_norm():
    return normalize_url("https://example.com/")
