"""Audit M1 + L1 regression tests: message reports must carry truthful
scoring and threat-intel summaries, and the same schema version as URL reports.

Before the fix, message reports carried the pydantic defaults (all-zero
`scoring`, empty `threat_intel.providers`) even when the deterministic engine
had classified real findings — the UI score grid showed zeros next to a
high-risk badge. These tests pin the fixed behaviour end-to-end through the API.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from app.models.enums import FindingCategory, Severity
from app.models.schemas import Finding
from tests.conftest import make_settings
from tests.test_api import StubFetcher, build_app, good_fetch_result


class FakeIntelRegistry:
    """Deterministic intel registry stub: canned findings, no network."""

    def __init__(self, domain_findings=None, url_findings=None,
                 domain_delay: float = 0.0, url_delay: float = 0.0):
        self.domain_findings = list(domain_findings or [])
        self.url_findings = list(url_findings or [])
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
        return list(self.url_findings)

    def status(self) -> dict:
        return {"stub": "active"}

    def answered_providers(self) -> list[str]:
        return sorted(self._answered)


def _intel_finding(fid: str = "URLHAUS-MATCH", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=fid, title=f"Stub feed match ({fid})", severity=severity,
        category=FindingCategory.INTEL, evidence=[f"source=stub {fid}"],
        source="trustlens/intel/stub", check_succeeded=True,
    )


def _client(application):
    transport = httpx.ASGITransport(app=application)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_message_without_urls_has_truthful_summaries(tmp_path):
    """Audit M1: a high-risk message WITHOUT embedded URLs must show the real
    score/counts, zero authoritative hits, and provider statuses that do not
    imply any intel check ran (checks_performed is empty)."""
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    async with _client(application) as c:
        resp = await c.post("/api/v1/analyze/message", json={
            "message": "URGENT: your bank account has been compromised. Call security team "
                       "now and read aloud the one-time code within 24 hours. Do not tell anyone."
        })
    assert resp.status_code == 200
    report = resp.json()
    assert report["classification"] == "high_risk"

    scoring = report["scoring"]
    assert scoring["high"] == 1 and scoring["low"] == 1 and scoring["medium"] == 0
    assert scoring["score"] == 10  # MSG-OTP-REQUEST high (8) + MSG-LANGUAGE-TACTICS low (2)
    assert scoring["authoritative_hits"] == 0
    assert scoring["key_checks_failed"] == []

    tsum = report["threat_intel"]
    # intel keys are pinned empty in test settings: config state, never "clean"
    assert set(tsum["providers"].values()) == {"unconfigured"}
    assert tsum["checks_performed"] == []  # no embedded URLs -> no intel work ran
    assert tsum["authoritative_hits"] == []
    assert tsum["total_findings"] == 0

    # Audit L1: URL and message reports share one schema version
    assert report["schema_version"] == "2.1"


@pytest.mark.asyncio
async def test_message_with_embedded_url_reflects_intel_in_summaries(tmp_path, monkeypatch):
    """An authoritative intel hit lifted from an embedded-URL sub-report must be
    visible in BOTH summary blocks, consistently with the classification."""
    fake = FakeIntelRegistry(domain_findings=[_intel_finding("URLHAUS-MATCH")])
    monkeypatch.setattr("app.pipeline.message.init_intel", lambda settings: fake)
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result("https://example.com/")))
    async with _client(application) as c:
        resp = await c.post("/api/v1/analyze/message", json={
            "message": "Please check https://example.com/verify now. Your account is at "
                       "risk, act urgently."
        })
    assert resp.status_code == 200
    report = resp.json()

    # Deterministic precedence: the authoritative feed hit wins.
    assert report["classification"] == "confirmed_malicious"

    scoring = report["scoring"]
    assert scoring["authoritative_hits"] == 1
    assert scoring["high"] >= 1
    assert scoring["score"] >= 16  # URLHAUS-MATCH high (8) counts double in the INTEL category

    tsum = report["threat_intel"]
    assert tsum["authoritative_hits"] == ["URLHAUS-MATCH"]
    assert tsum["total_findings"] == 1
    assert tsum["providers"] == {"stub": "active"}
    assert tsum["checks_performed"] == ["stub"]  # embedded-URL analyses actually ran intel

    # Internal consistency: an authoritative summary implies the verdict band.
    assert (tsum["authoritative_hits"] == []) or (report["classification"] == "confirmed_malicious")
    assert report["schema_version"] == "2.1"


@pytest.mark.asyncio
async def test_url_and_message_reports_share_schema_version(tmp_path, monkeypatch):
    """Audit L1: one SCHEMA_VERSION constant for every report type."""
    monkeypatch.setattr("app.pipeline.message.init_intel", lambda settings: FakeIntelRegistry())
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result("https://example.com/")))
    async with _client(application) as c:
        url_resp = await c.post("/api/v1/analyze/url", json={"url": "https://example.com/"})
        msg_resp = await c.post("/api/v1/analyze/message", json={
            "message": "Plain words only, nothing suspicious here at all."
        })
    assert url_resp.json()["schema_version"] == "2.1"
    assert msg_resp.json()["schema_version"] == "2.1"


@pytest.mark.asyncio
async def test_message_where_every_url_is_unparsable_is_inconclusive(tmp_path):
    """Methodology §7 gate: when embedded URLs exist, the embedded-URL fetch is
    required. URLs that cannot even be parsed did not complete a fetch, so a
    message whose ONLY links are malformed is inconclusive (previously the
    all-invalid edge silently produced a normal verdict)."""
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    async with _client(application) as c:
        resp = await c.post("/api/v1/analyze/message", json={
            "message": "Check https://:70000/ and https://:70001/ today. Your account "
                       "needs attention immediately."
        })
    report = resp.json()
    ids = {f["id"] for f in report["findings"]}
    assert "MSG-URL-INVALID" in ids
    assert report["extras"]["sub_reports"] == []
    assert report["classification"] == "inconclusive"
    assert report["scoring"]["key_checks_failed"] == ["page-fetch (embedded URLs)"]
