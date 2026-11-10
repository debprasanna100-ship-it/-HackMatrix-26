"""Audit M2 regression tests: threat-intel time budget and the message
embedded-URL aggregate budget.

Guarantees pinned here:
  * a budget expiry is reported as FAILED/unavailable coverage (never a clean
    answer) via the INTEL-BUDGET-EXCEEDED finding and the coverage note;
  * findings and authoritative matches obtained BEFORE the timeout are
    preserved and keep their deterministic precedence;
  * a partial provider success (some answered, some cut) does not force
    inconclusive;
  * a message with multiple embedded URLs is bounded by the aggregate budget;
    URLs past the deadline are skipped and reported (MSG-URL-SKIPPED).

All tests use stubbed intel registries and stubbed fetchers — no network.
"""
from __future__ import annotations

import asyncio

import pytest

from app.models.enums import FindingCategory, Severity
from app.models.schemas import Finding
from app.pipeline.message import analyze_message
from app.pipeline.runner import analyze_url
from tests.conftest import make_settings
from tests.test_api import SafeFetcher, StubFetcher, good_fetch_result
from tests.test_message_summaries import FakeIntelRegistry, _intel_finding


class SlowFetcher(SafeFetcher):
    """Stub fetcher that waits `delay` seconds per fetch, then succeeds."""

    def __init__(self, delay: float):
        self._delay = delay

    async def fetch(self, norm):  # type: ignore[override]
        await asyncio.sleep(self._delay)
        return good_fetch_result(norm.url)


def _budget_settings(tmp_path, **overrides):
    return make_settings(
        database_url=f"sqlite:///{tmp_path.as_posix()}/budget-test.db",
        **overrides,
    )


# ---- URL analysis: intel stage budget ------------------------------------------


@pytest.mark.asyncio
async def test_intel_budget_timeout_is_failed_coverage_not_clean(tmp_path):
    """When every configured provider is still waiting when the budget expires,
    the report is inconclusive (an outage), the budget finding is recorded as a
    failed check, and nothing reads as a clean provider answer."""
    intel = FakeIntelRegistry(domain_delay=5.0)  # would answer long after the budget
    settings = _budget_settings(tmp_path, intel_budget_seconds=0.05)
    report = await analyze_url(
        "https://example.com/", settings,
        fetcher=StubFetcher(good_fetch_result("https://example.com/")),
        intel=intel, persist=False,
    )
    assert report.classification.value == "inconclusive"
    ids = {f.id for f in report.findings}
    assert "INTEL-BUDGET-EXCEEDED" in ids
    budget_finding = next(f for f in report.findings if f.id == "INTEL-BUDGET-EXCEEDED")
    assert budget_finding.check_succeeded is False
    assert any("budget" in u and "threat-intel" in u for u in report.coverage.unavailable_checks)
    assert report.scoring.key_checks_unavailable == ["INTEL-BUDGET-EXCEEDED"]
    assert intel.answered_providers() == []  # nothing was (fully) answered
    assert report.schema_version == "2.1"  # audit L1


@pytest.mark.asyncio
async def test_partial_provider_success_survives_budget_cut(tmp_path):
    """A provider that answered before the budget expired counts as answered:
    the report proceeds to the risk bands (no forced inconclusive), while the
    cancelled remainder is still recorded as failed coverage."""
    intel = FakeIntelRegistry(
        domain_findings=[],          # clean domain answer, fast
        url_delay=5.0,               # URL pass would hang past the budget
    )
    settings = _budget_settings(tmp_path, intel_budget_seconds=0.05)
    report = await analyze_url(
        "https://example.com/", settings,
        fetcher=StubFetcher(good_fetch_result("https://example.com/")),
        intel=intel, persist=False,
    )
    assert intel.answered_providers() == ["stub"]
    assert report.classification.value != "inconclusive"  # partial success stays scorable
    ids = {f.id for f in report.findings}
    assert "INTEL-BUDGET-EXCEEDED" in ids
    assert any("budget" in u for u in report.coverage.unavailable_checks)


@pytest.mark.asyncio
async def test_authoritative_match_before_timeout_keeps_precedence(tmp_path):
    """An authoritative feed match obtained BEFORE the budget expires must keep
    its precedence: confirmed_malicious even though the stage then timed out."""
    intel = FakeIntelRegistry(
        domain_findings=[_intel_finding("URLHAUS-MATCH")],
        url_delay=5.0,
    )
    settings = _budget_settings(tmp_path, intel_budget_seconds=0.05)
    report = await analyze_url(
        "https://example.com/", settings,
        fetcher=StubFetcher(good_fetch_result("https://example.com/")),
        intel=intel, persist=False,
    )
    assert report.classification.value == "confirmed_malicious"
    ids = {f.id for f in report.findings}
    assert "URLHAUS-MATCH" in ids and "INTEL-BUDGET-EXCEEDED" in ids
    assert report.scoring.authoritative_hits >= 1


@pytest.mark.asyncio
async def test_intel_budget_disabled_runs_to_completion(tmp_path):
    """intel_budget_seconds=0 disables the budget: the (stubbed) stage finishes
    and no budget finding appears."""
    intel = FakeIntelRegistry(domain_delay=0.3)  # slower than the old budget would allow
    settings = _budget_settings(tmp_path, intel_budget_seconds=0)
    report = await analyze_url(
        "https://example.com/", settings,
        fetcher=StubFetcher(good_fetch_result("https://example.com/")),
        intel=intel, persist=False,
    )
    ids = {f.id for f in report.findings}
    assert "INTEL-BUDGET-EXCEEDED" not in ids
    assert intel.answered_providers() == ["stub"]


# ---- message pipeline: aggregate embedded-URL budget ----------------------------


@pytest.mark.asyncio
async def test_message_url_budget_skips_remaining_urls(tmp_path):
    """A message with several embedded URLs cannot multiply the per-URL cost:
    URLs past the aggregate deadline are skipped and reported as failed
    coverage, and processed URLs are unaffected."""
    intel = FakeIntelRegistry(domain_delay=0.05)
    settings = _budget_settings(
        tmp_path,
        message_url_budget_seconds=0.1,
        intel_budget_seconds=5.0,
    )
    fetcher = SlowFetcher(delay=0.06)  # per-URL cost ≈ 0.06 + 0.05 = 0.11s > budget
    report = await analyze_message(
        "Compare https://site-a.com/ with https://site-b.com/ and https://site-c.com/ today.",
        settings, fetcher=fetcher, intel=intel, persist=False,
    )
    assert len(report.extras["sub_reports"]) == 1  # only the first URL fit the budget
    ids = {f.id for f in report.findings}
    assert "MSG-URL-SKIPPED" in ids
    skipped = next(f for f in report.findings if f.id == "MSG-URL-SKIPPED")
    assert skipped.check_succeeded is False
    assert any("2/3 embedded URL(s) skipped" in u for u in report.coverage.unavailable_checks)
    assert skipped.evidence[0].startswith("2 of 3 embedded URL(s)")
    # Partial processing (one fetched OK) stays scorable — not inconclusive.
    assert report.classification.value != "inconclusive"
    assert report.scoring.key_checks_failed == []


@pytest.mark.asyncio
async def test_message_url_budget_disabled_processes_everything(tmp_path):
    """message_url_budget_seconds=0 disables the cap: all embedded URLs are
    analysed (their failures recorded by the pre-existing rules instead)."""
    intel = FakeIntelRegistry(domain_delay=0.02)
    settings = _budget_settings(tmp_path, message_url_budget_seconds=0, intel_budget_seconds=5.0)
    fetcher = SlowFetcher(delay=0.01)
    report = await analyze_message(
        "Compare https://site-a.com/ with https://site-b.com/ and https://site-c.com/ today.",
        settings, fetcher=fetcher, intel=intel, persist=False,
    )
    ids = {f.id for f in report.findings}
    assert "MSG-URL-SKIPPED" not in ids
    assert len(report.extras["sub_reports"]) == 3


@pytest.mark.asyncio
async def test_message_all_urls_skipped_or_invalid_forces_inconclusive(tmp_path):
    """If NO embedded URL completed a fetch (all unparsable here), the
    required-check gate yields inconclusive — a verdict without a completed
    fetch is never issued."""
    settings = _budget_settings(tmp_path)
    report = await analyze_message(
        "Check https://:70000/ and https://:70001/ right now, your account depends on it.",
        settings, fetcher=SlowFetcher(delay=0.0), intel=FakeIntelRegistry(), persist=False,
    )
    assert report.classification.value == "inconclusive"
    assert report.scoring.key_checks_failed == ["page-fetch (embedded URLs)"]
