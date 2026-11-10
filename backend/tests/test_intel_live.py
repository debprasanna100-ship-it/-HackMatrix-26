"""Live threat-intel adapter contract tests.

These tests run against the REAL provider endpoints and therefore need BOTH
(1) API keys present in the environment (backend/.env or TRUSTLENS_* env vars)
and (2) an explicit opt-in: set TRUSTLENS_LIVE_INTEL_TESTS=1. Keys alone are
not enough — a developer with configured keys must be able to run plain
`pytest` with zero network traffic (see README: "no real network in tests"),
and the live adapters share class-level caches with the hermetic tests, which
poisoned hermetic tests when both ran in one suite.

Opt-in examples: Git Bash `TRUSTLENS_LIVE_INTEL_TESTS=1 pytest tests/test_intel_live.py`,
PowerShell `$env:TRUSTLENS_LIVE_INTEL_TESTS="1"; pytest tests/test_intel_live.py`.

They exist to close the documented gap that "adapter parsing is unit-tested
against documented shapes only": a provider changing its live response shape
or auth semantics is caught here, on a machine configured with keys.

Safety: only Google's OFFICIAL test URL (testsafebrowsing.appspot.com) and
well-known benign domains are queried. No live threat/malware URLs are ever
contacted, per the project build rules.
"""
from __future__ import annotations

import os

import pytest

from app.config import get_settings
from app.pipeline.intel import IntelRegistry

AUTHORITATIVE_MATCH_IDS = {"URLHAUS-MATCH", "OPENPHISH-MATCH", "PHISHTANK-MATCH",
                           "GSB-MATCH", "VT-MATCH"}

_HAS_KEYS = any([
    get_settings().google_safe_browsing_api_key,
    get_settings().virustotal_api_key,
    get_settings().urlhaus_api_key,
    get_settings().openphish_api_key,
    get_settings().phishtank_api_key,
])

pytestmark = pytest.mark.skipif(
    not (os.environ.get("TRUSTLENS_LIVE_INTEL_TESTS") and _HAS_KEYS),
    reason="Live provider tests need TRUSTLENS_LIVE_INTEL_TESTS=1 AND provider keys",
)


async def test_live_benign_target_never_confirms():
    """A benign, well-known target must never produce an authoritative match
    from any configured provider (false-positive guard)."""
    registry = IntelRegistry(get_settings())
    configured = [n for n, s in registry.status().items() if s != "unconfigured"]
    assert configured, "keys are present but no provider initialised"

    findings = await registry.check_url("https://example.com/")
    matches = [f for f in findings if f.id in AUTHORITATIVE_MATCH_IDS]
    assert matches == [], f"benign target produced matches: {[f.id for f in matches]}"
    # providers that answered must be recorded as having answered
    assert registry.answered_providers(), "no configured provider answered"


@pytest.mark.skipif(not get_settings().google_safe_browsing_api_key,
                    reason="GSB key not configured")
async def test_live_gsb_official_test_url_is_flagged():
    """Google Safe Browsing documents testsafebrowsing.appspot.com URLs as
    always-match test fixtures (this is Google's own test host, NOT a live
    threat). The adapter must surface GSB-MATCH with high severity."""
    registry = IntelRegistry(get_settings())
    findings = await registry.check_url("http://testsafebrowsing.appspot.com/s/phishing.html")
    gsb = [f for f in findings if f.id == "GSB-MATCH"]
    assert gsb, "GSB did not flag its own documented test URL — response shape may have changed"
    assert all(f.severity.value in ("high", "medium") for f in gsb)
    assert all(f.check_succeeded for f in gsb)


@pytest.mark.skipif(not get_settings().virustotal_api_key,
                    reason="VT key not configured")
async def test_live_vt_domain_report_shape():
    """VT v3 domain endpoint must answer with parseable last_analysis_stats
    (this is what the adapter's fallback path relies on)."""
    registry = IntelRegistry(get_settings())
    findings = await registry.check_domain("example.com")
    # example.com is clean: no adverse findings — but the provider must have
    # ANSWERED (no ERROR/KEY-ERROR findings; 404 -> VT-NODATA is acceptable)
    failures = [f for f in findings if f.id in ("VT-ERROR", "VT-KEY-ERROR")]
    assert failures == [], f"VT domain check failed live: {[f.evidence for f in failures]}"
    assert registry.answered_providers(), "VT did not count as answered"


@pytest.mark.skipif(not get_settings().openphish_api_key,
                    reason="OpenPhish key not configured")
async def test_live_openphish_feed_fetches_and_indexes():
    """The community feed must download and index (a benign URL yields no
    match, and the adapter counts as answered)."""
    registry = IntelRegistry(get_settings())
    findings = await registry.check_url("https://example.com/")
    assert not [f for f in findings if f.id == "OPENPHISH-ERROR"]
    assert "openphish" in registry.answered_providers()
