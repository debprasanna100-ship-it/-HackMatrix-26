"""Deterministic tests for the passive DNS record checks (no real DNS traffic).

The query function is injected, so NXDOMAIN / no-answer / timeout / malformed
responses are all simulated locally; the DoH fallback is tested with
monkeypatched transports and well-formed dns.message objects.
"""
from __future__ import annotations

import asyncio

import dns.exception
import dns.message
import dns.rcode
import dns.resolver
import dns.rrset
import pytest

from app.pipeline import dns_records
from app.pipeline.dns_records import check_dns_records


def _a_response(name: str = "example.com", value: str = "93.184.216.34",
                rcode: int = dns.rcode.NOERROR) -> dns.message.Message:
    q = dns.message.make_query(name, "A")
    response = dns.message.make_response(q)
    response.set_rcode(rcode)
    if rcode == dns.rcode.NOERROR:
        response.answer.append(dns.rrset.from_text(f"{name}.", 300, "IN", "A", value))
    return response


def _query_map(answers: dict[str, list[str]] | None = None,
               errors: dict[str, Exception] | None = None):
    """Build an injected query fn: per-type canned values or raised errors."""
    answers = answers or {}
    errors = errors or {}

    async def query(domain: str, rtype: str, timeout: float = 3.0) -> list[str]:
        if rtype in errors:
            raise errors[rtype]
        return list(answers.get(rtype, []))

    return query


def _run(domain="example.com", **kwargs):
    query = kwargs.pop("query", None)
    return asyncio.run(check_dns_records(domain, query=query, **kwargs))


def test_all_record_types_resolved():
    findings, stats = _run(query=_query_map({
        "A": ["93.184.216.34", "2606:4700::1110"],
        "MX": ["10 mx1.example.com.", "20 mx2.example.com."],
        "NS": ["a.iana-servers.net.", "b.iana-servers.net."],
        "TXT": ["v=spf1 include:_spf.example.com ~all", "site-verification=SECRET-TOKEN-abc"],
    }))
    ids = {f.id for f in findings}
    assert "DNS-RECORDS" in ids
    assert stats["A"] == 2 and stats["MX"] == 2 and stats["NS"] == 2 and stats["TXT"] == 2
    assert stats["spf"] is True
    assert stats["failed_types"] == []
    summary = next(f for f in findings if f.id == "DNS-RECORDS")
    # Evidence is capped and names are shown, but raw TXT bodies are NOT stored:
    # the site-verification token must never appear.
    joined = " ".join(summary.evidence)
    assert "SECRET-TOKEN-abc" not in joined
    assert "SPF record present: yes" in joined
    assert all(f.category.value == "dns" and f.source == "trustlens/dns-records" for f in findings)


def test_no_answer_counts_as_zero_records():
    """NoAnswer (or an empty answer section) is a successful lookup with zero
    records — absence of records is context, not a failure."""
    findings, stats = _run(query=_query_map({}))
    assert stats["A"] == 0 and stats["MX"] == 0 and stats["NS"] == 0 and stats["TXT"] == 0
    assert stats["failed_types"] == []
    assert stats["spf"] is False
    assert any(f.id == "DNS-RECORDS" for f in findings)
    assert any("SPF record present: no" in e for f in findings for e in f.evidence)


def test_nxdomain_short_circuits_remaining_lookups():
    calls: list[str] = []

    async def query(domain, rtype, timeout=3.0):
        calls.append(rtype)
        raise dns.resolver.NXDOMAIN()

    findings, stats = asyncio.run(check_dns_records("dead.example", query=query))
    assert calls == ["A"]  # remaining types skipped
    assert any(f.id == "DNS-NXDOMAIN" for f in findings)
    nx = next(f for f in findings if f.id == "DNS-NXDOMAIN")
    assert nx.check_succeeded is False
    assert stats["error"] == "NXDOMAIN"
    assert stats["failed_types"] == ["A", "MX", "NS", "TXT"]


def test_timeout_is_a_failed_check_not_clean():
    findings, stats = _run(query=_query_map(
        {"A": ["93.184.216.34"]},
        errors={"MX": dns.exception.Timeout("query timed out")},
    ))
    f = next(f for f in findings if f.id == "DNS-MX-UNAVAILABLE")
    assert f.check_succeeded is False
    assert "Timeout" in f.evidence[0]
    assert stats["failed_types"] == ["MX"]
    assert stats["MX"] == 0
    # the successful A lookup is still reported
    assert stats["A"] == 1


def test_malformed_response_is_a_failed_check():
    findings, stats = _run(query=_query_map(
        errors={"TXT": ValueError("malformed answer")},
    ))
    assert any(f.id == "DNS-TXT-UNAVAILABLE" and not f.check_succeeded for f in findings)
    assert "TXT" in stats["failed_types"]


def test_partial_success_reports_both_sides():
    findings, stats = _run(query=_query_map(
        {"A": ["1.2.3.4"], "NS": ["ns1.example.com."]},
        errors={"MX": dns.resolver.NoNameservers(), "TXT": OSError("network down")},
    ))
    ids = {f.id for f in findings}
    assert "DNS-RECORDS" in ids          # successful types summarised
    assert "DNS-MX-UNAVAILABLE" in ids   # failed types recorded individually
    assert "DNS-TXT-UNAVAILABLE" in ids
    assert sorted(stats["failed_types"]) == ["MX", "TXT"]
    summary = next(f for f in findings if f.id == "DNS-RECORDS")
    assert any(line.startswith("A: 1 address") for line in summary.evidence)


def test_empty_domain_short_circuits():
    findings, stats = _run(domain="")
    assert findings == []
    assert stats["A"] == 0 and stats["failed_types"] == []




# ---- DoH fallback (Step 3): port-53 failure -> RFC 8484 over 443 -----------------


def test_doh_query_parses_real_message_shape(monkeypatch):
    """_doh_query builds a wire query and extracts rdata from a well-formed
    dns.message response (no network)."""
    seen: dict = {}

    async def fake_https(query, endpoint, timeout=None):
        seen["query"] = query
        seen["endpoint"] = endpoint
        return _a_response("example.com", "93.184.216.34")

    monkeypatch.setattr(dns_records.dns.asyncquery, "https", fake_https)
    values = asyncio.run(dns_records._doh_query(
        "example.com", "A", 3.0, "https://cloudflare-dns.com/dns-query"))
    assert values == ["93.184.216.34"]
    assert seen["endpoint"] == "https://cloudflare-dns.com/dns-query"
    assert str(seen["query"].question[0].name) == "example.com."


def test_doh_query_nxdomain_is_not_swallowed(monkeypatch):
    async def fake_https(query, endpoint, timeout=None):
        return _a_response("dead.example", rcode=dns.rcode.NXDOMAIN)

    monkeypatch.setattr(dns_records.dns.asyncquery, "https", fake_https)
    with pytest.raises(dns.resolver.NXDOMAIN):
        asyncio.run(dns_records._doh_query("dead.example", "A", 3.0, "https://x/dns-query"))


def test_doh_query_error_rcode_raises(monkeypatch):
    async def fake_https(query, endpoint, timeout=None):
        return _a_response("srvfail.example", rcode=dns.rcode.SERVFAIL)

    monkeypatch.setattr(dns_records.dns.asyncquery, "https", fake_https)
    with pytest.raises(dns.exception.DNSException):
        asyncio.run(dns_records._doh_query("srvfail.example", "A", 3.0, "https://x/dns-query"))


def test_fallback_tries_doh_endpoints_in_order(monkeypatch):
    """Port-53 failure -> first DoH endpoint fails -> second answers."""
    order: list[str] = []
    endpoints = dns_records.DOH_ENDPOINTS

    async def std_fail(domain, rtype, timeout):
        order.append("system")
        raise dns.exception.Timeout("port 53 blocked")

    async def selective_doh(domain, rtype, timeout, endpoint):
        order.append(endpoint)
        if endpoint == endpoints[0]:
            raise dns.exception.Timeout("endpoint down")
        return ["93.184.216.34"]

    monkeypatch.setattr(dns_records, "_standard_query", std_fail)
    monkeypatch.setattr(dns_records, "_doh_query", selective_doh)
    values = asyncio.run(dns_records._query_with_fallback("example.com", "A", 3.0, use_doh=True))
    assert values == ["93.184.216.34"]
    assert order[0] == "system" and endpoints[1] in order


def test_fallback_nxdomain_does_not_trigger_doh(monkeypatch):
    """NXDOMAIN is a definitive answer — no DoH retry (dead domains stay cheap)."""
    calls: list[str] = []

    async def std_nxdomain(domain, rtype, timeout):
        calls.append("system")
        raise dns.resolver.NXDOMAIN("no such domain")

    async def doh(domain, rtype, timeout, endpoint):
        calls.append("doh")
        return ["1.2.3.4"]

    monkeypatch.setattr(dns_records, "_standard_query", std_nxdomain)
    monkeypatch.setattr(dns_records, "_doh_query", doh)
    with pytest.raises(dns.resolver.NXDOMAIN):
        asyncio.run(dns_records._query_with_fallback("dead.example", "A", 3.0, use_doh=True))
    assert calls == ["system"]


def test_fallback_disabled_reraises_original_error(monkeypatch):
    calls: list[str] = []

    async def std_fail(domain, rtype, timeout):
        calls.append("system")
        raise dns.exception.Timeout("port 53 blocked")

    async def doh(domain, rtype, timeout, endpoint):
        calls.append("doh")
        return ["1.2.3.4"]

    monkeypatch.setattr(dns_records, "_standard_query", std_fail)
    monkeypatch.setattr(dns_records, "_doh_query", doh)
    with pytest.raises(dns.exception.Timeout):
        asyncio.run(dns_records._query_with_fallback("example.com", "A", 3.0, use_doh=False))
    assert calls == ["system"]


def test_fallback_all_endpoints_down_raises_last_error(monkeypatch):
    async def std_fail(domain, rtype, timeout):
        raise OSError("network unreachable")

    async def doh_fail(domain, rtype, timeout, endpoint):
        raise dns.exception.Timeout(f"{endpoint} down")

    monkeypatch.setattr(dns_records, "_standard_query", std_fail)
    monkeypatch.setattr(dns_records, "_doh_query", doh_fail)
    with pytest.raises(dns.exception.Timeout):
        asyncio.run(dns_records._query_with_fallback("example.com", "A", 3.0, use_doh=True))


def test_settings_defaults_for_dns_and_doh():
    from app.config import Settings

    s = Settings()
    assert s.dns_use_doh is True
    assert s.dns_timeout == 3.0


# ---- DoH redundancy & honest all-fail reporting (Task 3) ----


def test_doh_endpoint_list_has_three_independent_operators():
    assert dns_records.DOH_ENDPOINTS == (
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
        "https://dns.quad9.net/dns-query",
    )


def test_per_endpoint_doh_timeout_is_capped(monkeypatch):
    """Each DoH attempt gets its own short budget (2.0s) — a stalled provider
    must not consume the whole query budget."""
    seen: list[float] = []

    async def std_fail(domain, rtype, timeout):
        raise dns.exception.Timeout("port 53 blocked")

    async def doh_spy(domain, rtype, timeout, endpoint):
        seen.append(timeout)
        raise dns.exception.Timeout(f"{endpoint} down")

    monkeypatch.setattr(dns_records, "_standard_query", std_fail)
    monkeypatch.setattr(dns_records, "_doh_query", doh_spy)
    with pytest.raises(dns.exception.Timeout):
        asyncio.run(dns_records._query_with_fallback("example.com", "A", 3.0, use_doh=True))
    assert seen == [2.0, 2.0, 2.0]  # one short budget per endpoint


def test_all_lookups_fail_reports_dns_lookup_failed():
    """System resolver + every DoH endpoint down -> one honest
    DNS-LOOKUP-FAILED summary; the checker still returns normally (the
    pipeline is never halted by an optional check)."""
    findings, stats = _run(query=_query_map(errors={
        t: dns.exception.Timeout("everything down") for t in ("A", "MX", "NS", "TXT")}))
    ids = {f.id for f in findings}
    assert "DNS-LOOKUP-FAILED" in ids
    assert stats["failed_types"] == ["A", "MX", "NS", "TXT"]
    assert stats["error"]
    summary = next(f for f in findings if f.id == "DNS-LOOKUP-FAILED")
    assert summary.check_succeeded is False
    assert "coverage limitation" in " ".join(summary.evidence)
    # per-type failures are still recorded alongside the summary
    assert {"DNS-A-UNAVAILABLE", "DNS-MX-UNAVAILABLE", "DNS-NS-UNAVAILABLE",
            "DNS-TXT-UNAVAILABLE"} <= ids


def test_partial_failure_does_not_emit_dns_lookup_failed():
    findings, _ = _run(query=_query_map(
        {"A": ["1.2.3.4"]},
        errors={t: dns.exception.Timeout("down") for t in ("MX", "NS", "TXT")}))
    assert all(f.id != "DNS-LOOKUP-FAILED" for f in findings)
