"""Unit tests for SSRF guards: IP range classification, hostname policy, validation."""
from __future__ import annotations

import ipaddress

import pytest

from app.pipeline.fetcher import _PinningNetworkBackend
from app.pipeline.ssrf import (
    DnsFailure,
    SSRFPolicyError,
    SystemDnsResolver,
    check_hostname_allowed,
    classify_ip,
)
from tests.conftest import FakeResolver


@pytest.mark.parametrize("ip_text", [
    "10.0.0.5", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1",
    "127.0.0.1", "127.8.8.8", "169.254.169.254", "0.0.0.0", "100.64.0.1",
    "198.18.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "192.0.2.1",
])
def test_blocked_ipv4_ranges(ip_text):
    assert classify_ip(ipaddress.ip_address(ip_text)) is not None


@pytest.mark.parametrize("ip_text", [
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "104.16.132.229",
])
def test_public_ipv4_allowed(ip_text):
    assert classify_ip(ipaddress.ip_address(ip_text)) is None


@pytest.mark.parametrize("ip_text", [
    "::1", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "2001:db8::1",
    "::", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:192.168.0.1",
    "64:ff9b::a00:1",  # NAT64 embedding 10.0.0.1
    "2002:0a00:0001::",  # 6to4 embedding 10.0.0.1
])
def test_blocked_ipv6_ranges(ip_text):
    assert classify_ip(ipaddress.ip_address(ip_text)) is not None


@pytest.mark.parametrize("ip_text", [
    "2606:4700::1111", "2001:4860:4860::8888",
])
def test_public_ipv6_allowed(ip_text):
    assert classify_ip(ipaddress.ip_address(ip_text)) is None


def test_metadata_address_specifically_blocked():
    # AWS/GCP metadata endpoints live in 169.254.0.0/16.
    assert "metadata" in classify_ip(ipaddress.ip_address("169.254.169.254"))


@pytest.mark.parametrize("host", [
    "localhost", "foo.localhost", "metadata.google.internal", "metadata.goog",
    "db.local", "svc.internal", "myserver.lan", "box.corp", "x.home.arpa",
])
def test_blocked_hostnames(host):
    with pytest.raises(SSRFPolicyError):
        check_hostname_allowed(host)


@pytest.mark.parametrize("host", [
    "example.com", "8.8.8.8", "sub.example.co.uk", "xn--mnchen-3ya.de",
])
def test_allowed_hostnames(host):
    check_hostname_allowed(host)


def test_validate_refuses_when_any_address_is_blocked():
    resolver = FakeResolver({"mixed.example": ["8.8.8.8", "10.0.0.1"]})
    with pytest.raises(SSRFPolicyError) as exc:
        import asyncio
        asyncio.run(resolver.resolve_and_validate("mixed.example"))
    assert "10.0.0.1" in str(exc.value)


def test_validate_accepts_public_addresses():
    resolver = FakeResolver({"example.com": ["93.184.216.34", "2606:4700::1111"]})
    import asyncio
    assert asyncio.run(resolver.resolve_and_validate("example.com")) == ["93.184.216.34", "2606:4700::1111"]


def test_validate_ip_literal_directly():
    resolver = FakeResolver({})
    import asyncio
    with pytest.raises(SSRFPolicyError):
        asyncio.run(resolver.resolve_and_validate("127.0.0.1"))
    assert asyncio.run(resolver.resolve_and_validate("93.184.216.34")) == ["93.184.216.34"]


def test_unknown_host_raises_dns_failure():
    resolver = FakeResolver({})
    import asyncio
    with pytest.raises(DnsFailure):
        asyncio.run(resolver.resolve("missing.example"))


def test_pinning_backend_refuses_private_target_before_dialing():
    """The pinning backend must raise before any socket is opened."""
    resolver = FakeResolver({"internal.example": ["192.168.1.10"]})
    backend = _PinningNetworkBackend(resolver)

    class ExplodingBackend(_PinningNetworkBackend):
        async def connect_tcp(self, *args, **kwargs):  # pragma: no cover
            raise AssertionError("socket dial reached - policy must fire first")

    import asyncio
    with pytest.raises(SSRFPolicyError):
        asyncio.run(backend.connect_tcp("internal.example", 443))


def test_system_resolver_validates_before_returning():
    """SystemDnsResolver.resolve_and_validate is policy-safe even if DNS lies."""
    import asyncio

    class LyingResolver(SystemDnsResolver):
        async def resolve(self, host):
            return ["127.0.0.1", "169.254.169.254"]

    with pytest.raises(SSRFPolicyError):
        asyncio.run(LyingResolver().resolve_and_validate("evil.example"))


# ---- IP pinning: every connection dials the validated IP only ---------------------


def test_pinning_backend_dials_the_validated_ip(monkeypatch):
    """The pinning backend must resolve+validate the hostname, then dial the
    VALIDATED IP (not the hostname) — proving the connect path uses the
    validated address with no rebinding window."""
    import asyncio

    import app.pipeline.fetcher as fetcher_mod

    dials: list[tuple[str, int]] = []

    async def fake_base_connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        dials.append((host, port))

        class _FakeStream:
            async def start_tls(self, *a, **kw):
                return self

            async def write(self, data):
                pass

        return _FakeStream()

    monkeypatch.setattr(fetcher_mod._BaseNetworkBackend, "connect_tcp", fake_base_connect_tcp)

    resolver = FakeResolver({"example.com": ["93.184.216.34"]})
    backend = fetcher_mod._PinningNetworkBackend(resolver)
    asyncio.run(backend.connect_tcp("example.com", 443))

    assert resolver.calls == ["example.com"]       # hostname was resolved+validated
    assert dials == [("93.184.216.34", 443)]       # the VALIDATED IP was dialed


def test_pinning_backend_blocks_mixed_answers_before_dialing(monkeypatch):
    """Any blocked address among the answers refuses the connection — no socket
    dial may happen (conservative DNS-rebinding defence)."""
    import asyncio

    import app.pipeline.fetcher as fetcher_mod

    dials: list[tuple[str, int]] = []

    async def fake_base_connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        dials.append((host, port))
        raise AssertionError("must never dial")

    monkeypatch.setattr(fetcher_mod._BaseNetworkBackend, "connect_tcp", fake_base_connect_tcp)

    resolver = FakeResolver({"rebind.example": ["8.8.8.8", "10.0.0.1"]})
    backend = fetcher_mod._PinningNetworkBackend(resolver)
    with pytest.raises(SSRFPolicyError):
        asyncio.run(backend.connect_tcp("rebind.example", 443))
    assert dials == []
