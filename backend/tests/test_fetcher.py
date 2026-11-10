"""Unit tests for the SSRF-safe fetcher and redirect tracing (no real network)."""
from __future__ import annotations

import httpx
import pytest

from app.models.enums import FetchErrorKind
from app.pipeline.fetcher import SafeFetcher
from app.pipeline.normalizer import normalize_url
from tests.conftest import FakeResolver, FakeTransport, html_response, make_settings


def _fetcher(responses: list, mapping: dict[str, list[str]] | None = None, **overrides) -> tuple[SafeFetcher, FakeTransport]:
    settings = make_settings(**overrides)
    resolver = FakeResolver(mapping or {"example.com": ["93.184.216.34"], "redirected.example": ["93.184.216.35"]})
    transport = FakeTransport(responses)
    return SafeFetcher(settings, resolver=resolver, transport=transport), transport


@pytest.mark.asyncio
async def test_simple_200_records_single_hop_and_title():
    fetcher, transport = _fetcher([
        html_response(200, b"<html><head><title>Welcome to Example</title></head><body>hi</body></html>")
    ])
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.success is True
    assert result.ok is True
    assert result.status_code == 200
    assert result.final_url == "https://example.com/"
    assert result.title == "Welcome to Example"
    assert len(result.hops) == 1
    assert transport.requests[0].method == "GET"


@pytest.mark.asyncio
async def test_redirect_chain_fully_traced():
    fetcher, _ = _fetcher([
        httpx.Response(302, headers={"location": "https://example.com/step2"}),
        httpx.Response(301, headers={"location": "/step3"}),
        html_response(200, b"<html><title>Landing</title></html>"),
    ])
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.success is True
    assert result.final_url == "https://example.com/step3"
    assert [h.status for h in result.hops] == [302, 301, 200]
    assert result.hops[0].location == "https://example.com/step2"
    assert result.hops[1].location == "/step3"


@pytest.mark.asyncio
async def test_too_many_redirects_refused():
    responses = [httpx.Response(302, headers={"location": f"https://example.com/hop{i}"}) for i in range(7)]
    fetcher, _ = _fetcher(responses, fetch_max_redirects=5)
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.success is False
    assert result.error_kind == FetchErrorKind.POLICY
    assert "redirect" in (result.error or "").lower()
    # 5 redirects followed, 6th attempt exhausted the allowance
    assert len(result.hops) == 6


@pytest.mark.asyncio
async def test_redirect_to_non_http_scheme_refused():
    fetcher, _ = _fetcher([
        httpx.Response(302, headers={"location": "javascript:alert(1)"}),
    ])
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.success is False
    assert result.error_kind == FetchErrorKind.POLICY
    assert "scheme" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_https_to_http_downgrade_flagged_in_hop_note():
    fetcher, _ = _fetcher([
        httpx.Response(302, headers={"location": "http://example.com/plain"}),
        html_response(200, b"<html><title>Plain</title></html>"),
    ])
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.success is True
    assert "TLS downgrade" in (result.hops[0].note or "")


@pytest.mark.asyncio
async def test_non_standard_port_refused():
    fetcher, _ = _fetcher([html_response(200)])
    norm = normalize_url("https://example.com:8443/")
    result = await fetcher.fetch(norm)

    assert result.success is False
    assert result.error_kind == FetchErrorKind.POLICY
    assert "port" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_non_textual_body_is_never_read():
    # application/octet-stream: the body is not read at all (no file downloads).
    fetcher, _ = _fetcher([
        httpx.Response(200, headers={"content-type": "application/octet-stream", "content-length": str(10 * 1024 * 1024)},
                       content=b"")
    ])
    norm = normalize_url("https://example.com/file.bin")
    result = await fetcher.fetch(norm)

    assert result.success is True
    assert result.total_bytes == 0  # body never read
    assert result.hops[0].bytes_read == 0


@pytest.mark.asyncio
async def test_size_cap_truncates_body():
    big_html = b"<html><title>Big</title>" + b"x" * 200_000 + b"</html>"
    fetcher, _ = _fetcher([html_response(200, big_html)], fetch_max_bytes=50_000)
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.success is True
    assert result.size_capped is True
    assert result.total_bytes <= 50_000 + 65536  # capped within one chunk


@pytest.mark.asyncio
async def test_private_dns_answer_refused():
    # In production the pinning backend enforces this; with an injected transport we
    # verify the fetcher records the refusal raised by the validation path.
    settings = make_settings()
    resolver = FakeResolver({"intranet.example": ["192.168.1.10"]})
    # No transport injection: default transport would really dial. Instead wrap the
    # fetcher with a transport that mimics the policy error surface.
    class PolicyTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await resolver.resolve_and_validate("intranet.example")  # raises SSRFPolicyError
            raise AssertionError("unreachable")

    fetcher = SafeFetcher(settings, resolver=resolver, transport=PolicyTransport())
    norm = normalize_url("http://intranet.example/")
    result = await fetcher.fetch(norm)

    assert result.success is False
    assert result.error_kind == FetchErrorKind.POLICY
    assert "192.168.1.10" in (result.error or "")


@pytest.mark.asyncio
async def test_dns_failure_recorded():
    # In production the pinning backend raises DnsFailure before dialing;
    # emulate that surface by raising it from the transport.
    from app.pipeline.ssrf import DnsFailure as DnsFailureError

    fetcher, _ = _fetcher([DnsFailureError("example.com", "domain does not exist (NXDOMAIN)")], mapping={})
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.success is False
    assert result.error_kind == FetchErrorKind.DNS
    assert result.hops[0].note and "DNS" in result.hops[0].note


@pytest.mark.asyncio
async def test_timeout_recorded():
    fetcher, _ = _fetcher([httpx.ConnectTimeout("timed out")])
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.success is False
    assert result.error_kind == FetchErrorKind.TIMEOUT


@pytest.mark.asyncio
async def test_connection_error_recorded():
    fetcher, _ = _fetcher([httpx.ConnectError("connection refused")])
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.success is False
    assert result.error_kind == FetchErrorKind.CONNECTION


@pytest.mark.asyncio
async def test_tls_certificate_error_classified_as_tls():
    inner = httpx.ConnectError("certificate verify failed")
    inner.__cause__ = __import__("ssl").SSLCertVerificationError(1, "self-signed certificate")
    fetcher, _ = _fetcher([inner])
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.success is False
    assert result.error_kind == FetchErrorKind.TLS


@pytest.mark.asyncio
async def test_hop_evidence_contains_resolved_ips():
    fetcher, _ = _fetcher([html_response(200)])
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.hops[0].resolved_ips == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_user_agent_is_honest_bot():
    fetcher, transport = _fetcher([html_response(200)])
    norm = normalize_url("https://example.com/")
    await fetcher.fetch(norm)

    assert "TrustLensBot" in transport.requests[0].headers["user-agent"]


# ---- fail-closed transport (SSRF hardening) --------------------------------------


@pytest.mark.asyncio
async def test_transport_init_failure_fails_closed(monkeypatch):
    """If the IP-pinning transport cannot be constructed, EVERY fetch is
    refused with a POLICY error before any network activity — there is no
    plain-transport fallback."""
    import httpcore

    def broken_pool(*args, **kwargs):
        raise RuntimeError("httpx internals changed (simulated)")

    monkeypatch.setattr(httpcore, "AsyncConnectionPool", broken_pool)

    resolver = FakeResolver({"example.com": ["93.184.216.34"]})
    fetcher = SafeFetcher(make_settings(), resolver=resolver)
    assert fetcher._transport is None

    result = await fetcher.fetch(normalize_url("https://example.com/"))
    assert result.success is False
    assert result.error_kind == FetchErrorKind.POLICY
    assert "never contacted" in (result.error or "")
    assert result.final_url is None
    # No DNS resolution / connection attempt happened at all.
    assert resolver.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("target", [
    "http://192.168.1.10/",                                   # private
    "http://127.0.0.1:8000/",                                 # loopback
    "http://169.254.169.254/latest/meta-data/",               # link-local / cloud metadata
    "http://[fe80::1]/",                                      # IPv6 link-local
    "http://metadata.google.internal/computeMetadata/v1/",    # metadata hostname
])
async def test_private_and_metadata_targets_blocked_when_transport_setup_fails(monkeypatch, target):
    """Even with a broken transport setup, private/loopback/link-local/metadata
    targets must remain blocked — and no request may be sent."""
    import httpcore

    sent_requests: list[object] = []

    class RecordingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):  # pragma: no cover
            sent_requests.append(request)
            return html_response(200)

    monkeypatch.setattr(httpcore, "AsyncConnectionPool",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no pool")))

    resolver = FakeResolver({})  # would raise DnsFailure if ever consulted
    fetcher = SafeFetcher(make_settings(), resolver=resolver, transport=RecordingTransport())
    # Simulate the broken-default-transport path: force the refusal gate.
    fetcher._transport = None
    fetcher._init_error = "simulated init failure"

    result = await fetcher.fetch(normalize_url(target))
    assert result.success is False
    assert result.error_kind == FetchErrorKind.POLICY
    assert sent_requests == []            # no request was sent
    assert resolver.calls == []           # not even a DNS lookup


# ---- per-hop certificate capture ---------------------------------------------------


def _self_signed_der(cn: str) -> bytes:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class _FakeSslObject:
    def __init__(self, der: bytes):
        self._der = der

    def getpeercert(self, binary_form=False):
        return self._der if binary_form else {}


class _FakeNetworkStream:
    def __init__(self, der: bytes):
        self._der = der

    def get_extra_info(self, name):
        if name == "ssl_object":
            return _FakeSslObject(self._der)
        return None


@pytest.mark.asyncio
async def test_cert_capture_uses_final_hops_certificate(monkeypatch):
    """After a cross-host redirect the TLS analyser must see the FINAL
    connection's certificate — the capture buffer resets on every hop."""
    der1 = _self_signed_der("first.example")
    der2 = _self_signed_der("second.example")

    def response_with_cert(status, der, headers=None):
        resp = httpx.Response(status, headers=headers or {}, content=b"<html><title>x</title></html>")
        resp.extensions["network_stream"] = _FakeNetworkStream(der)
        return resp

    fetcher, _ = _fetcher([
        response_with_cert(302, der1, {"location": "https://second.example/", "content-type": "text/html"}),
        response_with_cert(200, der2, {"content-type": "text/html"}),
    ], mapping={"example.com": ["93.184.216.34"], "second.example": ["93.184.216.35"]})
    norm = normalize_url("https://example.com/")
    result = await fetcher.fetch(norm)

    assert result.success is True
    from app.pipeline.fetcher import leaf_cert_sha256
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    assert leaf_cert_sha256(result.cert_pem) == hashlib.sha256(der2).hexdigest()
    # and it is parseable as a valid certificate for the final host
    certs = x509.load_pem_x509_certificates(result.cert_pem.encode())
    assert len(certs) == 1


@pytest.mark.asyncio
async def test_cert_capture_failure_leaves_pem_empty_not_garbage(monkeypatch):
    """A stream without usable cert extras must degrade to an empty capture —
    the runner then records tls-analysis as unavailable, never as clean."""
    resp = httpx.Response(200, content=b"<html><title>x</title></html>")
    resp.extensions["network_stream"] = _FakeNetworkStream(b"not-a-real-der-blob")
    fetcher, _ = _fetcher([resp])
    result = await fetcher.fetch(normalize_url("https://example.com/"))
    assert result.success is True
    assert result.cert_pem == ""
