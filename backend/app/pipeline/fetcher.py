"""SSRF-safe page fetcher with manual redirect tracing.

Safety properties:
  * GET only; http/https only; ports 80/443 only; userinfo refused;
  * DNS is resolved and validated inside the connection step (IP pinning via a
    custom httpx network backend), then the TCP dial goes straight to the
    validated IP while TLS still verifies against the original hostname;
  * redirects are followed manually, at most `fetch_max_redirects` hops, with
    scheme/port/credential re-validation on every hop;
  * responses are streamed with a hard byte cap; non-textual content is never
    read at all (no file downloads); JavaScript is never executed;
  * connect/read timeouts per hop plus a total time budget for the chain.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import ssl
import time
from urllib.parse import urljoin, urlsplit

import httpx
import httpcore

from ..config import Settings
from ..models.enums import FetchErrorKind
from ..models.schemas import FetchHop, SafeFetchResult
from .normalizer import NormalizedUrl
from .ssrf import DnsFailure, Resolver, SSRFPolicyError, SystemDnsResolver, classify_ip

logger = logging.getLogger("trustlens.fetcher")

USER_AGENT = "Mozilla/5.0 (compatible; TrustLensBot/0.1; passive-analysis; will not execute scripts)"
_MAX_HEADER_COUNT = 40
_MAX_HEADER_VALUE_LEN = 300
_MAX_IP_CONNECT_ATTEMPTS = 4

_TEXTUAL_HINTS = ("html", "xml", "json", "x-www-form-urlencoded", "plain")


def _is_textual(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return ct.startswith("text/") or any(h in ct for h in _TEXTUAL_HINTS)


def _cap_headers(headers: httpx.Headers) -> dict[str, str]:
    out: dict[str, str] = {}
    for i, (k, v) in enumerate(headers.items()):
        if i >= _MAX_HEADER_COUNT:
            out["x-trustlens-truncated"] = "header list truncated"
            break
        out[k.lower()] = v[:_MAX_HEADER_VALUE_LEN]
    return out


def _peer_ip(response: httpx.Response) -> str | None:
    """Best-effort peer address from the underlying stream (evidence only)."""
    try:
        stream = response.extensions.get("network_stream")
        info = stream.get_extra_info("peername") if stream is not None else None
        if info:
            return str(info[0])
    except Exception:  # pragma: no cover - depends on backend internals
        return None
    return None


def _error_chain(exc: BaseException):
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _is_tls_error(exc: BaseException) -> bool:
    for link in _error_chain(exc):
        if isinstance(link, (ssl.SSLError, ssl.CertificateError)):
            return True
        try:  # the pyOpenSSL capture layer raises its own SSL.Error type
            from OpenSSL import SSL as _ossl
            if isinstance(link, _ossl.Error):
                return True
        except ImportError:  # pragma: no cover - pyOpenSSL is a hard dependency
            pass
        if isinstance(link, OSError) and "certificate" in str(link).lower():
            return True
    return False


def _der_encoding():
    """DER encoding for certificate serialisation (import-local helper)."""
    from cryptography.hazmat.primitives import serialization
    return serialization.Encoding.DER


def _detail(exc: BaseException) -> str:
    text = str(exc).strip()
    return text[:300] if text else type(exc).__name__


# ---- pyOpenSSL TLS layer (full-chain capture for CPython < 3.13) -----------------
#
# CPython 3.11/3.12 expose NO way to read the peer-presented certificate chain
# from a stdlib ssl.SSLObject (get_unverified_chain/get_verified_chain arrive
# in 3.13). pyOpenSSL's Connection DOES expose the chain — but it must own the
# handshake. httpcore calls `stream.start_tls(...)` on whatever connect_tcp
# returned, so the pinning backend wraps its TCP stream: start_tls() first
# tries the pyOpenSSL memory-BIO layer (full verification against the system
# trust store + explicit hostname/SAN matching) and falls back to httpcore's
# stdlib layer on ANY failure — TLS security never depends on this layer, only
# capture completeness does.


def _openssl_client_context() -> "SSL.Context":
    import certifi
    from OpenSSL import SSL

    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.load_verify_locations(certifi.where())
    ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT)
    return ctx


class _SSLObjectView:
    """Facade over the pyOpenSSL Connection: httpcore probes
    `selected_alpn_protocol()` after the handshake (we always run HTTP/1.1 —
    the pool is built with http2=False), and every other attribute (chain
    getters, getpeercert) is forwarded to the real connection."""

    def __init__(self, conn):
        self._conn = conn

    def selected_alpn_protocol(self) -> str:
        return "http/1.1"

    def __getattr__(self, name):
        return getattr(self._conn, name)


class _PyOpenSSLNetworkStream:
    """httpcore-compatible NetworkStream over a pyOpenSSL Connection using
    memory BIOs, with the wire side driven by any httpcore byte stream."""

    def __init__(self, wire, conn, server_hostname: str | None):
        self._wire = wire
        self._conn = conn
        self._host = server_hostname

    async def _flush_bio(self) -> None:
        from OpenSSL import SSL
        while True:
            try:
                data = self._conn.bio_read(65536)
            except SSL.WantReadError:
                return
            await self._wire.write(data)

    async def _feed_bio(self, timeout: float | None) -> None:
        data = await self._wire.read(65536, timeout)
        if data:
            self._conn.bio_write(data)
        else:
            from httpcore._exceptions import ConnectError
            raise ConnectError("TLS peer closed the connection during handshake")

    async def _handshake(self, timeout: float | None) -> None:
        from OpenSSL import SSL
        try:
            while True:
                try:
                    self._conn.do_handshake()
                    return
                except SSL.WantReadError:
                    await self._flush_bio()
                    await self._feed_bio(timeout)
                except SSL.WantWriteError:
                    await self._flush_bio()
        except SSL.Error as exc:
            from httpcore._exceptions import ConnectError
            raise ConnectError(f"TLS handshake failed: {_detail(exc)}") from exc

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        from OpenSSL import SSL
        from httpcore._exceptions import ReadTimeout
        while True:
            try:
                return self._conn.recv(max_bytes)
            except SSL.ZeroReturnError:
                return b""
            except SSL.WantReadError:
                try:
                    await self._flush_bio()
                    await self._feed_bio(timeout)
                except TimeoutError as exc:
                    raise ReadTimeout(str(exc)) from exc

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        from OpenSSL import SSL
        from httpcore._exceptions import WriteTimeout
        view = memoryview(buffer)
        try:
            while view:
                try:
                    sent = self._conn.send(view)
                    view = view[sent:]
                except SSL.WantWriteError:
                    pass
                await self._flush_bio()
        except TimeoutError as exc:
            raise WriteTimeout(str(exc)) from exc

    async def aclose(self) -> None:
        from OpenSSL import SSL
        try:
            self._conn.shutdown()
            await self._flush_bio()
        except SSL.Error:
            pass
        await self._wire.aclose()

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):  # pragma: no cover
        raise NotImplementedError("TLS is already established on this stream")

    def get_extra_info(self, info: str):
        if info == "ssl_object":
            return _SSLObjectView(self._conn)
        if info == "server_hostname":
            return self._host
        return self._wire.get_extra_info(info)


async def _pyopenssl_tls(wire, server_hostname: str | None, timeout: float | None,
                         openssl_ctx=None) -> "_PyOpenSSLNetworkStream":
    """Run the client handshake over `wire` via pyOpenSSL; verify the chain
    against the system store and the hostname against the SANs."""
    import anyio
    from OpenSSL import SSL
    from httpcore._exceptions import ConnectError

    from .tls import check_host_in_sans

    ctx = openssl_ctx or _openssl_client_context()
    conn = SSL.Connection(ctx)
    if server_hostname:
        conn.set_tlsext_host_name(server_hostname.encode("idna"))
    conn.set_connect_state()

    class _Timeout:
        pass

    stream = _PyOpenSSLNetworkStream(wire, conn, server_hostname)
    try:
        with anyio.fail_after(timeout):
            await stream._handshake(timeout)
            # OpenSSL validated the chain to the trust store; hostname/SAN
            # matching is enforced here explicitly (pyOpenSSL exposes no
            # set1_host-style API).
            if server_hostname:
                chain = conn.get_peer_cert_chain() or []
                if not chain:
                    raise ConnectError("TLS peer presented no certificate")
                leaf = chain[0].to_cryptography()
                covered, note = check_host_in_sans(leaf, server_hostname)
                if not covered:
                    raise ConnectError(
                        f"hostname '{server_hostname}' is not covered by the certificate: {note}")
    except SSL.Error as exc:
        raise ConnectError(f"TLS handshake failed: {_detail(exc)}") from exc
    except TimeoutError as exc:  # anyio 4.x raises the builtin TimeoutError
        from httpcore._exceptions import ConnectTimeout
        raise ConnectTimeout("TLS handshake timed out") from exc
    return stream


class _ChainCaptureStream:
    """Delegating NetworkStream whose start_tls() prefers the pyOpenSSL
    full-chain-capture layer and falls back to the stdlib AnyIO layer."""

    def __init__(self, inner):
        self._inner = inner

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._inner.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._inner.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        try:
            return await _pyopenssl_tls(self._inner, server_hostname, timeout)
        except Exception as exc:
            logger.warning("pyOpenSSL capture layer unavailable (%s: %s); using stdlib TLS "
                           "(leaf-only capture)", type(exc).__name__, _detail(exc))
            return await self._inner.start_tls(ssl_context, server_hostname, timeout)

    def get_extra_info(self, info: str):
        return self._inner.get_extra_info(info)


_BaseNetworkBackend = getattr(httpcore, "AnyIOBackend", None) or httpcore.AsyncNetworkBackend


class _PinningNetworkBackend(_BaseNetworkBackend):
    """Resolves + validates the host itself, then dials the validated IP directly.

    Every TCP connection (initial URL and every redirect hop) goes through
    `connect_tcp`, so resolution + SSRF validation happen immediately before
    the socket dial — there is no resolve-then-connect rebinding window. The
    dial target is the validated IP address only.

    httpcore passes the *original* hostname to the TLS layer (SNI + certificate
    verification) regardless of which address we dial, so certificate checking
    remains fully intact and tied to the hostname the user requested. The
    returned stream additionally routes start_tls() through the pyOpenSSL
    capture layer (see `_ChainCaptureStream`).
    """

    def __init__(self, resolver: Resolver):
        super().__init__()
        self._resolver = resolver

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        allowed = await self._resolver.resolve_and_validate(host)
        last_error: OSError | None = None
        for ip in allowed[:_MAX_IP_CONNECT_ATTEMPTS]:
            try:
                return _ChainCaptureStream(await super().connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                ))
            except OSError as exc:
                last_error = exc
        raise last_error if last_error else OSError(f"no validated address could be dialed for {host}")


class TransportInitError(RuntimeError):
    """The SSRF IP-pinning transport could not be constructed."""


class SafeFetcher:
    """Per-analysis fetcher. A custom `transport` may be injected for tests.

    Security: there is NO plain-transport fallback. If the IP-pinning transport
    cannot be constructed, every fetch fails closed with a POLICY error before
    any network request — a fetch without per-connection address validation
    would bypass the SSRF policy, so it is refused outright.
    """

    def __init__(self, settings: Settings, resolver: Resolver | None = None, transport: httpx.AsyncBaseTransport | None = None):
        self._settings = settings
        self._resolver: Resolver = resolver or SystemDnsResolver()
        self._init_error: str | None = None
        self._client_instance: httpx.AsyncClient | None = None
        if transport is not None:
            self._transport: httpx.AsyncBaseTransport | None = transport
        else:
            try:
                self._transport = self._default_transport()
            except Exception as exc:
                # Fail closed: keep the error for a clear refusal at fetch time.
                self._transport = None
                self._init_error = f"{type(exc).__name__}: {str(exc)[:200]}"
                logger.error("IP-pinning transport unavailable (%s); all fetches will be refused", self._init_error)

    def _default_transport(self) -> httpx.AsyncBaseTransport:
        """httpx transport whose connection pool dials only validated IPs.

        httpx (0.28) does not expose `network_backend` publicly, so the pool is
        rebuilt with our pinning backend and swapped in. Raises (never falls
        back to a plain transport) when httpx internals change — callers fail
        closed instead of silently losing SSRF validation.
        """
        from httpx._transports.default import create_ssl_context

        transport = httpx.AsyncHTTPTransport(verify=True, http2=False, trust_env=False, retries=0)
        ssl_context = create_ssl_context(verify=True, cert=None, trust_env=False)
        transport._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            network_backend=_PinningNetworkBackend(self._resolver),
            http1=True,
            http2=False,
            keepalive_expiry=10.0,
        )
        return transport

    def _client(self) -> httpx.AsyncClient:
        if self._client_instance is None or self._client_instance.is_closed:
            self._client_instance = httpx.AsyncClient(
                transport=self._transport,
                trust_env=False,
                follow_redirects=False,  # redirects are followed manually, hop by hop
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5",
                    "Accept-Language": "en-US,en;q=0.5",
                },
            )
        return self._client_instance

    async def aclose(self) -> None:
        if self._client_instance is not None and not self._client_instance.is_closed:
            await self._client_instance.aclose()

    async def fetch(self, norm: NormalizedUrl) -> SafeFetchResult:
        settings = self._settings
        started = time.monotonic()
        hops: list[FetchHop] = []
        url = norm.url
        final_url: str | None = None
        status_code: int | None = None
        final_headers: dict[str, str] = {}
        title: str | None = None
        body_excerpt: str | None = None
        content_type: str | None = None
        error_kind = FetchErrorKind.NONE
        error: str | None = None
        success = False
        size_capped = False
        cert_pem: list[str] = []  # raw certs presented by the FINAL connection (TLS analysis input)
        capture_method = "unavailable"  # how the final connection's chain was captured

        # ---- fail closed: never send a request without IP-pinning validation ----
        if self._transport is None:
            return SafeFetchResult(
                requested_url=norm.url,
                final_url=None,
                status_code=None,
                success=False,
                ok=False,
                error_kind=FetchErrorKind.POLICY,
                error=(
                    "fetch refused: the SSRF IP-pinning transport is not available "
                    f"({self._init_error}); the target was never contacted"
                ),
                hops=hops,
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )

        client = self._client()
        try:
            for _hop_index in range(settings.fetch_max_redirects + 1):
                if time.monotonic() - started > settings.fetch_total_budget:
                    error_kind = FetchErrorKind.TIMEOUT
                    error = f"total analysis time budget of {settings.fetch_total_budget:.0f}s exceeded"
                    break

                try:
                    parts = urlsplit(url)
                    hop_port = parts.port
                except ValueError as exc:
                    error_kind = FetchErrorKind.POLICY
                    error = f"redirect target has invalid host/port: {exc}"
                    break

                if parts.scheme not in ("http", "https"):
                    error_kind = FetchErrorKind.POLICY
                    error = f"redirect target uses unsupported scheme '{parts.scheme or 'none'}'; only http/https are fetched"
                    break
                if hop_port is not None and hop_port not in settings.allowed_fetch_ports:
                    error_kind = FetchErrorKind.POLICY
                    error = f"port {hop_port} is not allowed (only {settings.allowed_fetch_ports})"
                    break
                if parts.username or parts.password:
                    error_kind = FetchErrorKind.POLICY
                    error = "URL embeds credentials (userinfo), refused by policy"
                    break

                hop_started = time.monotonic()
                timeout = httpx.Timeout(
                    connect=settings.fetch_connect_timeout,
                    read=settings.fetch_read_timeout,
                    write=5.0,
                    pool=3.0,
                )
                try:
                    async with client.stream("GET", url, timeout=timeout) as response:
                        status_code = response.status_code
                        headers = _cap_headers(response.headers)
                        ct = (response.headers.get("content-type") or "").lower()
                        location = response.headers.get("location")
                        peer = _peer_ip(response)

                        # Capture the certificate chain presented on THIS connection.
                        # Newer interpreters expose the peer-presented chain via
                        # SSLObject.get_unverified_chain() (and the trust-store-
                        # completed chain via get_verified_chain()); on CPython
                        # 3.11/3.12 neither exists, so capture degrades to
                        # leaf-only and the method is recorded. The buffer is
                        # reset on every hop so that after a redirect the TLS
                        # analyser sees the FINAL connection's chain, not the
                        # first hop's.
                        cert_pem.clear()
                        capture_method = "leaf-only"
                        if response.extensions.get("network_stream"):
                            try:
                                stream = response.extensions["network_stream"]
                                ssl_object = stream.get_extra_info("ssl_object")
                                chain_der: list[bytes] = []
                                if ssl_object is not None and hasattr(ssl_object, "get_peer_cert_chain") \
                                        and hasattr(ssl_object, "get_verified_chain"):
                                    # --- pyOpenSSL layer (CPython < 3.13) ---
                                    try:  # complete chain incl. trust-store root
                                        verified = ssl_object.get_verified_chain()
                                        if verified:
                                            chain_der = [c.to_cryptography().public_bytes(
                                                _der_encoding()) for c in verified]
                                            capture_method = "verified-chain (pyOpenSSL)"
                                    except Exception:
                                        chain_der = []
                                    if not chain_der:
                                        presented = ssl_object.get_peer_cert_chain() or []
                                        if presented:
                                            chain_der = [c.to_cryptography().public_bytes(
                                                _der_encoding()) for c in presented]
                                            capture_method = "unverified-chain (pyOpenSSL)"
                                elif ssl_object is not None:
                                    # --- native stdlib layer (CPython 3.13+) ---
                                    # Prefer the peer-presented chain: it is what the
                                    # server actually sent (deterministic across
                                    # machines — unlike get_verified_chain(), which
                                    # appends intermediates/roots from the LOCAL trust
                                    # store and would make report hashes
                                    # host-dependent).
                                    for getter, method in (
                                        ("get_unverified_chain", "unverified-chain"),
                                        ("get_verified_chain", "verified-chain"),
                                    ):
                                        try:
                                            raw = getattr(ssl_object, getter, None)
                                            if callable(raw):
                                                presented = raw()
                                                if presented:
                                                    chain_der = [bytes(c) for c in presented]
                                                    capture_method = method
                                                    break
                                        except Exception:
                                            continue
                                if not chain_der:
                                    # Fallback: leaf-only via the documented extras.
                                    cert_der = None
                                    if ssl_object is not None:
                                        cert_der = ssl_object.getpeercert(binary_form=True) \
                                            if hasattr(ssl_object, "getpeercert") else None
                                    if not isinstance(cert_der, bytes) or not cert_der:
                                        cert_der = stream.get_extra_info("peercert")
                                    if isinstance(cert_der, bytes) and cert_der:
                                        chain_der = [cert_der]
                                        capture_method = "leaf-only"
                                if chain_der:
                                    import cryptography.x509 as _x509
                                    from cryptography.hazmat.primitives import serialization as _ser
                                    for der in chain_der:
                                        cert_pem.append(
                                            _x509.load_der_x509_certificate(der).public_bytes(
                                                _ser.Encoding.PEM).decode()
                                        )
                            except Exception:  # pragma: no cover - backend internals vary
                                cert_pem.clear()
                                capture_method = "unavailable"

                        if peer is not None:
                            try:
                                reason = classify_ip(ipaddress.ip_address(peer))
                            except ValueError:
                                reason = None
                            if reason:
                                hops.append(FetchHop(
                                    url=url, status=status_code, ok=False, content_type=ct.split(";")[0],
                                    resolved_ips=[], peer_ip=peer,
                                    elapsed_ms=int((time.monotonic() - hop_started) * 1000),
                                    note=f"connected peer {peer} is in a blocked range ({reason}); aborting",
                                ))
                                error_kind = FetchErrorKind.POLICY
                                error = f"connected peer address {peer} is in a blocked range: {reason}"
                                break

                        is_redirect = status_code in (301, 302, 303, 307, 308) and bool(location)
                        bytes_read = 0
                        chunks: list[bytes] = []
                        note: str | None = None

                        if not is_redirect and status_code < 400 and _is_textual(ct):
                            try:
                                async for chunk in response.aiter_bytes(65536):
                                    bytes_read += len(chunk)
                                    chunks.append(chunk)
                                    if bytes_read >= settings.fetch_max_bytes:
                                        size_capped = True
                                        note = (note + " | " if note else "") + (
                                            f"response size cap of {settings.fetch_max_bytes} bytes reached; body truncated"
                                        )
                                        break
                            except httpx.StreamError as exc:
                                note = (note + " | " if note else "") + f"body stream interrupted: {type(exc).__name__}"

                        hop = FetchHop(
                            url=url,
                            status=status_code,
                            ok=200 <= status_code < 400,
                            location=location if is_redirect else None,
                            content_type=ct.split(";")[0] or None,
                            server=headers.get("server"),
                            resolved_ips=await self._resolved_for_evidence(parts.hostname or ""),
                            peer_ip=peer,
                            elapsed_ms=int((time.monotonic() - hop_started) * 1000),
                            bytes_read=bytes_read,
                            note=note,
                        )
                        hops.append(hop)

                        if is_redirect:
                            next_url = urljoin(url, (location or "").strip())
                            next_parts = urlsplit(next_url)
                            if parts.scheme == "https" and next_parts.scheme == "http":
                                hop.note = (hop.note + " | " if hop.note else "") + \
                                    "TLS downgrade: https redirect to http"
                            url = next_url
                            continue

                        final_url = url
                        final_headers = headers
                        content_type = ct.split(";")[0] or None
                        success = True
                        if chunks:
                            body_excerpt = b"".join(chunks)[:131072].decode("utf-8", errors="replace")
                            title = _extract_title(body_excerpt)
                        break

                except SSRFPolicyError as exc:
                    error_kind = FetchErrorKind.POLICY
                    error = f"refused by SSRF policy: {exc.reason}"
                    hops.append(FetchHop(
                        url=url, ok=False, resolved_ips=list(exc.blocked),
                        elapsed_ms=int((time.monotonic() - hop_started) * 1000),
                        note=f"blocked by SSRF policy: {exc.reason}",
                    ))
                    break
                except DnsFailure as exc:
                    error_kind = FetchErrorKind.DNS
                    error = str(exc)
                    hops.append(FetchHop(
                        url=url, ok=False,
                        elapsed_ms=int((time.monotonic() - hop_started) * 1000),
                        note=f"DNS failure: {exc.reason}",
                    ))
                    break
                except httpx.TimeoutException as exc:
                    error_kind = FetchErrorKind.TIMEOUT
                    error = f"request timed out ({type(exc).__name__})"
                    hops.append(FetchHop(
                        url=url, ok=False,
                        elapsed_ms=int((time.monotonic() - hop_started) * 1000),
                        note=error,
                    ))
                    break
                except httpx.ConnectError as exc:
                    if _is_tls_error(exc):
                        error_kind = FetchErrorKind.TLS
                        error = f"TLS/certificate error: {_detail(exc)}"
                    else:
                        error_kind = FetchErrorKind.CONNECTION
                        error = f"connection failed: {_detail(exc)}"
                    hops.append(FetchHop(
                        url=url, ok=False,
                        elapsed_ms=int((time.monotonic() - hop_started) * 1000),
                        note=error,
                    ))
                    break
                except (httpx.UnsupportedProtocol, httpx.InvalidURL) as exc:
                    # httpx raises UnsupportedProtocol for non-http(s) redirect
                    # schemes and InvalidURL for unparsable Location headers —
                    # both are policy refusals, not fetch errors.
                    error_kind = FetchErrorKind.POLICY
                    error = (
                        "redirect target refused (unsupported scheme or malformed Location header): "
                        f"{_detail(exc)}"
                    )
                    hops.append(FetchHop(
                        url=url, ok=False,
                        elapsed_ms=int((time.monotonic() - hop_started) * 1000),
                        note=error,
                    ))
                    break
                except httpx.HTTPError as exc:
                    error_kind = FetchErrorKind.HTTP
                    error = f"HTTP protocol error: {type(exc).__name__}: {_detail(exc)}"
                    hops.append(FetchHop(
                        url=url, ok=False,
                        elapsed_ms=int((time.monotonic() - hop_started) * 1000),
                        note=error,
                    ))
                    break
                except (OSError, ValueError) as exc:
                    error_kind = FetchErrorKind.OTHER
                    error = f"fetch failed: {type(exc).__name__}: {_detail(exc)}"
                    hops.append(FetchHop(
                        url=url, ok=False,
                        elapsed_ms=int((time.monotonic() - hop_started) * 1000),
                        note=error,
                    ))
                    break
            else:
                error_kind = FetchErrorKind.POLICY
                error = f"exceeded maximum of {settings.fetch_max_redirects} redirects"
        finally:
            pass

        total_bytes = sum(h.bytes_read for h in hops)
        cert_pem = "\n".join(cert_pem) if cert_pem else ""
        return SafeFetchResult(
            requested_url=norm.url,
            final_url=final_url,
            status_code=status_code,
            success=success,
            ok=success and status_code is not None and 200 <= status_code < 400,
            error_kind=error_kind,
            error=error,
            hops=hops,
            response_headers=final_headers,
            title=title,
            content_type=content_type,
            total_bytes=total_bytes,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            size_capped=size_capped,
            cert_pem=cert_pem,  # internal: TLS analyser input
            cert_capture_method=capture_method,  # internal: how the chain was captured
            body_excerpt=body_excerpt or "",  # internal: title + mixed-content scan
        )

    async def _resolved_for_evidence(self, host: str) -> list[str]:
        """Best-effort resolution for hop evidence (never raises)."""
        if not host:
            return []
        try:
            ipaddress.ip_address(host.strip("[]"))
            return [host.strip("[]")]
        except ValueError:
            pass
        try:
            return await self._resolver.resolve(host)
        except Exception:
            return []

def leaf_cert_sha256(cert_pem: str) -> str:
    """Compute the SHA-256 of the leaf certificate in a PEM chain (Phase 2+)."""
    if not cert_pem.strip():
        return ""
    try:
        import cryptography.x509
        from cryptography.hazmat.primitives import serialization
        # load_pem_x509_certificates requires bytes, not str.
        chain = cryptography.x509.load_pem_x509_certificates(cert_pem.encode("utf-8"))
        leaf = chain[0]
        import hashlib
        return hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()
    except Exception:
        return ""

def _extract_title(body: str) -> str | None:
    import html
    import re as _re

    match = _re.search(r"<title[^>]*>(.*?)</title>", body, _re.IGNORECASE | _re.DOTALL)
    if not match:
        return None
    text = _re.sub(r"<[^>]+>", " ", match.group(1))
    text = html.unescape(text)
    text = " ".join(ch if ch == "\t" else ch for ch in text.split())
    text = " ".join(text.split())
    text = "".join(ch for ch in text if ch >= " " or ch == "\t")
    return text[:200] or None
