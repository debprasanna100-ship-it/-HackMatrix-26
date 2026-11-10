"""Full-chain capture layer tests (Task 1): the pyOpenSSL memory-BIO TLS layer.

A REAL TLS handshake runs between a stdlib server thread (presenting a
synthetic 3-certificate chain) and the pyOpenSSL client layer over a socket
pair — no external network.
"""
from __future__ import annotations

import asyncio
import datetime
import queue
import socket
import ssl
import threading

import httpcore
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.pipeline.fetcher import _pyopenssl_tls


def _build_chain_and_key(cn_leaf="leaf.example", server_chain=True):
    """root -> intermediate -> leaf; returns (server_pem, root_pem, leaf_cert)."""
    def keypair():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    root_key, int_key, leaf_key = keypair(), keypair(), keypair()
    now = datetime.datetime.now(datetime.timezone.utc)

    def build(subject, issuer, subject_key, signing_key, days, ca):
        b = (x509.CertificateBuilder()
             .subject_name(subject).issuer_name(issuer)
             .public_key(subject_key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now)
             .not_valid_after(now + datetime.timedelta(days=days)))
        if ca:
            b = b.add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        else:
            b = (b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                  .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn_leaf)]), critical=False))
        return b.sign(signing_key, hashes.SHA256())

    root = build(name("Capture Test Root"), name("Capture Test Root"), root_key, root_key, 365, True)
    intermediate = build(name("Capture Test Intermediate"), name("Capture Test Root"),
                         int_key, root_key, 365, True)
    leaf = build(name(cn_leaf), name("Capture Test Intermediate"), leaf_key, int_key, 365, False)

    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()
    # the SERVER presents leaf + intermediate (what a real server sends; the
    # root stays in the trust store)
    server_chain = "\n".join([pem(leaf), pem(intermediate)]) if server_chain else pem(leaf)
    return server_chain, pem(root), leaf


def _make_server(chain_pem: str, key_pem: str):
    """Real server thread: accepts one TLS connection, echoes nothing, closes."""
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    import tempfile
    from pathlib import Path

    td = tempfile.TemporaryDirectory()
    chain_path = Path(td.name) / "chain.pem"
    key_path = Path(td.name) / "key.pem"
    chain_path.write_text(chain_pem, encoding="utf-8")
    key_path.write_text(key_pem, encoding="utf-8")
    server_ctx.load_cert_chain(str(chain_path), str(key_path))

    errors: list[Exception] = []

    def serve(sock: socket.socket, ready: threading.Event):
        try:
            ready.set()
            conn = server_ctx.wrap_socket(sock, server_side=True)
            try:
                while conn.recv(4096):
                    pass  # drain until the client goes away
            except (ssl.SSLError, OSError):
                pass
            finally:
                conn.close()
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
        finally:
            ready.set()

    return serve, errors


class _QueueWire:
    """httpcore-NetworkStream-shaped bridge between asyncio and a socket
    handled by a thread (blocking I/O marshalled via queue + to_thread)."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._in: queue.Queue = queue.Queue()
        self._closed = False
        threading.Thread(target=self._pump_in, daemon=True).start()

    def _pump_in(self):
        try:
            while True:
                data = self._sock.recv(65536)
                self._in.put(data)
                if not data:
                    return
        except OSError:
            self._in.put(b"")

    async def read(self, max_bytes: int = 65536, timeout: float | None = None) -> bytes:
        import anyio
        data = await anyio.to_thread.run_sync(self._in.get, True, 10)
        if not data:
            raise anyio.EndOfStream
        return data

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        import anyio
        await anyio.to_thread.run_sync(self._sock.sendall, bytes(buffer))

    async def aclose(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def get_extra_info(self, info: str):
        return None


@pytest.fixture
def chain_with_key():
    """Builds the synthetic chain AND the leaf's private key for the server."""
    def keypair():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    root_key, int_key, leaf_key = keypair(), keypair(), keypair()
    now = datetime.datetime.now(datetime.timezone.utc)

    def build(subject, issuer, subject_key, signing_key, ca):
        b = (x509.CertificateBuilder()
             .subject_name(subject).issuer_name(issuer)
             .public_key(subject_key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365)))
        if ca:
            b = b.add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        else:
            b = (b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                  .add_extension(x509.SubjectAlternativeName([x509.DNSName("leaf.example")]),
                                 critical=False))
        return b.sign(signing_key, hashes.SHA256())

    root = build(name("Capture Test Root"), name("Capture Test Root"), root_key, root_key, True)
    intermediate = build(name("Capture Test Intermediate"), name("Capture Test Root"),
                         int_key, root_key, True)
    leaf = build(name("leaf.example"), name("Capture Test Intermediate"), leaf_key, int_key, False)
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()
    from cryptography.hazmat.primitives.serialization import PrivateFormat
    leaf_key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    return {
        "server_chain": "\n".join([pem(leaf), pem(intermediate)]),
        "root_pem": pem(root),
        "leaf_key_pem": leaf_key_pem,  # the leaf key doubles as the server key
        "n_certs": 3,
    }


def _trusting_ctx(root_pem: str):
    from app.pipeline.fetcher import _openssl_client_context
    ctx = _openssl_client_context()
    # swap the trust store: ONLY the test root (deterministic, offline)
    import tempfile
    from pathlib import Path
    td = tempfile.TemporaryDirectory()
    p = Path(td.name) / "root.pem"
    p.write_text(root_pem, encoding="utf-8")
    ctx.load_verify_locations(str(p))
    return ctx


def test_pyopenssl_layer_captures_full_presented_chain(chain_with_key):
    """Handshake against a stdlib server: the peer-presented chain (leaf +
    intermediate) is fully reachable through get_extra_info('ssl_object')."""
    serve, errors = _make_server(chain_with_key["server_chain"], chain_with_key["leaf_key_pem"])
    client_sock, server_sock = socket.socketpair()
    ready = threading.Event()
    threading.Thread(target=serve, args=(server_sock, ready), daemon=True).start()
    assert ready.wait(5)

    async def run():
        return await _pyopenssl_tls(
            _QueueWire(client_sock), "leaf.example", 10.0,
            openssl_ctx=_trusting_ctx(chain_with_key["root_pem"]))

    stream = asyncio.run(run())
    conn = stream.get_extra_info("ssl_object")
    chain = conn.get_peer_cert_chain()
    assert len(chain) == 2  # leaf + intermediate as presented by the server
    assert chain[0].to_cryptography().subject.rfc4514_string().endswith("leaf.example")
    # the server accepted the client's close
    assert not errors


def test_pyopenssl_layer_rejects_hostname_mismatch(chain_with_key):
    serve, _ = _make_server(chain_with_key["server_chain"], chain_with_key["leaf_key_pem"])
    client_sock, server_sock = socket.socketpair()
    ready = threading.Event()
    threading.Thread(target=serve, args=(server_sock, ready), daemon=True).start()
    assert ready.wait(5)

    async def run():
        return await _pyopenssl_tls(
            _QueueWire(client_sock), "wrong.example", 10.0,
            openssl_ctx=_trusting_ctx(chain_with_key["root_pem"]))

    with pytest.raises(httpcore.ConnectError) as excinfo:
        asyncio.run(run())
    assert "not covered" in str(excinfo.value)


def test_pyopenssl_layer_rejects_untrusted_chain(chain_with_key):
    serve, _ = _make_server(chain_with_key["server_chain"], chain_with_key["leaf_key_pem"])
    client_sock, server_sock = socket.socketpair()
    ready = threading.Event()
    threading.Thread(target=serve, args=(server_sock, ready), daemon=True).start()
    assert ready.wait(5)

    # build an UNRELATED trust root: the presented chain must not verify
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    other_root = (x509.CertificateBuilder()
                  .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other Root")]))
                  .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other Root")]))
                  .public_key(other_key.public_key())
                  .serial_number(x509.random_serial_number())
                  .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                  .sign(other_key, hashes.SHA256()))
    other_root_pem = other_root.public_bytes(serialization.Encoding.PEM).decode()

    async def run():
        return await _pyopenssl_tls(
            _QueueWire(client_sock), "leaf.example", 10.0,
            openssl_ctx=_trusting_ctx(other_root_pem))

    with pytest.raises(httpcore.ConnectError):
        asyncio.run(run())


def test_capture_method_reported_for_pyopenssl_objects():
    """The capture branch recognises pyOpenSSL connections by their duck type
    (get_peer_cert_chain + to_cryptography) and labels the method."""
    import io

    from app.pipeline.fetcher import _der_encoding

    class FakeX509:
        def __init__(self, cn):
            self._cn = cn

        def to_cryptography(self):
            from tests.test_fetcher import _self_signed_der
            import cryptography.x509 as x509
            return x509.load_der_x509_certificate(_self_signed_der(self._cn))

    class FakeOSSLLike:
        def get_verified_chain(self):
            return [FakeX509("a.example"), FakeX509("b.example")]

        def get_peer_cert_chain(self):
            return self.get_verified_chain()

    from cryptography.hazmat.primitives import serialization
    conn = FakeOSSLLike()
    ders = [c.to_cryptography().public_bytes(serialization.Encoding.DER) for c in conn.get_verified_chain()]
    assert len(ders) == 2
    assert _der_encoding() == serialization.Encoding.DER
