"""SSRF protection: hostname policy, IP range guards, and DNS resolution.

Every outbound connection made by TrustLens goes through `Resolver.resolve_and_validate`
(via the pinning network backend in `fetcher.py`). The guarantees:

  * only http/https URLs reach the fetcher (enforced earlier by the normaliser and
    re-checked per hop by the fetcher);
  * hostnames on internal/metdata lists are refused before any DNS query;
  * every resolved A/AAAA address is checked against blocked ranges — if *any*
    address is blocked, the whole target is refused (conservative: mixed
    public/private answers are a classic DNS-rebinding signal);
  * IPv4-mapped IPv6, NAT64, 6to4 and Teredo tunnel forms are unwrapped and their
    embedded IPv4 re-checked;
  * resolution happens inside the connect step, immediately before the TCP dial,
    which removes the classic resolve-then-connect DNS-rebinding TOCTOU window.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Iterable, Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
}
BLOCKED_HOSTNAME_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".lan",
    ".corp",
    ".home.arpa",
)

_HOSTNAME_ALLOWED_RE = __import__("re").compile(r"^[a-z0-9.\-]+$")

_BLOCKED_V4: list[tuple[ipaddress.IPv4Network, str]] = [
    (ipaddress.ip_network("0.0.0.0/8"), "unspecified network (0.0.0.0/8)"),
    (ipaddress.ip_network("10.0.0.0/8"), "private network (10.0.0.0/8)"),
    (ipaddress.ip_network("100.64.0.0/10"), "carrier-grade NAT (100.64.0.0/10)"),
    (ipaddress.ip_network("127.0.0.0/8"), "loopback (127.0.0.0/8)"),
    (ipaddress.ip_network("169.254.0.0/16"), "link-local incl. cloud metadata (169.254.0.0/16)"),
    (ipaddress.ip_network("172.16.0.0/12"), "private network (172.16.0.0/12)"),
    (ipaddress.ip_network("192.0.0.0/24"), "IETF protocol assignments (192.0.0.0/24)"),
    (ipaddress.ip_network("192.0.2.0/24"), "documentation range (192.0.2.0/24)"),
    (ipaddress.ip_network("192.168.0.0/16"), "private network (192.168.0.0/16)"),
    (ipaddress.ip_network("198.18.0.0/15"), "network benchmarking (198.18.0.0/15)"),
    (ipaddress.ip_network("198.51.100.0/24"), "documentation range (198.51.100.0/24)"),
    (ipaddress.ip_network("203.0.113.0/24"), "documentation range (203.0.113.0/24)"),
    (ipaddress.ip_network("224.0.0.0/4"), "multicast (224.0.0.0/4)"),
    (ipaddress.ip_network("240.0.0.0/4"), "reserved (240.0.0.0/4)"),
    # Deprecated 6to4 relay-anycast prefix (RFC 7526) — never a legit dial target.
    (ipaddress.ip_network("192.88.99.0/24"), "6to4 relay anycast, deprecated (192.88.99.0/24)"),
]

_BLOCKED_V6: list[tuple[ipaddress.IPv6Network, str]] = [
    (ipaddress.ip_network("::/128"), "unspecified address (::)"),
    (ipaddress.ip_network("::1/128"), "IPv6 loopback (::1)"),
    # Rest of the reserved low block (RFC 4291) — includes the deprecated
    # IPv4-compatible form ::a.b.c.d (e.g. ::127.0.0.1). IPv4-mapped
    # addresses (::ffff:x.x.x.x) never reach this entry: they are unwrapped
    # and re-checked as IPv4 first (audit L-K).
    (ipaddress.ip_network("::/8"), "reserved IPv6 block incl. deprecated IPv4-compatible form (::/8)"),
    (ipaddress.ip_network("fe80::/10"), "IPv6 link-local (fe80::/10)"),
    (ipaddress.ip_network("fc00::/7"), "IPv6 unique-local (fc00::/7)"),
    (ipaddress.ip_network("ff00::/8"), "IPv6 multicast (ff00::/8)"),
    (ipaddress.ip_network("2001:db8::/32"), "IPv6 documentation range (2001:db8::/32)"),
    (ipaddress.ip_network("64:ff9b::/96"), "NAT64 translation prefix (64:ff9b::/96)"),
    (ipaddress.ip_network("2001::/32"), "Teredo tunneling prefix (2001::/32)"),
]

_NET_6TO4 = ipaddress.ip_network("2002::/16")
_NET_V4MAPPED = ipaddress.ip_network("::ffff:0:0/96")


def classify_ip(ip: ipaddress._BaseAddress) -> str | None:
    """Return a human-readable reason if the IP must not be contacted, else None."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return classify_ip(ip.ipv4_mapped)
        if ip in _NET_6TO4:
            embedded = ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
            reason = classify_ip(embedded)
            if reason:
                return f"6to4 tunnel embedding a blocked IPv4 ({reason})"
            return "6to4 tunnel prefix (2002::/16)"
        for net, label in _BLOCKED_V6:
            if ip in net:
                return label
        return None
    for net, label in _BLOCKED_V4:
        if ip in net:
            return label
    return None


class SSRFPolicyError(Exception):
    """The target is refused by security policy before any connection is made."""

    def __init__(self, reason: str, host: str = "", blocked: Iterable[str] = ()):
        self.reason = reason
        self.host = host
        self.blocked = list(blocked)
        super().__init__(reason)


class DnsFailure(Exception):
    """DNS resolution failed or returned no usable address."""

    def __init__(self, host: str, reason: str):
        self.host = host
        self.reason = reason
        super().__init__(f"DNS resolution failed for '{host}': {reason}")


def check_hostname_allowed(host: str) -> None:
    h = (host or "").lower().rstrip(".")
    if not h:
        raise SSRFPolicyError("empty hostname", host=h)
    if not _HOSTNAME_ALLOWED_RE.match(h):
        raise SSRFPolicyError(f"hostname '{h}' contains characters not valid in a DNS name", host=h)
    if h in BLOCKED_HOSTNAMES:
        raise SSRFPolicyError(f"hostname '{h}' is blocked by SSRF policy", host=h)
    for suffix in BLOCKED_HOSTNAME_SUFFIXES:
        if h.endswith(suffix):
            raise SSRFPolicyError(f"hostname '{h}' uses the reserved suffix '{suffix}'", host=h)


class Resolver(Protocol):
    """Resolution boundary used by the fetcher (swap with fakes in tests)."""

    async def resolve(self, host: str) -> list[str]: ...

    async def resolve_and_validate(self, host: str) -> list[str]: ...


class SystemDnsResolver:
    """DNS resolver combining dnspython (A + AAAA) with a system fallback."""

    def __init__(self, timeout: float = 3.0):
        self._timeout = timeout

    async def resolve(self, host: str) -> list[str]:
        host = host.rstrip(".")
        loop = asyncio.get_running_loop()
        errors: list[str] = []

        async def query(rtype: str) -> list[str]:
            try:
                answers = await dns.asyncresolver.resolve(host, rtype, lifetime=self._timeout)
                return [r.to_text().split("%")[0] for r in answers]
            except dns.resolver.NXDOMAIN:
                raise DnsFailure(host, "domain does not exist (NXDOMAIN)")
            except (dns.exception.DNSException, OSError, TimeoutError, ValueError) as exc:
                # DNSException is the base of NoAnswer/NoNameservers/LifetimeTimeout/etc.
                errors.append(f"{rtype}: {type(exc).__name__}")
                return []

        a, aaaa = await asyncio.gather(query("A"), query("AAAA"))
        ips: list[str] = []
        for result in (a, aaaa):
            for ip_text in result:
                if ip_text not in ips:
                    ips.append(ip_text)
        if ips:
            return ips[:16]

        # Fallback: the platform resolver (also catches hosts dnspython could not configure for).
        try:
            infos = await loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            for info in infos:
                addr = str(info[4][0]).split("%")[0]
                if addr not in ips:
                    ips.append(addr)
        except socket.gaierror as exc:
            raise DnsFailure(host, f"no address records ({'; '.join(errors) or exc})") from exc
        if not ips:
            raise DnsFailure(host, "no address records")
        return ips[:16]

    async def resolve_and_validate(self, host: str) -> list[str]:
        check_hostname_allowed(host)
        try:
            literal = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            literal = None
        if literal is not None:
            reason = classify_ip(literal)
            if reason:
                raise SSRFPolicyError(
                    f"IP address {literal} is in a blocked range: {reason}", host=host, blocked=[str(literal)]
                )
            return [str(literal)]

        resolved = await self.resolve(host)
        allowed: list[str] = []
        blocked: list[str] = []
        for ip_text in resolved:
            ip = ipaddress.ip_address(ip_text)
            reason = classify_ip(ip)
            if reason:
                blocked.append(f"{ip} ({reason})")
            else:
                allowed.append(ip_text)
        if blocked:
            # Conservative: refuse when ANY address is private/reserved. Mixed
            # answers are a DNS-rebinding indicator.
            raise SSRFPolicyError(
                f"host '{host}' resolves to blocked address(es): {', '.join(blocked)}",
                host=host,
                blocked=blocked,
            )
        if not allowed:
            raise DnsFailure(host, "resolution returned no usable addresses")
        return allowed
