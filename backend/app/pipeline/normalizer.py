"""URL normalisation: parse, validate, canonicalise, and enrich submitted URLs.

Guarantees provided to the rest of the pipeline:
  * scheme is http or https (anything else is rejected, never rewritten);
  * host is lowercase, ASCII (IDN -> punycode), trailing dot removed;
  * IP-literal hosts (including decimal/hex/octal obfuscations) are canonicalised
    and exposed as `ip`;
  * credentials (userinfo) are detected and removed from the canonical URL;
  * tracking parameters are stripped from the canonical URL;
  * the registrable domain (eTLD+1) is extracted from an offline Public Suffix
    List snapshot (no network, deterministic).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import idna
from tldextract import TLDExtract

# Offline PSL snapshot: never fetch, never write a cache dir (deterministic, CI-friendly).
_extract = TLDExtract(suffix_list_urls=(), cache_dir=None)

MAX_URL_LENGTH = 2048

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")
# Bare host like "example.com", "example.com:8080/path" (no scheme typed by the user).
_LOOKS_LIKE_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?(:\d+)?(/.*)?$", re.IGNORECASE)
# Characters commonly invisible in chat/PDF copies of URLs; browsers strip these too.
_INVISIBLE_CHARS_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u206f\u2061-\u2064\ufeff\u00ad]")

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "fbclid", "gclid", "msclkid", "dclid", "mc_eid", "yclid", "twclid", "igshid",
    "_ga", "_gl", "spm", "scm", "ref_src", "ref_url", "s_kwcid", "vbref",
}


class UrlNormalizationError(ValueError):
    """Raised when the submitted string cannot be safely interpreted as a URL."""


@dataclass
class NormalizedUrl:
    raw_input: str
    cleaned_input: str
    scheme: str
    host: str                       # canonical: lowercase, punycode if IDN, canonical IP form
    original_host: str              # host as parsed (before punycode/IP canonicalisation)
    unicode_host: Optional[str]     # decoded unicode form when IDN
    port: Optional[int]
    path: str
    query: str                      # tracking parameters stripped
    fragment: Optional[str]
    url: str                        # canonical full URL (no fragment, no credentials)
    has_credentials: bool
    original_netloc: Optional[str]  # netloc as submitted (may include userinfo)
    is_ip_literal: bool
    ip: Optional[str]
    registrable_domain: Optional[str]  # eTLD+1, e.g. "example.co.uk"
    domain_label: Optional[str]        # e.g. "example" for example.co.uk
    suffix: Optional[str]              # e.g. "co.uk"
    subdomain: Optional[str]           # e.g. "secure.login" (without registrable part)
    labels: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _parse_ip_literal(host: str) -> Optional[ipaddress._BaseAddress]:
    """Parse an IP literal, including obfuscated IPv4 forms (decimal/hex/octal)."""
    h = host.strip("[]").lower()
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if h.isdigit():
        value = int(h)
        try:
            if value <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(value)
            return ipaddress.IPv6Address(value)
        except ValueError:
            return None
    if re.fullmatch(r"0x[0-9a-f]+", h):
        value = int(h, 16)
        if value <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(value)
        try:
            return ipaddress.IPv6Address(value)
        except ValueError:
            return None
    # Dotted forms with octal components, e.g. 0177.0.0.1 (some stacks accept these).
    parts = h.split(".")
    if len(parts) == 4 and all(parts):
        decoded: list[int] = []
        for p in parts:
            try:
                if re.fullmatch(r"0[0-7]+", p):
                    decoded.append(int(p, 8))
                elif p.isdigit():
                    decoded.append(int(p, 10))
                else:
                    return None
            except ValueError:
                return None
        try:
            return ipaddress.IPv4Address(".".join(str(x) for x in decoded))
        except ValueError:
            return None
    return None


def normalize_url(raw: str) -> NormalizedUrl:
    notes: list[str] = []

    if not isinstance(raw, str) or not raw.strip():
        raise UrlNormalizationError("Empty input: submit a URL such as 'https://example.com'.")

    cleaned = raw.strip()
    cleaned = _INVISIBLE_CHARS_RE.sub("", cleaned)
    if len(cleaned) > MAX_URL_LENGTH:
        raise UrlNormalizationError(f"URL exceeds the maximum supported length of {MAX_URL_LENGTH} characters.")

    # Strip wrapping quotes/angle brackets left over from copy-paste.
    while len(cleaned) >= 2 and cleaned[0] in "\"'<" and cleaned[-1] in "\"'>":
        cleaned = cleaned[1:-1].strip()

    if any(ch.isspace() for ch in cleaned):
        raise UrlNormalizationError("URL contains whitespace; submit a single URL without spaces.")

    scheme: Optional[str] = None
    if "://" in cleaned:
        m = _SCHEME_RE.match(cleaned)
        if not m:
            raise UrlNormalizationError("Input is not a valid URL (unparsable scheme).")
        scheme = m.group(0)[:-1].lower()
    elif _SCHEME_RE.match(cleaned):
        head, _, rest = cleaned.partition(":")
        # "example.com:8080/path" is a bare host with a port, not a scheme —
        # browsers interpret digits directly after the colon as a port.
        if re.fullmatch(r"\d+", rest.split("/", 1)[0]) and _LOOKS_LIKE_HOST_RE.match(cleaned):
            cleaned = "https://" + cleaned
            notes.append("no scheme supplied; assumed https://")
            scheme = "https"
        else:
            scheme = head.lower()
    if scheme is None:
        if _LOOKS_LIKE_HOST_RE.match(cleaned):
            cleaned = "https://" + cleaned
            notes.append("no scheme supplied; assumed https://")
            scheme = "https"
        else:
            raise UrlNormalizationError(
                "Input does not look like a URL. Submit something like 'https://example.com' or 'example.com'."
            )

    if scheme not in ("http", "https"):
        raise UrlNormalizationError(
            f"Unsupported URL scheme '{scheme}:'. Only http and https URLs can be analysed."
        )

    try:
        parts = urlsplit(cleaned)
    except ValueError as exc:
        raise UrlNormalizationError(f"URL could not be parsed: {exc}") from exc

    has_credentials = bool(parts.username or parts.password)
    original_netloc = parts.netloc if has_credentials else None
    if has_credentials:
        notes.append("URL contained credentials (userinfo) which were removed from the canonical URL")

    try:
        original_host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise UrlNormalizationError(f"Invalid host or port in URL: {exc}") from exc

    if not original_host:
        raise UrlNormalizationError("URL has no hostname.")

    host = original_host.lower()
    if host.endswith("."):
        host = host[:-1]
        notes.append("trailing dot removed from hostname")

    unicode_host: Optional[str] = None
    if any(ord(c) > 127 for c in host):
        unicode_host = host
        try:
            host = idna.encode(host, uts46=True).decode("ascii")
        except (idna.IDNAError, UnicodeError) as exc:
            raise UrlNormalizationError(f"Invalid internationalised domain name: {exc}") from exc
        notes.append(f"internationalised hostname converted to punycode: {host}")

    is_ip_literal = False
    ip_str: Optional[str] = None
    ip_obj = _parse_ip_literal(host)
    if ip_obj is not None:
        is_ip_literal = True
        ip_str = str(ip_obj)
        if ip_str != original_host:
            notes.append(f"IP literal canonicalised from '{original_host}' to '{ip_str}'")
        else:
            notes.append("host is an IP literal")
        host = ip_str

    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        kept = [(k, v) for k, v in pairs if k.lower() not in TRACKING_PARAMS]
        if len(kept) != len(pairs):
            notes.append(f"stripped {len(pairs) - len(kept)} tracking parameter(s)")
            query = urlencode(kept)

    fragment = parts.fragment or None
    path = parts.path or "/"

    netloc = host
    if is_ip_literal and ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if port is not None:
        netloc = f"{netloc}:{port}"

    url = urlunsplit((scheme, netloc, path, query, ""))

    registrable_domain = domain_label = suffix = subdomain = None
    if not is_ip_literal:
        ext = _extract(url)
        if ext.suffix and ext.domain:
            suffix = ext.suffix
            domain_label = ext.domain
            subdomain = ext.subdomain or None
            registrable_domain = f"{ext.domain}.{ext.suffix}"

    return NormalizedUrl(
        raw_input=raw,
        cleaned_input=cleaned,
        scheme=scheme,
        host=host,
        original_host=original_host,
        unicode_host=unicode_host,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        url=url,
        has_credentials=has_credentials,
        original_netloc=original_netloc,
        is_ip_literal=is_ip_literal,
        ip=ip_str,
        registrable_domain=registrable_domain,
        domain_label=domain_label,
        suffix=suffix,
        subdomain=subdomain,
        labels=host.split("."),
        notes=notes,
    )
