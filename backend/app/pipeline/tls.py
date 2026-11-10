"""TLS / certificate analysis.

Reads the certificate chain as presented during the fetched HTTPS connection,
parses every inspectable fact, and checks whether the certificate covers the
requested hostname. When the fetcher captured the FULL peer-presented chain
(Python 3.10+ `get_unverified_chain()`), the chain is ALSO independently
re-verified here — cryptographic signatures from leaf up the presented
issuers, validity windows, and BasicConstraints (`ca=True` on intermediates) —
and every certificate in the chain (leaf, intermediates, root) is checked
against the curated distrusted/dead-CA indicator list. The trust anchor
(root) itself comes from the system store, which the TLS handshake already
validated; a non-self-signed top-of-chain is therefore normal, not an error.

A valid certificate is NOT proof of safety: any entity can obtain a valid
certificate for a look-alike domain. These facts feed the scoring engine; the
scoring engine decides risk.
"""
from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..config import Settings
from ..models.enums import Severity
from ..models.schemas import Finding

SOURCE = "trustlens/tls"

_CERTI_PATH: Path | None = None


def _certi_path() -> Path:
    """Lazily resolve the system CA bundle (certifi path API changed across versions)."""
    global _CERTI_PATH
    if _CERTI_PATH is not None:
        return _CERTI_PATH
    try:
        import certifi
    except Exception:
        return Path(__import__("ssl").get_default_verify_paths().cafile or "/etc/ssl/certs/ca-certificates.crt")
    try:
        p = certifi.where()  # certifi >= 2021.10
    except AttributeError:
        p = certifi.file() if hasattr(certifi, "file") else certifi.__path__[0] + "/cacert.pem"
    _CERTI_PATH = Path(p)
    return _CERTI_PATH


CERTI_FILE = _certi_path()


@dataclass
class CertInfo:
    """Parsed certificate facts (or error list)."""

    subject: str = ""
    issuer: str = ""
    issuer_common_name: str = ""
    public_key_type: str = ""
    public_key_size: Optional[int] = None
    signature_algorithm: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: Optional[int] = None
    san_dns: list[str] = field(default_factory=list)
    san_ip: list[str] = field(default_factory=list)
    san_email: list[str] = field(default_factory=list)
    san_other: list[str] = field(default_factory=list)
    issuer_ca: bool = False
    chain_length: int = 1
    chain: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    # True only when a multi-certificate chain was captured AND every
    # verifiable property (signatures, dates, BasicConstraints) passed.
    chain_verified: bool = False


class TlsAnalysisError(Exception):
    """TLS connection or certificate could not be obtained/validated."""


def _cert_name(name: x509.Name) -> str:
    parts = []
    for rdn in name.rdns:
        for attribute in rdn:  # each RDN yields NameAttribute objects
            label = getattr(attribute.oid, "_name", None) or attribute.oid.dotted_string
            parts.append(f"{label}={attribute.value}")
    return ", ".join(parts) if parts else "(empty)"


def _key_info(cert: x509.Certificate) -> tuple[str, Optional[int]]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC", pub.curve.key_size
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    return "UNKNOWN", None


def _signature_algorithm(cert: x509.Certificate) -> str:
    try:
        oid = cert.signature_algorithm_oid
        return oid._name or oid.dotted_string
    except Exception:
        return "(unparsable)"


def check_host_in_sans(cert: x509.Certificate, hostname: str) -> tuple[bool, str]:
    """Does the cert cover this hostname? Prefer SAN; fall back to CN only if no SAN."""
    fqdn = hostname.lower().rstrip(".")

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn and _match_name(fqdn, [cn[0].value]):
            return True, "matched via commonName (no SAN present)"
        return False, "no SAN and no matching commonName"

    dns = ext.value.get_values_for_type(x509.DNSName)
    ip_list = ext.value.get_values_for_type(x509.IPAddress)
    # _match_name(query, candidates): wildcard patterns live in the candidates list.
    if _match_name(fqdn, dns):
        return True, "matched via Subject Alternative Name (SAN)"
    return False, "hostname not present in Subject Alternative Name"


def _match_name(pattern: str, candidates: list[str]) -> bool:
    """Match a query pattern against candidates, supporting single-label wildcards.

    The wildcard may appear in the query ('*.example.org') or in a candidate.
    A wildcard covers exactly one label: api.example.org matches *.example.org.
    """
    if not candidates:
        return False
    query = pattern.lower().rstrip(".")
    for c in candidates:
        cand = c.lower().rstrip(".")
        if query == cand:
            return True
        if query.startswith("*."):
            suffix = query[2:]
            # api.example.org == *.example.org  -> candidate ends with '.example.org' and the part
            # before the suffix is exactly one label (no dots).
            if cand.endswith("." + suffix) and cand[:-len(suffix) - 1].count(".") == 0:
                return True
        if cand.startswith("*."):
            suffix = cand[2:]
            # '*.example.org' == api.example.org -> query ends with '.example.org' and the part
            # before the suffix is exactly one label.
            if query.endswith("." + suffix) and query[:-len(suffix) - 1].count(".") == 0:
                return True
    return False


class DistrustedCaList:
    """Curated indicators of CAs actually distrusted / removed by major root
    programs (browser root-store removals), plus documented phishing-kit abuse.

    The list deliberately contains ONLY CAs that are genuinely dead or
    distrusted. Earlier revisions also listed mainstream CAs (DigiCert,
    Baltimore, GoDaddy, GeoTrust, Thawte, GlobalSign, Comodo DV, IdenTrust,
    …) with inaccurate "removed from root stores" claims — a loose substring
    match then emitted a false TLS-POLICY finding for most normal sites
    (e.g. every DigiCert-issued certificate), which made benign targets look
    suspicious. A positive hit here is a strong signal; absence is not proof
    of safety.
    """

    INDICATORS: list[tuple[str, str]] = [
        ("Entrust Root Certification Authority",
         "Entrust root certificates were distrusted by major browser/root programs in late 2024 "
         "after documented compliance-reporting failures; new Entrust certificates are rejected "
         "by those platforms."),
        ("Entrust.net Secure Server CA", "Distrusted root (Entrust)."),
        ("RapidSSL", "Frequently abused in phishing kits: cheap, automated issuance on look-alike domains."),
        ("WoSign", "Removed from major root stores after improper issuance practices."),
        ("StartCom Certification Authority", "Removed from root stores after improper practices."),
        ("Equifax Secure Certificate Authority", "Removed from root stores."),
    ]

    @classmethod
    def match_issuer(cls, issuer_cn: str) -> list[str]:
        if not issuer_cn:
            return []
        cn_lc = issuer_cn.strip().lower()
        words = re.findall(r"[a-z0-9.\-]+", cn_lc)
        reasons: list[str] = []
        for token, reason in cls.INDICATORS:
            token_base = token.split(" - ")[0].split(" ")[0].lower()
            # Match the full CN exactly, or a leading word of it. A bare
            # substring test is wrong here: "entrust" is literally contained
            # in "identrust", which flagged IdenTrust-issued certificates as
            # distrusted Entrust roots.
            matched = cn_lc == token.lower() or (
                len(token_base) >= 6 and any(w.startswith(token_base) for w in words)
            )
            if matched and reason not in reasons:  # two tokens can share a base (Entrust variants)
                reasons.append(reason)
        return reasons

    @classmethod
    def is_distrusted(cls, issuer_cn: str) -> bool:
        return bool(cls.match_issuer(issuer_cn))


def _load_certificate(cert_bytes: bytes) -> x509.Certificate:
    """Accept PEM or DER input."""
    if b"-----BEGIN" in cert_bytes:
        return x509.load_pem_x509_certificate(cert_bytes)
    return x509.load_der_x509_certificate(cert_bytes)


def parse_certificate(cert_der: bytes) -> CertInfo:
    """Parse a DER- or PEM-encoded certificate and gather all inspectable facts."""
    info = CertInfo()
    try:
        cert = _load_certificate(cert_der)
    except Exception as exc:
        info.errors.append(f"failed to parse certificate: {type(exc).__name__}: {str(exc)[:200]}")
        return info

    info.subject = _cert_name(cert.subject)
    info.issuer = _cert_name(cert.issuer)
    info.signature_algorithm = _signature_algorithm(cert)

    cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    info.issuer_common_name = cn_attrs[0].value if cn_attrs else ""

    info.public_key_type, info.public_key_size = _key_info(cert)

    info.not_before = cert.not_valid_before_utc
    info.not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    if info.not_after is not None:
        # Signed: negative when already expired, positive days remaining otherwise.
        info.days_remaining = (info.not_after - now).days

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        # get_values_for_type returns plain strings for DNS/email, ipaddress
        # objects for IPs, and bytes for OtherName.
        info.san_dns = sorted({s.lower() for s in ext.value.get_values_for_type(x509.DNSName)})
        info.san_ip = [str(s) for s in ext.value.get_values_for_type(x509.IPAddress)]
        info.san_email = sorted({s.lower() for s in ext.value.get_values_for_type(x509.RFC822Name)})
        info.san_other = sorted({str(s) for s in ext.value.get_values_for_type(x509.OtherName)})
    except x509.ExtensionNotFound:
        pass

    try:
        ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        info.issuer_ca = ski is None  # no SKI -> treated as leaf
    except Exception:
        pass

    # Self-signed: issuer DN == subject DN (newer cryptography builds dropped
    # the is_self_signed helper; DN equality is the standard equivalent check).
    info.is_self_signed = cert.issuer == cert.subject
    return info


def _verify_signature(child: x509.Certificate, parent: x509.Certificate) -> tuple[bool, str]:
    """Cryptographically verify `child`'s signature with `parent`'s public key.

    RSA signatures are parameter-aware: RSASSA-PSS certificates (OID
    1.2.840.113549.1.1.10) are verified with the PSS parameters encoded in the
    certificate (hash algorithm, MGF1 mask generation, salt length), while the
    classic sha*/WithRSAEncryption OIDs use PKCS#1 v1.5.
    """
    pub = parent.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            params = None
            try:
                params = child.signature_algorithm_parameters
            except Exception:
                params = None  # unparseable/absent parameters — handled below
            if child.signature_algorithm_oid == x509.SignatureAlgorithmOID.RSASSA_PSS:
                if not isinstance(params, padding.PSS):
                    return False, "RSASSA-PSS OID present but PSS parameters are missing or invalid"
                pub.verify(child.signature, child.tbs_certificate_bytes,
                           params, child.signature_hash_algorithm)
            else:
                pub.verify(child.signature, child.tbs_certificate_bytes,
                           padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        elif isinstance(pub, dsa.DSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       child.signature_hash_algorithm)
        else:
            return False, f"unsupported issuer public key type ({type(pub).__name__})"
        return True, ""
    except InvalidSignature:
        return False, "invalid signature"
    except UnsupportedAlgorithm as exc:
        return False, f"unsupported signature algorithm: {exc}"
    except Exception as exc:  # malformed signature bits etc.
        return False, f"{type(exc).__name__}: {str(exc)[:120]}"


def verify_chain(certs: list[x509.Certificate]) -> tuple[bool, list[str]]:
    """Independently re-verify the peer-presented chain.

    For every certificate: validity window, BasicConstraints (ca=True on
    intermediates, ca=False on the leaf), and — wherever the issuer is present
    in the chain — the cryptographic signature. The top certificate is
    self-signature-checked only when self-signed; a non-self-signed top is the
    normal case (the root lives in the system trust store and was validated
    during the handshake).

    Returns (all_ok, errors).
    """
    errors: list[str] = []
    now = datetime.now(timezone.utc)
    for i, cert in enumerate(certs):
        role = "leaf" if i == 0 else f"chain certificate #{i}"

        # Validity window.
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        if now < not_before:
            errors.append(f"{role}: not yet valid (not_before {not_before.isoformat()})")
        if now > not_after:
            errors.append(f"{role}: expired (not_after {not_after.isoformat()})")

        # BasicConstraints.
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if i > 0 and not bc.ca:
                errors.append(f"{role}: BasicConstraints ca=False on an issuing (CA) certificate")
            if i == 0 and bc.ca:
                errors.append("leaf: BasicConstraints ca=True — this certificate acts as a CA")
        except x509.ExtensionNotFound:
            if i > 0:
                errors.append(f"{role}: missing BasicConstraints extension")

        # Signature by the issuing certificate in the chain.
        if i + 1 < len(certs):
            ok, err = _verify_signature(cert, certs[i + 1])
            if not ok:
                errors.append(f"{role}: signature not verifiable with the next certificate in the chain: {err}")
        elif cert.issuer == cert.subject:
            ok, err = _verify_signature(cert, cert)
            if not ok:
                errors.append(f"{role}: self-signature invalid: {err}")
        # else: anchor is the trust-store root — validated during the handshake.

    return (not errors), errors


def analyze_tls(hostname: str, cert_pem: str | bytes) -> CertInfo:
    """Analyse the certificate presented by `hostname` on HTTPS (443).

    The fetcher already validates the chain against system roots. This module:
      * parses every inspectable certificate fact,
      * checks whether the certificate covers the requested hostname (SAN > CN),
      * flags local policy issues (self-signed, weak keys, weak signatures, expiry).
    """
    pem_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
    leaf = _load_certificate(pem_bytes)
    info = parse_certificate(leaf.public_bytes(serialization.Encoding.DER))

    # Parse the full presented chain (leaf + intermediates [+ root]) when the
    # fetcher captured more than the leaf.
    chain: list[x509.Certificate] = [leaf]
    try:
        loaded = x509.load_pem_x509_certificates(pem_bytes)
        if len(loaded) > 1:
            chain = list(loaded)
    except Exception:
        pass
    info.chain = [_cert_name(c.subject) for c in chain]
    info.chain_length = len(chain)

    # Independent chain verification (signatures, dates, BasicConstraints) and
    # distrusted-CA screening of EVERY certificate in the chain.
    if len(chain) > 1:
        chain_ok, chain_errors = verify_chain(chain)
        info.chain_verified = chain_ok
        for err in chain_errors:
            info.errors.append(f"chain verification: {err}")
    else:
        info.chain_verified = False

    # Distrusted/dead-CA screening for every certificate's issuer.
    seen_reasons: set[str] = set()
    for idx, cert in enumerate(chain):
        cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_cn = cn_attrs[0].value if cn_attrs else ""
        if not issuer_cn:
            continue
        for reason in DistrustedCaList.match_issuer(issuer_cn):
            line = reason if idx == 0 else f"issuer of chain certificate #{idx} ('{issuer_cn}'): {reason}"
            if line not in seen_reasons:
                seen_reasons.add(line)
                info.errors.append(line)

    fqdn = hostname.lower().rstrip(".")
    covered, cover_note = check_host_in_sans(leaf, fqdn)

    # ---- local policy checks on parsed facts ----
    if info.public_key_size is not None and info.public_key_type == "RSA" and info.public_key_size < 2048:
        info.errors.append(f"weak RSA key size: {info.public_key_size} bits (minimum 2048)")
    if info.public_key_size is not None and info.public_key_type == "RSA" and info.public_key_size > 4096:
        info.errors.append(f"unusually large RSA key size: {info.public_key_size} bits; may be misconfigured")
    if info.signature_algorithm.lower().startswith("md5") or info.signature_algorithm.lower().startswith("md"):
        info.errors.append(f"weak signature algorithm: {info.signature_algorithm}")
    if info.days_remaining is not None and info.days_remaining < 0:
        info.errors.append(f"certificate already expired ({info.days_remaining} days)")
    elif info.days_remaining is not None and info.days_remaining < 30:
        info.errors.append(f"certificate expires in less than 30 days ({info.days_remaining})")
    if info.days_remaining is not None and info.days_remaining > 825:
        info.errors.append(f"certificate validity exceeds the CA/Browser Forum maximum (825 days): "
                           f"{info.days_remaining} days")
    # NOTE: distrusted-CA screening happens above for EVERY certificate in the
    # captured chain (leaf, intermediates, root) — not duplicated here.

    if info.is_self_signed:
        if not covered:
            info.errors.append(f"self-signed certificate and hostname '{hostname}' is not covered")
        else:
            info.errors.append("self-signed certificate (issuer == subject); no third-party validation")
    elif not covered:
        info.errors.append(f"hostname '{fqdn}' is not covered by the certificate: {cover_note}")

    return info
