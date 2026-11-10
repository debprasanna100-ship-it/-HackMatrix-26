"""Unit tests for TLS analysis, certificate transparency, deterministic scoring, and threat-intel."""
from __future__ import annotations

import base64
import json
import re

import pytest

from app.models.enums import Classification, FindingCategory, Severity
from app.models.schemas import TlsSummary
from app.pipeline.scoring import ScoringEngine, classification_rationale, recommended_actions
from app.pipeline.tls import (
    CertInfo,
    DistrustedCaList,
    check_host_in_sans,
    parse_certificate,
)
from app.pipeline.crtsh import CtRecord, CrtshResult, _domain_for_ct


# ---- test fixtures: sample certs ----
# A minimal self-signed cert for testing (subject: CN=self-signed.example).
SELF_SIGNED_PEM = """-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIUQkxvdyZvYmplY3RDbkV4YW1wbGUwDQYJKoZIhvcNAQEL
BQAwDTELMAkGA1UEBhMCVVMwHhcNMTYwODMxMjI0NDIyWhcNMTYwODMxMjI0NDIy
WjANMQswCQYDVQQGEwJVUzAqGA8yMDE2MDgzMTIyNDQyMloYDzIwNDYwODI0MjI0
NDIyWjANMQswCQYDVQQGEwJVUzAqGA8yMDE2MDgzMTIyNDQyMowRCAJhLmNvLmNv
bTANBgkqhkiG9w0BAQsFAANBAAs5N6aJmZvRv0xvXh7aXNlZDByb2JqZWN0Q25F
eGFtcGxlMB4GCSqGSIb3DQEJFQMEKw5lZGNvbS5jb20wHhcNMTYwODMxMjI0NDIy
WjANMQswCQYDVQQGEwJVUzAqGA8yMDE2MDgzMTIyNDQyMowRCAJhLmNvLmNv
bTANBgkqhkiG9w0BAQsFAANBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
==
-----END CERTIFICATE-----"""


# A minimal real-world-structure cert (sanitized) with multiple SANs; used only for
# parsing/structure checks where the actual bytes matter. We skip validation against
# the wire; test_cert.pem is generated at test time below instead.
@pytest.fixture
def test_cert(tmp_path):
    """Generate a real x509 cert with SANs, RSA-2048, and SHA-256."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtensionOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    names = [
        x509.DNSName("example.com"),
        x509.DNSName("www.example.com"),
        x509.DNSName("*.example.org"),
        x509.IPAddress(__import__("ipaddress").ip_address("192.0.2.1")),
    ]
    not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)
    not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=800)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
    )
    cert = builder.sign(key, hashes.SHA256())
    path = tmp_path / "test.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path.read_bytes()


@pytest.fixture
def expired_cert(tmp_path):
    """Generate a cert that expired 10 days ago."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.example")])
    not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1000)
    not_after = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
    cert = x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(
        key.public_key()
    ).serial_number(2).not_valid_before(not_before).not_valid_after(not_after).sign(key, hashes.SHA256())
    path = tmp_path / "expired.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path.read_bytes()


@pytest.fixture
def weak_cert(tmp_path):
    """Generate a self-signed SHA-256 cert (weak-signature policy is exercised
    separately: modern cryptography refuses to CREATE MD5-signed certs, so we
    test the detection branch with a monkeypatched parse instead)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "md5.example")])
    cert = x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(
        key.public_key()
    ).serial_number(3).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).sign(key, hashes.SHA256())
    path = tmp_path / "weak.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path.read_bytes()




# ---- parse_certificate ----


def test_parse_real_cert_structure(test_cert):
    info = parse_certificate(test_cert)
    assert "example.com" in info.subject
    assert info.public_key_type == "RSA"
    assert info.public_key_size == 2048
    assert info.signature_algorithm.lower().startswith("sha256")
    assert info.issuer_ca is False
    assert info.chain_length == 1
    assert "example.com" in info.san_dns
    assert "www.example.com" in info.san_dns
    assert "*.example.org" in info.san_dns
    assert "192.0.2.1" in info.san_ip
    assert info.days_remaining and info.days_remaining > 300


def test_parse_expired_cert_expired_flag(expired_cert):
    info = parse_certificate(expired_cert)
    assert info.days_remaining is not None and info.days_remaining < 0


def test_parse_md5_cert_weak_signature(weak_cert, monkeypatch):
    """Weak-signature detection: modern cryptography cannot CREATE MD5-signed
    certs, so exercise the policy branch by monkeypatching the parser to report
    an MD5 signature for a valid PEM."""
    from cryptography import x509 as _x509
    import app.pipeline.tls as tls_mod

    real_parse = tls_mod.parse_certificate

    def md5_parse(cert_bytes):
        info = real_parse(cert_bytes)
        info.signature_algorithm = "md5WithRSAEncryption"
        return info

    monkeypatch.setattr(tls_mod, "parse_certificate", md5_parse)
    info = tls_mod.analyze_tls("md5.example", weak_cert.decode())
    assert any("weak signature algorithm" in e.lower() for e in info.errors)
    # The fixture cert itself parses normally with the real parser.
    clean = real_parse(weak_cert)
    assert clean.signature_algorithm.lower().startswith("sha256")
    assert clean.is_self_signed


def test_parse_self_signed_marked():
    # Use a locally-generated self-signed cert via the fixture helper pattern:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "self.example")])
    cert = x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(
        key.public_key()
    ).serial_number(4).not_valid_before(datetime.datetime.now(datetime.timezone.utc)).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).sign(key, hashes.SHA256())
    info = parse_certificate(cert.public_bytes(serialization.Encoding.DER))
    assert info.is_self_signed
    assert info.issuer_ca is False


# ---- check_host_in_sans ----


def test_sans_match_exact():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtensionOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    names = [x509.DNSName("example.com"), x509.DNSName("*.example.org")]
    cert = x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(
        key.public_key()
    ).serial_number(5).not_valid_before(datetime.datetime.now(datetime.timezone.utc)).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(x509.SubjectAlternativeName(names), critical=False).sign(key, hashes.SHA256())

    assert check_host_in_sans(cert, "example.com")[0] is True
    assert check_host_in_sans(cert, "www.example.com")[0] is False
    assert check_host_in_sans(cert, "api.example.org")[0] is True  # wildcard covers any single label
    assert check_host_in_sans(cert, "malware.example.org")[0] is True  # wildcard covers any single label
    assert check_host_in_sans(cert, "a.b.example.org")[0] is False  # wildcard covers only one label


def test_fallback_to_cn_when_no_san():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.example")])
    cert = x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(
        key.public_key()
    ).serial_number(6).not_valid_before(datetime.datetime.now(datetime.timezone.utc)).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).sign(key, hashes.SHA256())

    assert check_host_in_sans(cert, "legacy.example")[0] is True
    assert check_host_in_sans(cert, "foo.legacy.example")[0] is False


# ---- distrusted CA list ----


@pytest.mark.parametrize("issuer", [
    ("Entrust Root Certification Authority", True),
    ("RapidSSL", True),
    ("DistrustedCABogus", False),
    ("Unknown CA", False),
])
def test_distrusted_ca_detection(issuer):
    name, expected = issuer
    assert DistrustedCaList.is_distrusted(name) == expected
    hits = DistrustedCaList.match_issuer(name)
    if expected:
        assert any("phishing" in h.lower() or "distrusted" in h.lower() for h in hits)


def test_distrusted_ca_no_false_positives_on_mainstream_issuers():
    """The list must only contain CAs genuinely dead/distrusted. Earlier
    revisions flagged mainstream CAs (DigiCert/Baltimore/GoDaddy/…), emitting a
    false TLS-POLICY finding for most normal sites — e.g. every DigiCert-issued
    certificate (github.com's issuer)."""
    for issuer in (
        "DigiCert Global G2 TLS RSA SHA256 2022 CA1",
        "DigiCert High Assurance EV Root CA",
        "Baltimore CyberTrust Root",
        "Go Daddy Secure Certificate Authority - G2",
        "GeoTrust Global CA",
        "Thawte Server CA",
        "GlobalSign Domain Validation CA - SHA256 - G2",
        "COMODO RSA Domain Validation Secure Server CA",
        "IdenTrust Commercial Root CA 1",
        "Let's Encrypt Authority X3",
        "Amazon RSA 2048 M01",
    ):
        assert not DistrustedCaList.is_distrusted(issuer), issuer


def test_distrusted_ca_removed_cas_still_flagged():
    for issuer in ("WoSign", "StartCom Certification Authority",
                   "Equifax Secure Certificate Authority"):
        assert DistrustedCaList.is_distrusted(issuer), issuer


# ---- crt.sh domain normalization ----


def test_ct_domain_query_format():
    # Wildcard query covers subdomains.
    assert _domain_for_ct("example.com") == "*.example.com"
    assert _domain_for_ct("sub.example.co.uk") == "*.sub.example.co.uk"
    assert _domain_for_ct("xn--mnchen-3ya.de") == "*.xn--mnchen-3ya.de"


# ---- crt.sh record parsing (old + 2025 API schemas) ----


def test_ct_record_parses_2025_schema():
    """The 2025 crt.sh rewrite replaced inserted_timestamp with naive
    not_before stamps and dropped certfingerprint* columns entirely."""
    row = {
        "issuer_ca_id": 413868,
        "issuer_name": "C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3",
        "common_name": "example.com",
        "name_value": "*.example.com\nexample.com",
        "id": 29581277802,
        "not_before": "2026-09-26T22:49:11",
        "not_after": "2026-12-25T22:56:35",
        "serial_number": "01eee6aabb521d5e14fc315fd9985690",
        "result_count": 3,
    }
    rec = CtRecord.from_api_json(row)
    assert rec.entry_timestamp is not None
    assert rec.entry_timestamp.tzinfo is not None  # naive stamp treated as UTC
    assert rec.entry_timestamp.year == 2026
    assert rec.names == ["*.example.com", "example.com"]
    assert rec.common_name == "*.example.com"
    assert rec.sha256 == ""  # fingerprints absent in the new schema


def test_ct_record_parses_legacy_schema():
    row = {
        "id": 1234,
        "name_value": "a.example.com,b.example.com",
        "inserted_timestamp": "2024-01-02T03:04:05Z",
        "issuer_name": "C=US, O=Test CA",
        "certfingerprintsha256": "ab" * 32,
        "certfingerprintsha1": "cd" * 20,
    }
    rec = CtRecord.from_api_json(row)
    assert rec.entry_timestamp is not None and rec.entry_timestamp.tzinfo is not None
    assert rec.sha256 == "ab" * 32
    assert rec.fingerprint == "ab" * 32


def test_ct_record_missing_timestamp_is_none_not_epoch():
    """A missing/invalid stamp must yield None, never the 1970 fallback that
    poisoned most_recent (and mis-dated every CT summary)."""
    rec = CtRecord.from_api_json({"id": 1, "name_value": "x.example.com"})
    assert rec.entry_timestamp is None
    rec_bad = CtRecord.from_api_json({"id": 1, "name_value": "x.example.com",
                                      "not_before": "not-a-date"})
    assert rec_bad.entry_timestamp is None

    result = CrtshResult("example.com", records=[rec, rec_bad])
    assert result.most_recent is None
    assert result.oldest is None


# ---- scoring engine ----


def test_scoring_low_risk_empty_findings():
    engine = ScoringEngine()
    result = engine.score([], None)
    assert result == Classification.LOW_RISK


def test_scoring_inconclusive_on_fetch_fail():
    """The page fetch is the REQUIRED check: the caller declares its failure and
    the engine must yield Inconclusive (never Low Risk)."""
    engine = ScoringEngine()
    from app.models.schemas import Finding
    f = Finding(id="FETCH-DNS-FAIL", title="DNS failed", severity=Severity.LOW,
                category=FindingCategory.FETCH, evidence=["no dns"], source="t", check_succeeded=False)
    result = engine.score([f], None, required_failures=["page-fetch"])
    assert result == Classification.INCONCLUSIVE


def test_scoring_suspicious_on_low_findings():
    engine = ScoringEngine()
    from app.models.schemas import Finding
    f = Finding(id="DOM-SUSPICIOUS-TLD", title="Suspicious", severity=Severity.LOW,
                category=FindingCategory.DOMAIN, evidence=[".xyz"], source="t")
    result = engine.score([f], None)
    assert result == Classification.SUSPICIOUS


def test_scoring_unavailable_check_never_raises_risk():
    """A failed/unavailable check (check_succeeded=False) is a coverage
    limitation — e.g. a crt.sh outage — and must not make a benign site
    suspicious (low finding weight must not reach the score)."""
    engine = ScoringEngine()
    from app.models.schemas import Finding
    f = Finding(id="CT-CACHE-FAIL", title="CT lookup unavailable", severity=Severity.LOW,
                category=FindingCategory.TLS, evidence=["crt.sh returned 502"],
                source="t", check_succeeded=False)
    result = engine.score([f], None)
    assert engine.ctx.score == 0
    assert result == Classification.LOW_RISK


def test_scoring_high_on_multiple_medians():
    engine = ScoringEngine()
    from app.models.schemas import Finding
    f = Finding(id="TLD", title="x", severity=Severity.MEDIUM, category=FindingCategory.DOMAIN,
                evidence=["x"], source="t")
    result = engine.score([f, f, f], None)  # 3 medians
    assert result == Classification.SUSPICIOUS
    result = engine.score([f, f, f, f], None)  # 4 medians
    assert result == Classification.HIGH_RISK


def test_scoring_authoritative_confirmed_malicious():
    engine = ScoringEngine()
    from app.models.schemas import Finding
    f = Finding(id="URLHAUS-MATCH", title="Malicious", severity=Severity.HIGH,
                category=FindingCategory.INTEL, evidence=["urlhaus id=123"], source="t")
    result = engine.score([f], None)
    assert result == Classification.CONFIRMED_MALICIOUS

    f2 = Finding(id="VT-MATCH", title="VT", severity=Severity.MEDIUM,
                 category=FindingCategory.INTEL, evidence=["positives=8/70", "example.com"], source="t")
    result = engine.score([f2], None)
    assert result == Classification.CONFIRMED_MALICIOUS


def test_scoring_gsb_malware_high_band():
    engine = ScoringEngine()
    from app.models.schemas import Finding
    f = Finding(id="GSB-MATCH", title="GSB", severity=Severity.MEDIUM,
                category=FindingCategory.INTEL, evidence=["THREAT_TYPE=MALWARE", "http://x/"], source="t")
    result = engine.score([f], None)
    assert result in (Classification.CONFIRMED_MALICIOUS, Classification.HIGH_RISK)


def test_classification_rationale_no_findings():
    import datetime  # noqa - unused here, keep module consistent
    from app.pipeline.scoring import ScoreContext
    c = classification_rationale(Classification.LOW_RISK, [], ScoreContext())
    assert "no significant indicators" in c.lower()
    assert "safe" in c.lower()


def test_classification_rationale_inconclusive():
    from app.pipeline.scoring import ScoreContext
    ctx = ScoreContext()
    ctx.key_checks_failed = ["page-fetch"]
    c = classification_rationale(Classification.INCONCLUSIVE, [], ctx)
    assert "coverage" in c.lower()


def test_recommendation_confirmed_malicious():
    acts = recommended_actions(Classification.CONFIRMED_MALICIOUS, [])
    assert any("do not visit" in a for a in acts)


# ---- TlsSummary ----


def test_tls_summary_from_certinfo(test_cert):
    info = parse_certificate(test_cert)
    ts = TlsSummary(
        hostname="example.com", san_dns=info.san_dns, issuer=info.issuer,
        issuer_common_name=info.issuer_common_name, issuer_ca=info.issuer_ca,
        public_key_type=info.public_key_type, public_key_size=info.public_key_size,
        signature_algorithm=info.signature_algorithm, days_remaining=info.days_remaining,
        is_self_signed=info.is_self_signed, chain_length=info.chain_length, chain=info.chain,
        cert_sha256="", errors=list(info.errors),
    )
    assert ts.public_key_size == 2048
    assert "example.com" in ts.san_dns
    assert ts.is_self_signed


# ---- intel providers (stubbed sync httpx clients; no network) ----


class _StubResponse:
    def __init__(self, status_code, body, headers: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body) if isinstance(body, (dict, list)) else str(body or "")

    def json(self):
        if isinstance(self._body, (dict, list)):
            return self._body
        raise ValueError("not json")


class _StubSyncClient:
    """Stands in for the provider's httpx.Client; records method calls."""

    def __init__(self, response):
        self.response = response
        self.calls: list[tuple[tuple, dict]] = []

    def post(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.response

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.response


def _intel_finding_by_id(findings, fid):
    return next((f for f in findings if f.id == fid), None)


def test_gsb_body_uses_only_valid_threat_types():
    """Invalid v4 threatTypes (THREAT_TYPE_UNSPECIFIED / API_ABUSE / MOBILE_APP)
    make the API answer 400 INVALID_ARGUMENT — GSB could never match. The body
    must use the documented client + threatInfo shape (a flat {"requests": [...]}
    body is rejected with 400 "Unknown name ...: Cannot find field")."""
    from app.pipeline.intel import GoogleSafeBrowsing

    valid = {"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
             "POTENTIALLY_HARMFUL_APPLICATION"}
    body = GoogleSafeBrowsing("k")._build_body("https://example.com/")
    assert set(body.keys()) == {"client", "threatInfo"}
    info = body["threatInfo"]
    assert info["threatEntryTypes"] == ["URL"] and info["threatEntries"][0]["url"]
    sent = set(info["threatTypes"])
    assert sent and sent <= valid


def test_gsb_malware_match_is_high_severity():
    """Severity must be derived from the parsed threat types — the old
    `"MALWARE" in threats` check tested list membership of items shaped
    "THREAT_TYPE=MALWARE" and was always False."""
    from app.pipeline.intel import GoogleSafeBrowsing

    gsb = GoogleSafeBrowsing("k")
    gsb.client = _StubSyncClient(_StubResponse(200, {"matches": [{"threatType": "MALWARE"}]}))
    findings = gsb.check("https://example.com/")
    f = _intel_finding_by_id(findings, "GSB-MATCH")
    assert f is not None
    assert f.severity == Severity.HIGH
    assert "THREAT_TYPE=MALWARE" in f.evidence
    assert f.check_succeeded


def test_gsb_unwanted_software_is_medium():
    from app.pipeline.intel import GoogleSafeBrowsing

    gsb = GoogleSafeBrowsing("k")
    gsb.client = _StubSyncClient(_StubResponse(200, {"matches": [{"threatType": "UNWANTED_SOFTWARE"}]}))
    f = _intel_finding_by_id(gsb.check("https://example.com/"), "GSB-MATCH")
    assert f is not None and f.severity == Severity.MEDIUM


def test_gsb_key_error_is_a_failed_check():
    """A rejected API key is a coverage limitation, never evidence about the
    target: check_succeeded=False keeps it out of the score (MEDIUM × INTEL
    weight ×2 was enough to push every site to suspicious)."""
    from app.pipeline.intel import GoogleSafeBrowsing

    gsb = GoogleSafeBrowsing("k")
    gsb.client = _StubSyncClient(_StubResponse(403, {"error": "forbidden"}))
    f = _intel_finding_by_id(gsb.check("https://example.com/"), "GSB-KEY-ERROR")
    assert f is not None and f.check_succeeded is False


def _vt_v3_payload(malicious=0, suspicious=0, harmless=70, undetected=0, timeout=0):
    results = {}
    engines = {}
    for i in range(malicious):
        engines[f"EngineM{i}"] = {"category": "malicious", "result": "malware site"}
        results["malicious"] = results.get("malicious", 0) + 1
    for i in range(suspicious):
        engines[f"EngineS{i}"] = {"category": "suspicious", "result": "suspicious"}
        results["suspicious"] = results.get("suspicious", 0) + 1
    stats = {"malicious": malicious, "suspicious": suspicious, "undetected": undetected,
             "harmless": harmless, "timeout": timeout}
    return {"data": {"type": "url", "id": "x", "attributes": {
        "last_analysis_stats": stats, "last_analysis_results": engines,
    }}}


def test_vt_v3_url_stats_parsing():
    """VT v3: last_analysis_stats carries the verdict counts; only
    malicious+suspicious count as adverse. A low adverse count (1-5) is a
    supporting signal (VT-LOW-CONFIDENCE), never an authoritative match."""
    from app.pipeline.intel import VirusTotal
    from app.pipeline.scoring import ScoringEngine

    vt = VirusTotal("k")
    body = _vt_v3_payload(malicious=1, suspicious=1, harmless=60, undetected=7, timeout=1)
    vt.client = _StubSyncClient(_StubResponse(200, body))
    f = _intel_finding_by_id(vt.check_url("https://example.com/"), "VT-LOW-CONFIDENCE")
    assert f is not None
    assert "positives=2/70" in f.evidence  # 1+1+7+1 = 70 total engines
    assert f.severity == Severity.MEDIUM  # below the authoritative threshold
    assert f.check_succeeded
    assert any(e.startswith("EngineM0=") for e in f.evidence)
    assert ScoringEngine().score([f], None) == Classification.SUSPICIOUS


def test_vt_v3_many_positives_is_high_and_authoritative():
    from app.pipeline.intel import VirusTotal
    from app.pipeline.scoring import ScoringEngine

    vt = VirusTotal("k")
    vt.client = _StubSyncClient(_StubResponse(200, _vt_v3_payload(malicious=7)))
    f = _intel_finding_by_id(vt.check_url("https://high.example.com/"), "VT-MATCH")
    assert f is not None and f.severity == Severity.HIGH

    # The scoring engine must treat it as authoritative (evidence contract).
    engine = ScoringEngine()
    assert engine.score([f], None) == Classification.CONFIRMED_MALICIOUS


def test_vt_v3_url_id_is_urlsafe_base64_without_padding():
    from app.pipeline.intel import VirusTotal

    assert VirusTotal._url_id("https://example.com/a") == \
        base64.urlsafe_b64encode(b"https://example.com/a").decode().rstrip("=")


def test_vt_v3_not_found_is_nodata_never_clean():
    """A 404 means VT has no data for the object — an answered query surfaced as
    an explicit NODATA finding, not as an implicit clean result."""
    from app.pipeline.intel import VirusTotal

    vt = VirusTotal("k")
    vt.client = _StubSyncClient(_StubResponse(404, {"error": {"code": "NotFoundError"}}))
    f = _intel_finding_by_id(vt.check_url("https://fresh.example.com/"), "VT-NODATA")
    assert f is not None
    assert f.severity == Severity.INFO
    assert "never submitted" in f.evidence[0] or "never" in f.evidence[0]


def test_vt_v3_domain_stats():
    from app.pipeline.intel import VirusTotal

    vt = VirusTotal("k")
    body = _vt_v3_payload(malicious=2, suspicious=0, harmless=68)
    body["data"]["type"] = "domain"
    vt.client = _StubSyncClient(_StubResponse(200, body))
    f = _intel_finding_by_id(vt.check_domain("flagged.example"), "VT-MATCH")
    assert f is not None
    assert "positives=2/70" in f.evidence
    assert f.severity == Severity.MEDIUM


def test_vt_key_error_is_a_failed_check():
    from app.pipeline.intel import VirusTotal

    vt = VirusTotal("k")
    vt.client = _StubSyncClient(_StubResponse(401, {"error": {"code": "AuthenticationError"}}))
    f = _intel_finding_by_id(vt.check_url("https://badkey.example.com/"), "VT-KEY-ERROR")
    assert f is not None and f.check_succeeded is False


def test_vt_rate_limit_raises_unavailable():
    from app.pipeline.intel import IntelUnavailable, VirusTotal

    vt = VirusTotal("k")
    vt.client = _StubSyncClient(_StubResponse(429, {"error": {"code": "QuotaExceededError"}}))
    with pytest.raises(IntelUnavailable):
        vt.check_url("https://ratelimited.example.com/")


def test_vt_server_error_and_malformed_json_are_failed_checks():
    """Non-success responses and malformed payloads are failed checks — never
    silent (which would read as "clean")."""
    from app.pipeline.intel import VirusTotal

    vt = VirusTotal("k")
    vt.client = _StubSyncClient(_StubResponse(500, {}))
    f = _intel_finding_by_id(vt.check_url("https://err.example.com/"), "VT-ERROR")
    assert f is not None and f.check_succeeded is False

    vt2 = VirusTotal("k")
    vt2.client = _StubSyncClient(_StubResponse(200, "<html>not json</html>"))
    f2 = _intel_finding_by_id(vt2.check_url("https://err2.example.com/"), "VT-ERROR")
    assert f2 is not None and f2.check_succeeded is False
    assert "malformed" in f2.evidence[0].lower()

    vt3 = VirusTotal("k")
    vt3.client = _StubSyncClient(_StubResponse(200, "just a string"))
    f3 = _intel_finding_by_id(vt3.check_url("https://err3.example.com/"), "VT-ERROR")
    assert f3 is not None and f3.check_succeeded is False


def test_urlhaus_parses_v1_object_response():
    """URLhaus v1 answers with {query_status, url_details} objects, not lists;
    the old list-only parsing (and the nonexistent /v1/urlhaus/ domain
    endpoint) meant URLhaus could never match."""
    from app.pipeline.intel import Urlhaus

    body = {"query_status": "ok", "url_details": {
        "url_id": "123", "url_status": "online", "threat": "Payloader"}}
    uh = Urlhaus("k")
    uh.client = _StubSyncClient(_StubResponse(200, body))
    findings = uh.check_url("https://example.com/payload.exe")
    f = _intel_finding_by_id(findings, "URLHAUS-MATCH")
    assert f is not None and f.severity == Severity.HIGH
    assert "url_id=123" in f.evidence
    # v1 takes form-encoded bodies
    _, kwargs = uh.client.calls[0]
    assert "json" not in kwargs

    no_results = Urlhaus("k")
    no_results.client = _StubSyncClient(_StubResponse(200, {"query_status": "no_results"}))
    assert no_results.check_url("https://example.com/") == []


def test_urlhaus_host_endpoint_for_domain_checks():
    from app.pipeline.intel import Urlhaus

    body = {"query_status": "ok", "host_details": [
        {"url_id": "5", "url_status": "offline", "threat": "Payload"},
        {"url_id": "6", "url_status": "online", "threat": "Payload"},
    ]}
    uh = Urlhaus("k")
    uh.client = _StubSyncClient(_StubResponse(200, body))
    findings = uh.check_domain("example.com")
    args, _kwargs = uh.client.calls[0]
    assert args[0].endswith("/v1/host/")
    assert len([f for f in findings if f.id == "URLHAUS-MATCH"]) == 2


def test_phishtank_v2_results_dict():
    """PhishTank v2 returns results as a dict keyed "url0"; the legacy list
    parsing never matched, and the old endpoint was undocumented."""
    from app.pipeline.intel import PhishTank

    body = {"meta": {"in_database": True}, "results": {"url0": {
        "phish_id": 42, "verified": "yes", "valid": "yes",
        "phish_detail_page": "https://phishtank.org/detail/42",
    }}}
    pt = PhishTank("k")
    pt.client = _StubSyncClient(_StubResponse(200, body))
    findings = pt.check_url("https://phished.example/login")
    f = _intel_finding_by_id(findings, "PHISHTANK-MATCH")
    assert f is not None and f.severity == Severity.HIGH
    assert "phish_id=42" in f.evidence
    assert "verified=yes" in f.evidence and "valid=yes" in f.evidence
    assert pt.check_domain_supported is False

    pt_err = PhishTank("k")
    pt_err.client = _StubSyncClient(_StubResponse(200, {"errormessage": "bad key"}))
    f_err = _intel_finding_by_id(pt_err.check_url("https://phished.example/other"), "PHISHTANK-ERROR")
    assert f_err is not None and f_err.check_succeeded is False


@pytest.mark.parametrize("verified,valid", [("yes", "no"), ("no", "yes"), ("no", "no")])
def test_phishtank_unverified_entries_are_never_authoritative(verified, valid):
    """Only verified AND valid PhishTank records may produce an authoritative
    match; in-database but unverified/invalid records stay informational."""
    from app.pipeline.intel import PhishTank
    from app.pipeline.scoring import ScoringEngine

    body = {"meta": {"in_database": True}, "results": {"url0": {
        "phish_id": 7, "verified": verified, "valid": valid,
    }}}
    pt = PhishTank("k")
    pt.client = _StubSyncClient(_StubResponse(200, body))
    findings = pt.check_url(f"https://case-{verified}-{valid}.example/x")
    assert _intel_finding_by_id(findings, "PHISHTANK-MATCH") is None
    f = _intel_finding_by_id(findings, "PHISHTANK-UNVERIFIED")
    assert f is not None and f.severity == Severity.INFO
    assert f"verified={verified}" in f.evidence and f"valid={valid}" in f.evidence
    # Not authoritative in the scoring engine either.
    engine = ScoringEngine()
    assert engine.score([f], None) == Classification.LOW_RISK


def test_openphish_community_feed_matches_url_and_domain():
    """OpenPhish uses the official community feed (plain URL list, no key in any
    URL); the adapter indexes it by URL and hostname."""
    from app.pipeline.intel import OpenPhish

    feed = "\n".join([
        "http://phish1.example/login",
        "http://phish2.example/|extra|fields",  # tolerate decorated lines
        "https://phish1.example/deep/page",
    ])
    op = OpenPhish("community")  # value is an opt-in flag, never sent anywhere
    op.client = _StubSyncClient(_StubResponse(200, feed))
    OpenPhish._feed_urls = OpenPhish._feed_hosts = None  # reset class feed cache
    OpenPhish._feed_error = None

    f = _intel_finding_by_id(op.check_url("http://phish1.example/login"), "OPENPHISH-MATCH")
    assert f is not None and f.severity == Severity.HIGH

    f2 = _intel_finding_by_id(op.check_domain("phish1.example"), "OPENPHISH-MATCH")
    assert f2 is not None
    assert any("phish1.example/login" in e for e in f2.evidence)

    # clean answers
    assert op.check_url("https://benign.example/") == []
    assert op.check_domain("benign.example") == []
    # the key value never appears in the requested feed URL
    requested_url = op.client.calls[0][0][0]
    assert requested_url == OpenPhish.FEED_URL and "community" not in requested_url


def test_openphish_feed_failure_is_a_failed_check():
    from app.pipeline.intel import OpenPhish

    op = OpenPhish("community")
    op.client = _StubSyncClient(_StubResponse(500, ""))
    OpenPhish._feed_urls = OpenPhish._feed_hosts = None
    OpenPhish._feed_error = None
    OpenPhish._feed_error_ts = 0.0
    f = _intel_finding_by_id(op.check_url("https://benign.example/"), "OPENPHISH-ERROR")
    assert f is not None and f.check_succeeded is False

    # a clean match list is never fabricated while the feed is down
    op2 = OpenPhish("community")
    op2.client = _StubSyncClient(_StubResponse(200, ""))
    f2 = _intel_finding_by_id(op2.check_domain("benign.example"), "OPENPHISH-ERROR")
    assert f2 is not None and f2.check_succeeded is False


def test_registry_answer_usable_semantics():
    """A provider that only emits failed-check findings did NOT answer — the
    runner uses this for the required threat-intel outage gate."""
    from app.models.schemas import Finding
    from app.pipeline.intel import IntelRegistry

    assert IntelRegistry._answer_usable([]) is True  # clean no-hit = answer
    ok = Finding(id="X", title="t", severity=Severity.INFO, category=FindingCategory.INTEL,
                 evidence=["e"], source="t", check_succeeded=True)
    assert IntelRegistry._answer_usable([ok]) is True
    failed = Finding(id="X-ERROR", title="t", severity=Severity.INFO, category=FindingCategory.INTEL,
                     evidence=["e"], source="t", check_succeeded=False)
    assert IntelRegistry._answer_usable([failed]) is False
    assert IntelRegistry._answer_usable([ok, failed]) is True


def test_intel_key_errors_never_raise_risk_band():
    """Every provider KEY-ERROR finding must be check_succeeded=False so a
    misconfigured key can never make benign sites suspicious."""
    from app.models.schemas import Finding
    from app.pipeline.scoring import ScoringEngine

    for fid in ("GSB-KEY-ERROR", "URLHAUS-KEY-ERROR", "OPENPHISH-KEY-ERROR",
                "PHISHTANK-KEY-ERROR", "VT-KEY-ERROR"):
        f = Finding(id=fid, title="key rejected", severity=Severity.MEDIUM,
                    category=FindingCategory.INTEL, evidence=["key invalid"], source="t",
                    check_succeeded=False)
        engine = ScoringEngine()
        assert engine.score([f], None) == Classification.LOW_RISK, fid
        assert engine.ctx.score == 0, fid
        assert engine.ctx.medium == 0, fid


def test_registry_does_not_backoff_on_unsupported_domain_checks():
    """GSB has no domain check; the base class raises IntelUnavailable("not
    supported") — the registry must skip it silently, NOT mark the provider
    failed for 60s (which silently disabled the GSB URL check on every report,
    because the runner runs the domain pass first)."""
    from app.pipeline.intel import IntelRegistry
    from tests.conftest import make_settings

    settings = make_settings(google_safe_browsing_api_key="k")
    registry = IntelRegistry(settings)
    assert registry.status()["google_safe_browsing"] == "active"

    import asyncio
    findings = asyncio.run(registry.check_domain("example.com"))
    ids = {f.id for f in findings}
    assert "GOOGLE_SAFE_BROWSING-RATELIMIT" not in ids
    assert "google_safe_browsing" not in registry._failed
    assert registry.status()["google_safe_browsing"] == "active"


def test_gsb_and_phishtank_declare_domain_unsupported():
    from app.pipeline.intel import GoogleSafeBrowsing, PhishTank

    assert GoogleSafeBrowsing.check_domain_supported is False
    assert PhishTank.check_domain_supported is False


# ---- scoring policy: required vs optional checks (see scoring.py docstring) ----


def test_scoring_policy_required_failure_over_bands():
    """A required-check failure always beats the risk bands (Inconclusive,
    never a benign or suspicious verdict without the required evidence)."""
    from app.models.schemas import Finding
    med = Finding(id="M", title="x", severity=Severity.MEDIUM, category=FindingCategory.DOMAIN,
                  evidence=["x"], source="t")
    engine = ScoringEngine()
    assert engine.score([med], None, required_failures=["page-fetch"]) == Classification.INCONCLUSIVE


def test_scoring_policy_authoritative_wins_over_required_failure():
    """Precedence (documented): authoritative feed evidence stays actionable —
    Confirmed Malicious even when the fetch failed; the hard rule is only that
    a failed check may never produce a *benign* verdict."""
    from app.models.schemas import Finding
    feed_hit = Finding(id="URLHAUS-MATCH", title="Malicious", severity=Severity.HIGH,
                       category=FindingCategory.INTEL, evidence=["urlhaus id=123"], source="t")
    engine = ScoringEngine()
    assert engine.score([feed_hit], None, required_failures=["page-fetch"]) == \
        Classification.CONFIRMED_MALICIOUS


def test_scoring_policy_configured_feed_outage_is_inconclusive():
    """When feeds ARE configured but none answered (outage), absence of intel
    hits is not evidence -> Inconclusive."""
    engine = ScoringEngine()
    assert engine.score([], None, intel_outcome=(["urlhaus", "virustotal"], [])) == \
        Classification.INCONCLUSIVE


def test_scoring_policy_mixed_providers_still_conclusive():
    """One configured provider answered, another failed -> conclusive."""
    engine = ScoringEngine()
    assert engine.score([], None, intel_outcome=(["urlhaus", "virustotal"], ["urlhaus"])) == \
        Classification.LOW_RISK


def test_scoring_policy_unconfigured_feeds_are_optional():
    """No provider configured -> threat-intel is optional; a clean scan stays
    low_risk (providers marked unavailable, never 'clean')."""
    engine = ScoringEngine()
    assert engine.score([], None, intel_outcome=([], [])) == Classification.LOW_RISK
    assert engine.score([], None) == Classification.LOW_RISK


def test_scoring_policy_optional_unavailable_recorded_not_gating():
    """Optional failed checks (CT outage) are preserved as evidence, excluded
    from the score/counts, and listed in key_checks_unavailable — without
    changing the verdict."""
    from app.models.schemas import Finding
    ct_outage = Finding(id="CT-CACHE-FAIL", title="CT lookup unavailable", severity=Severity.LOW,
                        category=FindingCategory.TLS, evidence=["crt.sh 502"], source="t",
                        check_succeeded=False)
    engine = ScoringEngine()
    result = engine.score([ct_outage], None)
    assert result == Classification.LOW_RISK
    assert engine.ctx.score == 0
    assert engine.ctx.key_checks_unavailable == ["CT-CACHE-FAIL"]
    assert engine.ctx.key_checks_failed == []


def test_scoring_authoritative_with_optional_unavailable_stays_confirmed():
    """A feed hit with unrelated optional checks down is still Confirmed."""
    from app.models.schemas import Finding
    hit = Finding(id="VT-MATCH", title="VT", severity=Severity.MEDIUM,
                  category=FindingCategory.INTEL, evidence=["positives=8/70"], source="t")
    ct_outage = Finding(id="CT-CACHE-FAIL", title="CT outage", severity=Severity.LOW,
                        category=FindingCategory.TLS, evidence=["crt.sh 502"], source="t",
                        check_succeeded=False)
    engine = ScoringEngine()
    assert engine.score([hit, ct_outage], None, intel_outcome=(["virustotal"], ["virustotal"])) == \
        Classification.CONFIRMED_MALICIOUS


# ---- VT v3 miss policy: domain fallback + optional submit-on-miss ----


def test_vt_url_miss_falls_back_to_domain_reputation():
    """On URL 404 (never analysed) the adapter passively queries the domain
    object instead (default policy). A domain match with a weak malicious
    count is non-authoritative (domain_positives= evidence)."""
    from app.pipeline.intel import VirusTotal

    class SeqClient(_StubSyncClient):
        """404 for /urls/..., 200-with-payload for /domains/..."""
        def get(self, *args, **kwargs):
            path = args[0] if args else kwargs.get("url", "")
            self.calls.append((args, kwargs))
            if "/urls/" in path:
                return _StubResponse(404, {"error": {"code": "NotFoundError"}})
            return _StubResponse(200, _vt_v3_payload(malicious=2, suspicious=1, harmless=60))

    vt = VirusTotal("k")  # defaults: domain fallback on, submit off
    vt.client = SeqClient(None)
    findings = vt.check_url("https://fresh.example.com/some/page")
    f = _intel_finding_by_id(findings, "VT-LOW-CONFIDENCE")
    assert f is not None and f.severity == Severity.MEDIUM
    assert "target=domain fresh.example.com (URL uncached)" in f.evidence
    assert any(e.startswith("domain_positives=3/") for e in f.evidence)
    assert not any(e.startswith("positives=") for e in f.evidence)
    # non-authoritative: the scoring engine must NOT confirm malicious from it
    from app.pipeline.scoring import ScoringEngine
    assert ScoringEngine().score(findings, None) == Classification.SUSPICIOUS


def test_vt_domain_fallback_strong_malicious_majority_is_authoritative():
    from app.pipeline.intel import VirusTotal

    class SeqClient(_StubSyncClient):
        def get(self, *args, **kwargs):
            path = args[0] if args else ""
            self.calls.append((args, kwargs))
            if "/urls/" in path:
                return _StubResponse(404, {"error": {"code": "NotFoundError"}})
            return _StubResponse(200, _vt_v3_payload(malicious=9, harmless=61))

    vt = VirusTotal("k")
    vt.client = SeqClient(None)
    findings = vt.check_url("https://verybad.example.com/")
    f = _intel_finding_by_id(findings, "VT-MATCH")
    assert f is not None and f.severity == Severity.HIGH
    assert any(e.startswith("positives=9/") for e in f.evidence)
    from app.pipeline.scoring import ScoringEngine
    assert ScoringEngine().score(findings, None) == Classification.CONFIRMED_MALICIOUS


def test_vt_url_miss_domain_also_missing_is_nodata():
    from app.pipeline.intel import VirusTotal

    vt = VirusTotal("k")
    vt.client = _StubSyncClient(_StubResponse(404, {"error": {"code": "NotFoundError"}}))
    findings = vt.check_url("https://unknown.example.org/")
    f = _intel_finding_by_id(findings, "VT-NODATA")
    assert f is not None and f.severity == Severity.INFO and f.check_succeeded
    assert "unknown.example.org" in f.evidence[0]


def test_vt_domain_fallback_disabled_goes_straight_to_nodata():
    from app.config import Settings
    from app.pipeline.intel import VirusTotal

    settings = Settings(virustotal_api_key="k", vt_domain_fallback=False)
    vt = VirusTotal("k", settings)
    calls: list[str] = []

    class RecordingClient(_StubSyncClient):
        def get(self, *args, **kwargs):
            calls.append(args[0] if args else "")
            return _StubResponse(404, {"error": {"code": "NotFoundError"}})

    vt.client = RecordingClient(None)
    findings = vt.check_url("https://unknown.example.org/")
    assert _intel_finding_by_id(findings, "VT-NODATA") is not None
    assert all("/domains/" not in c for c in calls)  # no fallback query was made


def test_vt_submit_on_miss_optin_submits_and_rechecks():
    from app.config import Settings
    from app.pipeline.intel import VirusTotal

    settings = Settings(virustotal_api_key="k", vt_submit_on_miss=True)
    vt = VirusTotal("k", settings)

    class SeqClient(_StubSyncClient):
        def __init__(self):
            super().__init__(None)
            self.url_gets = 0

        def get(self, *args, **kwargs):
            path = args[0] if args else ""
            self.calls.append((args, kwargs))
            if "/urls/" in path:
                self.url_gets += 1
                if self.url_gets == 1:
                    return _StubResponse(404, {"error": {"code": "NotFoundError"}})
                return _StubResponse(200, _vt_v3_payload(malicious=7, harmless=63))
            return _StubResponse(404, {})

        def post(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return _StubResponse(200, {"data": {"id": "x"}})

    vt.client = SeqClient()
    findings = vt.check_url("https://submitted.example.com/")
    f = _intel_finding_by_id(findings, "VT-MATCH")
    assert f is not None and f.severity == Severity.HIGH
    assert "target=URL (https://submitted.example.com/)" in f.evidence
    posts = [c for c in vt.client.calls if c[1].get("data")]
    assert posts and posts[0][1]["data"] == {"url": "https://submitted.example.com/"}


def test_vt_submit_failure_degrades_to_domain_fallback():
    from app.config import Settings
    from app.pipeline.intel import VirusTotal

    settings = Settings(virustotal_api_key="k", vt_submit_on_miss=True,
                        vt_domain_fallback=True)
    vt = VirusTotal("k", settings)

    class SeqClient(_StubSyncClient):
        def get(self, *args, **kwargs):
            path = args[0] if args else ""
            self.calls.append((args, kwargs))
            if "/urls/" in path:
                return _StubResponse(404, {"error": {"code": "NotFoundError"}})
            return _StubResponse(200, _vt_v3_payload(malicious=1, harmless=69))

        def post(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return _StubResponse(429, {"error": {"code": "QuotaExceededError"}})

    vt.client = SeqClient(None)
    findings = vt.check_url("https://mid.example.com/")
    # submission failed (429) -> passive domain fallback still ran
    assert _intel_finding_by_id(findings, "VT-LOW-CONFIDENCE") is not None


def test_vt_domain_fallback_failure_is_a_failed_check_not_clean():
    """If the domain fallback itself errors (500), the adapter must surface a
    failed check — never silence."""
    from app.pipeline.intel import VirusTotal

    class SeqClient(_StubSyncClient):
        def get(self, *args, **kwargs):
            path = args[0] if args else ""
            self.calls.append((args, kwargs))
            if "/urls/" in path:
                return _StubResponse(404, {"error": {"code": "NotFoundError"}})
            return _StubResponse(500, {})

    vt = VirusTotal("k")
    vt.client = SeqClient(None)
    findings = vt.check_url("https://broken.example.com/")
    f = _intel_finding_by_id(findings, "VT-ERROR")
    assert f is not None and f.check_succeeded is False


# ---- Step 2: full-chain capture + independent verification ----


def _cert_chain(cn_leaf: str = "leaf.example", tamper_leaf_signature: bool = False,
                intermediate_ca: bool = True, intermediate_days: int = 300,
                leaf_days: int = 30, intermediate_cn: str = "Test Intermediate CA",
                rsa_padding: str = "pkcs1"):
    """Build root -> intermediate -> leaf; returns (pem_all, root_pem, int_pem, leaf_pem)."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    def keypair():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def build(subject, issuer_name, subject_key, signing_key, days, ca):
        b = (x509.CertificateBuilder()
             .subject_name(subject)
             .issuer_name(issuer_name)
             .public_key(subject_key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=40 if days < 0 else 5))
             .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)))
        if ca:
            b = b.add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        else:
            b = b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn_leaf)]), critical=False)
        padding_kwargs = {}
        if rsa_padding == "pss":
            padding_kwargs["rsa_padding"] = __import__(
                "cryptography.hazmat.primitives.asymmetric.padding", fromlist=["padding"]
            ).PSS(mgf=__import__(
                "cryptography.hazmat.primitives.asymmetric.padding", fromlist=["padding"]
            ).MGF1(hashes.SHA256()), salt_length=__import__(
                "cryptography.hazmat.primitives.asymmetric.padding", fromlist=["padding"]
            ).PSS.DIGEST_LENGTH)
        return b.sign(signing_key, hashes.SHA256(), **padding_kwargs)

    root_key, int_key, leaf_key = keypair(), keypair(), keypair()
    root = build(name("Test Root CA"), name("Test Root CA"), root_key, root_key, 3650, True)
    intermediate = build(name(intermediate_cn), name("Test Root CA"), int_key, root_key,
                         intermediate_days, intermediate_ca)
    leaf = build(name(cn_leaf), name(intermediate_cn), leaf_key, int_key, leaf_days, False)
    if tamper_leaf_signature:
        # re-sign the leaf's TBS with an unrelated key while keeping the
        # issuer name — signature verification must catch this
        evil_key = keypair()
        leaf = (x509.CertificateBuilder()
                .subject_name(name(cn_leaf))
                .issuer_name(name(intermediate_cn))
                .public_key(evil_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=5))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=leaf_days))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn_leaf)]), critical=False)
                .sign(evil_key, hashes.SHA256()))

    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()
    return "\n".join([pem(leaf), pem(intermediate), pem(root)]), pem(leaf), pem(intermediate), pem(root)


def test_full_chain_independently_verified():
    from app.pipeline.tls import analyze_tls

    pem, _, _, _ = _cert_chain()
    info = analyze_tls("leaf.example", pem)
    assert info.chain_length == 3
    assert info.chain_verified is True
    assert not any(e.startswith("chain verification:") for e in info.errors)


def test_tampered_leaf_signature_is_caught():
    from app.pipeline.tls import analyze_tls

    pem, _, _, _ = _cert_chain(tamper_leaf_signature=True)
    info = analyze_tls("leaf.example", pem)
    assert info.chain_verified is False
    assert any("signature not verifiable" in e for e in info.errors)


def test_non_ca_intermediate_violates_basic_constraints():
    from app.pipeline.tls import analyze_tls

    pem, _, _, _ = _cert_chain(intermediate_ca=False)
    info = analyze_tls("leaf.example", pem)
    assert info.chain_verified is False
    assert any("BasicConstraints ca=False on an issuing" in e for e in info.errors)


def test_expired_intermediate_is_caught():
    from app.pipeline.tls import analyze_tls

    pem, _, _, _ = _cert_chain(intermediate_days=-10)
    info = analyze_tls("leaf.example", pem)
    assert info.chain_verified is False
    assert any("expired" in e for e in info.errors)


def test_distrusted_intermediate_issuer_flagged():
    from app.pipeline.tls import analyze_tls

    pem, _, _, _ = _cert_chain(intermediate_cn="RapidSSL TLS RSA CA G1")
    info = analyze_tls("leaf.example", pem)
    # the intermediate IS the leaf's issuer — the reason must appear exactly
    # once (leaf-issuer screening; no duplicate from the old leaf-only path)
    rapid_lines = [e for e in info.errors if "RapidSSL" in e or "phishing kits" in e]
    assert rapid_lines and len(rapid_lines) == 1, info.errors
    assert DistrustedCaList.is_distrusted("RapidSSL TLS RSA CA G1")


def test_leaf_only_capture_does_not_claim_chain_verification():
    from app.pipeline.tls import analyze_tls

    _, leaf_pem, _, _ = _cert_chain()
    info = analyze_tls("leaf.example", leaf_pem)
    assert info.chain_length == 1
    assert info.chain_verified is False
    assert not any(e.startswith("chain verification:") for e in info.errors)


# ---- RSASSA-PSS signature verification (Task 1) ----


def test_pss_signed_chain_fully_verifies():
    """A chain signed with RSASSA-PSS (OID 1.2.840.113549.1.1.10) at every link
    must verify via the certificate's own PSS parameters — no false
    'unsupported signature' errors."""
    from app.pipeline.tls import analyze_tls

    pem, _, _, _ = _cert_chain(rsa_padding="pss")
    info = analyze_tls("leaf.example", pem)
    assert info.chain_length == 3
    assert info.chain_verified is True
    assert not any(e.startswith("chain verification:") for e in info.errors), info.errors


def test_pkcs1_and_pss_mixed_chain_verifies():
    """A PKCS#1-v1.5 root with a PSS-signed intermediate (and vice versa) must
    verify — each link uses its own encoded parameters."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID

    def keypair():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    root_key, int_key, leaf_key = keypair(), keypair(), keypair()
    now = datetime.datetime.now(datetime.timezone.utc)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)

    root = (x509.CertificateBuilder().subject_name(name("M Root")).issuer_name(name("M Root"))
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(root_key, hashes.SHA256()))  # PKCS#1 v1.5
    intermediate = (x509.CertificateBuilder().subject_name(name("M Int")).issuer_name(name("M Root"))
                    .public_key(int_key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
                    .sign(root_key, hashes.SHA256(), rsa_padding=pss))  # PSS
    leaf = (x509.CertificateBuilder().subject_name(name("mixed.example")).issuer_name(name("M Int"))
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("mixed.example")]), critical=False)
            .sign(int_key, hashes.SHA256()))  # PKCS#1 v1.5

    pem = "\n".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in (leaf, intermediate, root))
    from app.pipeline.tls import analyze_tls
    info = analyze_tls("mixed.example", pem)
    assert info.chain_verified is True, info.errors
    assert intermediate.signature_algorithm_oid == x509.SignatureAlgorithmOID.RSASSA_PSS


def test_pss_wrong_key_signature_rejected():
    """A PSS-signed certificate whose signature does not come from the claimed
    issuer must fail chain verification."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID

    key_a = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
    nm = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    root = (x509.CertificateBuilder().subject_name(nm("P Root")).issuer_name(nm("P Root"))
            .public_key(key_a.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key_a, hashes.SHA256()))
    # claims to be issued by "P Root" but is signed by key_b with PSS
    rogue = (x509.CertificateBuilder().subject_name(nm("rogue.example")).issuer_name(nm("P Root"))
             .public_key(key_b.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
             .sign(key_b, hashes.SHA256(), rsa_padding=pss))

    pem = "\n".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in (rogue, root))
    from app.pipeline.tls import analyze_tls
    info = analyze_tls("rogue.example", pem)
    assert info.chain_verified is False
    assert any("signature not verifiable" in e for e in info.errors)




# ---- VirusTotal budget & Retry-After (Task 3) ----


def test_vt_submit_budget_is_honored():
    from app.config import Settings
    from app.pipeline.intel import VirusTotal

    settings = Settings(virustotal_api_key="k", vt_submit_on_miss=True,
                        vt_submit_max_per_hour=1, vt_domain_fallback=True)
    VirusTotal._submit_window_start = 0.0
    VirusTotal._submit_count = 0

    posts: list[str] = []

    class SeqClient(_StubSyncClient):
        def __init__(self):
            super().__init__(None)
            self.url_gets: dict[str, int] = {}

        def get(self, *args, **kwargs):
            path = args[0] if args else ""
            self.calls.append((args, kwargs))
            if "/urls/" in path:
                self.url_gets[path] = self.url_gets.get(path, 0) + 1
                if self.url_gets[path] == 1:
                    return _StubResponse(404, {"error": {"code": "NotFoundError"}})
                return _StubResponse(200, _vt_v3_payload(malicious=7, harmless=63))
            return _StubResponse(404, {"error": {"code": "NotFoundError"}})

        def post(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            posts.append(args[0] if args else "")
            return _StubResponse(200, {"data": {"id": "x"}})

    vt = VirusTotal("k", settings)
    vt.client = SeqClient()
    vt.check_url("https://first.example.com/")   # consumes the 1-per-hour budget
    assert len(posts) == 1
    vt.check_url("https://second.example.com/")  # budget exhausted -> no POST
    assert len(posts) == 1
    VirusTotal._submit_window_start = 0.0
    VirusTotal._submit_count = 0


def test_vt_429_parses_retry_after():
    from app.pipeline.intel import IntelUnavailable, VirusTotal

    vt = VirusTotal("k")
    vt.client = _StubSyncClient(_StubResponse(
        429, {"error": {"code": "QuotaExceededError"}}, headers={"retry-after": "300"}))
    with pytest.raises(IntelUnavailable) as excinfo:
        vt.check_url("https://ratelimited2.example.com/")
    assert excinfo.value.retry_after == 300.0


def test_registry_backs_off_for_retry_after_window():
    """A 429 must open a SILENT window: subsequent calls emit RATELIMIT without
    any HTTP request (no thread stalls against a 429-ing provider)."""
    import asyncio
    import time as _time

    from app.pipeline.intel import IntelRegistry, IntelUnavailable
    from tests.conftest import make_settings

    settings = make_settings(urlhaus_api_key="k")
    registry = IntelRegistry(settings)
    calls = {"n": 0}

    class _Inner:
        def check_url(self, url):
            calls["n"] += 1
            raise IntelUnavailable("URLhaus rate-limited", retry_after=300.0)

        def check_domain(self, domain):
            return []

    registry._instances["urlhaus"] = _Inner()

    findings1 = asyncio.run(registry.check_url("https://a.example.com/"))
    assert calls["n"] == 1
    assert registry._failed["urlhaus"] > _time.time() + 200  # ~300s silent window
    assert registry.status()["urlhaus"] == "rate_limited"

    findings2 = asyncio.run(registry.check_url("https://b.example.com/"))
    assert calls["n"] == 1  # no second HTTP attempt inside the window
    assert any(f.id == "URLHAUS-RATELIMIT" for f in findings2)
