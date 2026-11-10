"""Unit tests for deterministic domain heuristics."""
from __future__ import annotations

import pytest

from app.models.enums import Severity
from app.pipeline.domain_heuristics import analyze_domain, damerau_levenshtein
from app.pipeline.normalizer import normalize_url


def findings_for(url: str):
    return analyze_domain(normalize_url(url))


def ids(findings):
    return {f.id for f in findings}


# ---- distance function -------------------------------------------------------


@pytest.mark.parametrize("a,b,expected", [
    ("google", "google", 0),
    ("goog1e", "google", 1),
    ("paypa1", "paypal", 1),
    ("amozon", "amazon", 1),
    ("amazn", "amazon", 1),
    ("netflxi", "netflix", 1),  # adjacent transposition
])
def test_damerau_levenshtein(a, b, expected):
    assert damerau_levenshtein(a, b, cap=3) == expected


def test_damerau_levenshtein_far_apart():
    # 'secure-paypal' vs 'paypal' needs 7 deletions; early-exit caps the work.
    assert damerau_levenshtein("secure-paypal", "paypal", cap=3) == 4
    assert damerau_levenshtein("secure-paypal", "paypal", cap=10) == 7


# ---- individual heuristics -----------------------------------------------------


def test_typosquat_detected():
    # 'paypall' = insertion typo (paypa1 is caught as a homoglyph instead).
    out = findings_for("http://paypall.com/login")
    assert "DOM-TYPOSQUAT" in ids(out)
    finding = next(f for f in out if f.id == "DOM-TYPOSQUAT")
    assert finding.severity == Severity.HIGH
    assert any("paypal" in e for e in finding.evidence)


def test_digit_homoglyph_detected_as_confusable():
    out = findings_for("http://paypa1.com/login")
    assert "DOM-HOMOGLYPH-CONFUSABLE" in ids(out)


def test_cyrillic_homoglyph_detected():
    # "аpple.com" with a Cyrillic 'а' (U+0430)
    out = findings_for("https://аpple.com/")
    found = ids(out)
    assert "DOM-HOMOGLYPH-CONFUSABLE" in found or "DOM-MIXED-SCRIPT-HOST" in found
    assert "DOM-PUNYCODE-HOST" in found


def test_brand_in_subdomain_detected():
    out = findings_for("http://paypal.com.secure-login.example.io/")
    assert "DOM-BRAND-IN-SUBDOMAIN" in ids(out)
    finding = next(f for f in out if f.id == "DOM-BRAND-IN-SUBDOMAIN")
    assert any("example.io" in e for e in finding.evidence)


def test_homoglyph_in_subdomain_detected():
    # paypa1 (digit 1) folds to paypal; registrable domain is the unrelated xyz host
    out = findings_for("http://paypa1.com.verify-account.xyz/")
    assert "DOM-BRAND-IN-SUBDOMAIN" in ids(out)
    finding = next(f for f in out if f.id == "DOM-BRAND-IN-SUBDOMAIN")
    assert finding.severity == Severity.HIGH
    assert any("homoglyph" in e.lower() for e in finding.evidence)
    assert any("verify-account.xyz" in e for e in finding.evidence)


def test_typo_in_subdomain_detected():
    out = findings_for("http://paypall.com.evil.io/")
    assert "DOM-BRAND-IN-SUBDOMAIN" in ids(out)


def test_brand_lookalike_tld_detected():
    out = findings_for("http://paypal.security-example.top/")
    # registrable label is 'security-example'; brand token appears in subdomain
    assert "DOM-BRAND-IN-SUBDOMAIN" in ids(out) or "DOM-SUSPICIOUS-TLD" in ids(out)


def test_suspicious_tld_medium():
    out = findings_for("http://random-site.tk/")
    assert "DOM-SUSPICIOUS_TLD".replace("_", "-") in ids(out)
    finding = next(f for f in out if f.id == "DOM-SUSPICIOUS-TLD")
    assert finding.severity == Severity.MEDIUM


def test_url_shortener_detected():
    out = findings_for("https://bit.ly/3xY2zAb")
    assert "DOM-URL-SHORTENER" in ids(out)


def test_ip_literal_host_flagged():
    out = findings_for("http://93.184.216.34/admin")
    assert "DOM-IP-LITERAL-HOST" in ids(out)


def test_private_ip_literal_flagged():
    out = findings_for("http://192.168.1.1/admin")
    assert "DOM-PRIVATE-IP-TARGET" in ids(out)


def test_excessive_subdomains_flagged():
    out = findings_for("http://a.b.c.d.evil.io/")
    assert "DOM-EXCESSIVE-SUBDOMAINS" in ids(out)


def test_redirect_parameter_flagged():
    out = findings_for("http://go.example.com/?url=https://phish.example/claims")
    assert "DOM-REDIRECT-PARAM" in ids(out)


def test_credentials_in_url_flagged():
    out = findings_for("http://user:pw@phish.example/")
    assert "DOM-CREDENTIALS-IN-URL" in ids(out)
    finding = next(f for f in out if f.id == "DOM-CREDENTIALS-IN-URL")
    assert "pw" not in " ".join(finding.evidence)  # password must be masked


def test_brand_plus_keyword_pattern():
    out = findings_for("http://paypal-login-verify.xyz/")
    assert "DOM-BRAND-KEYWORD-PATTERN" in ids(out)


def test_long_url_flagged():
    long_path = "/" + "a" * 200
    out = findings_for(f"https://example.com{long_path}")
    assert "DOM-LONG-URL" in ids(out)


def test_executable_path_flagged():
    out = findings_for("https://downloads.example.com/setup.exe")
    assert "DOM-EXECUTABLE-DOWNLOAD-LINK" in ids(out)


# ---- benign cases must stay clean -----------------------------------------------


@pytest.mark.parametrize("url", [
    "https://www.google.com/search?q=test",
    "https://github.com/microsoft/vscode",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.paypal.com/signin",  # official domain: keyword check must not escalate
    "https://example.com/",
    "https://münchen.de/",  # legitimate IDN
    "https://onlinesbi.sbi/",  # official SBI portal
    "https://sbi.co.in/",
    "https://www.hdfcbank.com/",
    "https://www.icicibank.com/",
    "https://www.kotak.com/",
    "https://www.pnbindia.in/",
])
def test_benign_urls_produce_no_domain_findings(url):
    out = findings_for(url)
    # IDN gets an informational low-severity note, everything else must be empty.
    assert all(f.severity != Severity.HIGH for f in out), f"unexpected high finding for {url}: {out}"
    unexpected = [f.id for f in out if f.id not in ("DOM-NON-ASCII-HOST", "DOM-PUNYCODE-HOST")]
    assert unexpected == [], f"unexpected findings for {url}: {unexpected}"


def test_official_brand_ccTLD_not_flagged():
    out = findings_for("https://google.de/")
    assert ids(out) == set()


def test_indian_bank_phishing_detected():
    # SBI brand + keyword combination on rogue domain
    sbi_kyc = findings_for("http://sbi-instant-kyc-verification.top/")
    assert "DOM-BRAND-KEYWORD-PATTERN" in ids(sbi_kyc)

    # SBI brand used directly with rogue TLD
    sbi_rogue = findings_for("http://sbi.xyz/login")
    assert "DOM-BRAND-LOOKALIKE-TLD" in ids(sbi_rogue)

    # Kotak brand + keyword pattern
    kotak_scam = findings_for("http://kotak-netbanking-verify.xyz/")
    assert "DOM-BRAND-KEYWORD-PATTERN" in ids(kotak_scam)

    # PNB brand in subdomain
    pnb_sub = findings_for("http://pnb.secure-login.com/")
    assert "DOM-BRAND-IN-SUBDOMAIN" in ids(pnb_sub)

