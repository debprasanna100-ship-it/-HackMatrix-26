"""Unit tests for the URL normaliser."""
from __future__ import annotations

import pytest

from app.pipeline.normalizer import UrlNormalizationError, normalize_url


def test_adds_default_scheme():
    norm = normalize_url("example.com")
    assert norm.scheme == "https"
    assert norm.url == "https://example.com/"
    assert any("assumed https" in n for n in norm.notes)


def test_preserves_http_scheme():
    norm = normalize_url("http://example.com/page?id=7")
    assert norm.scheme == "http"
    assert norm.url == "http://example.com/page?id=7"


def test_lowercases_host_and_keeps_path_case():
    norm = normalize_url("https://WWW.Example.COM/Path/Q")
    assert norm.host == "www.example.com"
    assert norm.path == "/Path/Q"


def test_drops_fragment_and_notes_it():
    norm = normalize_url("https://example.com/page#section")
    assert "#" not in norm.url
    assert norm.fragment == "section"


def test_strips_tracking_parameters():
    norm = normalize_url("https://example.com/?utm_source=x&id=2&FBCLID=abc&keep=1")
    assert "utm_source" not in norm.query
    assert "fbclid" not in norm.query.lower()
    assert "keep=1" in norm.query
    assert any("tracking" in n for n in norm.notes)


def test_idn_to_punycode():
    norm = normalize_url("https://münchen.de/faq")
    assert norm.host == "xn--mnchen-3ya.de"
    assert norm.unicode_host == "münchen.de"
    assert norm.registrable_domain == "xn--mnchen-3ya.de"
    assert any("punycode" in n for n in norm.notes)


def test_trailing_dot_removed():
    norm = normalize_url("https://example.com./x")
    assert norm.host == "example.com"


def test_credentials_detected_and_removed():
    norm = normalize_url("https://alice:secret@example.com/")
    assert norm.has_credentials is True
    assert norm.original_netloc == "alice:secret@example.com"
    assert norm.url == "https://example.com/"
    assert "secret" not in norm.url


def test_decimal_ip_obfuscation_canonicalised():
    # 2130706433 == 127.0.0.1
    norm = normalize_url("http://2130706433/admin")
    assert norm.is_ip_literal is True
    assert norm.ip == "127.0.0.1"
    assert norm.host == "127.0.0.1"
    assert any("canonicalised" in n for n in norm.notes)


def test_octal_ip_obfuscation_canonicalised():
    # 0177.0.0.1 == 127.0.0.1
    norm = normalize_url("http://0177.0.0.1/")
    assert norm.ip == "127.0.0.1"


def test_ipv6_literal_parsed():
    norm = normalize_url("http://[2001:db8::1]:8080/x")
    assert norm.is_ip_literal is True
    assert norm.ip == "2001:db8::1"
    assert norm.port == 8080
    assert "[2001:db8::1]:8080" in norm.url


def test_non_standard_port_preserved_for_policy_check():
    norm = normalize_url("https://example.com:8443/")
    assert norm.port == 8443
    assert ":8443" in norm.url


def test_registrable_domain_extraction():
    norm = normalize_url("https://secure.paypal.com.evil.io/x")
    assert norm.registrable_domain == "evil.io"
    assert norm.subdomain == "secure.paypal.com"
    assert norm.domain_label == "evil"


def test_registrable_domain_multi_label_suffix():
    norm = normalize_url("https://shop.example.co.uk/item")
    assert norm.registrable_domain == "example.co.uk"
    assert norm.suffix == "co.uk"
    assert norm.subdomain == "shop"


def test_ip_literal_has_no_registrable_domain():
    norm = normalize_url("http://8.8.8.8/")
    assert norm.is_ip_literal is True
    assert norm.registrable_domain is None


def test_invisible_characters_stripped():
    norm = normalize_url("https://exa\u200bmple.com/")
    assert norm.host == "example.com"


def test_wrapping_quotes_stripped():
    norm = normalize_url('"https://example.com/"')
    assert norm.url == "https://example.com/"


def test_rejects_javascript_scheme():
    with pytest.raises(UrlNormalizationError) as exc:
        normalize_url("javascript:alert(document.cookie)")
    assert "scheme" in str(exc.value).lower()


def test_rejects_data_scheme():
    with pytest.raises(UrlNormalizationError):
        normalize_url("data:text/html,<script>alert(1)</script>")


def test_rejects_file_scheme():
    with pytest.raises(UrlNormalizationError):
        normalize_url("file:///etc/passwd")


def test_rejects_ftp_scheme():
    with pytest.raises(UrlNormalizationError):
        normalize_url("ftp://files.example.com/pub")


def test_rejects_whitespace_inside():
    with pytest.raises(UrlNormalizationError):
        normalize_url("https://example.com/with space")


def test_rejects_empty_and_garbage():
    with pytest.raises(UrlNormalizationError):
        normalize_url("   ")
    with pytest.raises(UrlNormalizationError):
        normalize_url("just some random text!!")


def test_rejects_overlong_input():
    with pytest.raises(UrlNormalizationError):
        normalize_url("https://example.com/" + "a" * 3000)


def test_rejects_hostless_url():
    with pytest.raises(UrlNormalizationError):
        normalize_url("https://:8080/path")
