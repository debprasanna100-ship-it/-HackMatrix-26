"""Deterministic domain/URL heuristics (no network required).

Every finding is factual: evidence quotes what was observed, and the wording
distinguishes "commonly abused" from "confirmed malicious". The scoring engine
(Phase 2) combines these findings into a classification; heuristics never
classify on their own.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import parse_qsl

import idna

from ..models.enums import FindingCategory, Severity
from ..models.schemas import Finding
from .normalizer import NormalizedUrl
from .ssrf import classify_ip

SOURCE = "trustlens/domain-heuristics"

# Brands are matched against the registrable label (eTLD+1 label part) and host
# tokens. Each brand maps to the registrable domains that legitimately belong
# to it; those are never flagged.
BRAND_OFFICIAL: dict[str, set[str]] = {
    "google": {"google.com"},
    "youtube": {"youtube.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "tiktok": {"tiktok.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.co.jp"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
    "stripe": {"stripe.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "hsbc": {"hsbc.com"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "santander": {"santander.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "ledger": {"ledger.com"},
    "github": {"github.com"},
    "gitlab": {"gitlab.com"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com"},
    "telegram": {"telegram.org", "t.me"},
    "discord": {"discord.com", "discord.gg"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "roblox": {"roblox.com"},
    "playstation": {"playstation.com", "sony.com"},
    "xbox": {"xbox.com"},
    "icloud": {"icloud.com"},
    "adobe": {"adobe.com"},
    "zoom": {"zoom.us"},
    "slack": {"slack.com"},
    "shopify": {"shopify.com"},
    "ebay": {"ebay.com"},
    "walmart": {"walmart.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
    "irs": {"irs.gov"},
    "outlook": {"outlook.com", "live.com", "office.com"},
    "office365": {"office.com", "microsoft.com"},
    "sharepoint": {"sharepoint.com", "microsoft.com"},
    "americanexpress": {"americanexpress.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    # Indian banking & financial services
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "statebankofindia.com"},
    "statebankofindia": {"sbi.co.in", "onlinesbi.sbi", "statebankofindia.com"},
    "axisbank": {"axisbank.com"},
    "kotak": {"kotak.com", "kotakbank.com"},
    "pnb": {"pnbindia.in"},
    "pnbindia": {"pnbindia.in"},
    "bankofbaroda": {"bankofbaroda.in", "bankofbaroda.com"},
}

# Cheap/free or heavily-abused TLDs. Presence here is a weak signal, never proof.
SUSPICIOUS_TLDS_MEDIUM = {
    "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "top", "xyz",
    "cam", "cfd", "sbs", "quest", "monster", "buzz", "rest", "fit", "work",
    "loan", "men", "mom", "party", "date", "faith", "review", "stream", "icu", "pw",
}
SUSPICIOUS_TLDS_LOW = {
    "link", "info", "country", "kim", "gdn", "wang", "bar", "hair", "beauty",
    "makeup", "autos", "boats", "yoga", "cyou", "shop", "live", "cloud",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "rebrand.ly", "shorturl.at", "tiny.cc", "ow.ly", "buff.ly", "s.id",
    "v.gd", "t.ly", "shorte.st", "adf.ly", "bit.do", "soo.gd", "clck.ru",
    "qr.ae", "lnkd.in", "bl.ink",
}

SUSPICIOUS_HOST_KEYWORDS = [
    "login", "signin", "sign-in", "signon", "verify", "verification", "verifyaccount",
    "secure", "security", "account", "update", "confirm", "billing", "invoice",
    "payment", "wallet", "recover", "unlock", "suspend", "suspended", "alert",
    "helpdesk", "reset", "validate", "authenticate", "webscr", "credential",
]

REDIRECT_PARAM_NAMES = {
    "url", "uri", "link", "redirect", "redirect_url", "redirect_uri", "redirect_to",
    "return", "return_url", "returnto", "return_to", "next", "goto", "go", "target",
    "dest", "destination", "continuation", "continue", "forward", "out", "redir",
    "jump", "to", "u", "r", "callback", "callbackurl",
}

_EXECUTABLE_EXTS_MEDIUM = {".exe", ".msi", ".bat", ".cmd", ".scr", ".apk", ".dmg",
                           ".jar", ".vbs", ".ps1", ".hta", ".com"}
_EXECUTABLE_EXTS_LOW = {".zip", ".rar", ".7z", ".iso", ".img", ".gz"}

# Homoglyph folding: Cyrillic/Greek look-alikes plus common digit substitutions.
CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "А": "a", "Е": "e", "О": "o", "Р": "p",
    "С": "c", "Х": "x", "У": "y", "К": "k", "М": "m", "Т": "t", "В": "b", "Н": "h",
    # Greek
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z",
    "Η": "h", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t",
    "Υ": "y", "Χ": "x",
    # Digit look-alikes (only used for confusable comparison)
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "$": "s",
})

_SCRIPT_RANGES: list[tuple[str, int, int]] = [
    ("latin", 0x41, 0x5A), ("latin", 0x61, 0x7A), ("latin", 0xC0, 0x24F), ("latin", 0x1E00, 0x1EFF),
    ("greek", 0x370, 0x3FF), ("cyrillic", 0x400, 0x4FF), ("armenian", 0x530, 0x58F),
    ("hebrew", 0x590, 0x5FF), ("arabic", 0x600, 0x6FF), ("devanagari", 0x900, 0x97F),
    ("bengali", 0x980, 0x9FF), ("thai", 0xE00, 0xE7F), ("georgian", 0x10A0, 0x10FF),
    ("hiragana", 0x3040, 0x309F), ("katakana", 0x30A0, 0x30FF), ("han", 0x4E00, 0x9FFF),
    ("hangul", 0xAC00, 0xD7AF),
]


def _fold(text: str) -> str:
    return text.lower().translate(CONFUSABLES)


def damerau_levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Damerau-Levenshtein distance with early exit above `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev2: list[int] | None = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if (prev2 is not None and i > 1 and j > 1
                    and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]):
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[lb]


def scripts_in(text: str) -> set[str]:
    found: set[str] = set()
    for ch in text:
        if not unicodedata.category(ch).startswith("L"):
            continue
        cp = ord(ch)
        for name, start, end in _SCRIPT_RANGES:
            if start <= cp <= end:
                found.add(name)
                break
    return found


def _decode_punycode_host(host: str) -> str | None:
    if "xn--" not in host:
        return None
    try:
        return idna.decode(host)
    except (idna.IDNAError, UnicodeError):
        return None


def _finding(fid: str, title: str, severity: Severity, evidence: list[str],
             check_succeeded: bool = True) -> Finding:
    return Finding(
        id=fid, title=title, severity=severity, category=FindingCategory.DOMAIN,
        evidence=evidence, source=SOURCE, check_succeeded=check_succeeded,
    )


# Major ccTLDs where large brands legitimately own their exact name (google.de,
# paypal.co.uk, ...). Only used to suppress the exact-label lookalike check.
_MAJOR_CCTLD_SUFFIXES = {
    "de", "fr", "it", "es", "nl", "br", "ca", "us", "in", "jp", "co.uk",
    "com.au", "com.br", "com.mx", "com.sg", "co.za", "com.tr", "pl", "se",
    "no", "at", "ch", "be", "pt", "dk", "fi", "ie", "mx", "ar", "cl", "co",
}


def _official_domains(brand: str) -> set[str]:
    base = BRAND_OFFICIAL[brand]
    expanded = set(base)
    for domain in base:
        if domain.split(".")[0] == brand:
            expanded.update(f"{brand}.{sfx}" for sfx in _MAJOR_CCTLD_SUFFIXES)
    return expanded


def _brand_for(brand: str, registrable: str | None) -> bool:
    return registrable is not None and registrable.lower() in _official_domains(brand)


def _is_official_domain(registrable: str | None) -> bool:
    """True when the registrable domain is a known official domain of any tracked brand."""
    if not registrable:
        return False
    r = registrable.lower()
    return any(r in _official_domains(brand) for brand in BRAND_OFFICIAL)


def analyze_domain(norm: NormalizedUrl) -> list[Finding]:
    findings: list[Finding] = []
    host = norm.host
    analysis_host = norm.unicode_host or _decode_punycode_host(host) or host
    label = (norm.domain_label or "").lower()
    registrable = (norm.registrable_domain or "").lower()

    # --- credentials in URL -------------------------------------------------
    if norm.has_credentials:
        user = (norm.original_netloc or "").split("@")[0]
        shown = user.split(":", 1)[0] + ":•••" if ":" in user else user
        findings.append(_finding(
            "DOM-CREDENTIALS-IN-URL", "Credentials embedded in the URL", Severity.HIGH,
            [
                f"The submitted URL contains userinfo before '@' (username part: '{shown[:80]}').",
                "Browsers ignore everything before '@'; the real destination is the part after it. "
                "This pattern is frequently used to disguise the true host.",
            ],
        ))

    # --- typosquatting / homoglyphs against popular brands -------------------
    if label and not norm.is_ip_literal:
        folded = _fold(label)
        for brand, official in BRAND_OFFICIAL.items():
            official = _official_domains(brand)
            if registrable and registrable in official:
                continue
            if label == brand:
                findings.append(_finding(
                    "DOM-BRAND-LOOKALIKE-TLD",
                    f"Brand name '{brand}' used with an unrelated domain ending",
                    Severity.MEDIUM,
                    [
                        f"Registrable domain '{registrable}' uses the exact brand label '{brand}' "
                        f"but is not an official {brand} domain ({', '.join(sorted(official))}).",
                        "Legitimate organisations rarely host their brand on unrelated TLDs.",
                    ],
                ))
                break
            if len(brand) < 5:
                continue
            distance = damerau_levenshtein(label, brand, cap=2)
            folded_distance = damerau_levenshtein(folded, brand, cap=2)
            if folded_distance == 0 and label != brand:
                findings.append(_finding(
                    "DOM-HOMOGLYPH-CONFUSABLE",
                    f"Hostname is a confusable homoglyph of '{brand}'",
                    Severity.HIGH,
                    [
                        f"Label '{label}' becomes '{folded}' after homoglyph normalisation, "
                        f"exactly matching brand '{brand}'.",
                        f"Registrable domain: '{registrable}'.",
                    ],
                ))
                break
            threshold = 1 if len(brand) <= 6 else 2
            if distance <= threshold:
                findings.append(_finding(
                    "DOM-TYPOSQUAT",
                    f"Registrable domain is {distance} edit(s) from brand '{brand}'",
                    Severity.HIGH,
                    [
                        f"'{registrable}' is within {distance} Damerau-Levenshtein edit(s) of '{brand}'.",
                        "Typosquatting relies on users mistyping or misreading a known brand.",
                    ],
                ))
                break

    # --- IDN / homograph / mixed-script --------------------------------------
    non_ascii = [ch for ch in analysis_host if ord(ch) > 127]
    if non_ascii and not norm.is_ip_literal:
        scripts = scripts_in(analysis_host)
        if len(scripts) >= 2:
            findings.append(_finding(
                "DOM-MIXED-SCRIPT-HOST", "Hostname mixes multiple Unicode scripts", Severity.HIGH,
                [
                    f"Hostname '{analysis_host}' contains characters from scripts: {', '.join(sorted(scripts))}.",
                    "Mixed-script hostnames are the classic homograph attack vector; "
                    "legitimate IDNs normally use a single script.",
                ],
            ))
        else:
            findings.append(_finding(
                "DOM-NON-ASCII-HOST", "Hostname contains non-ASCII (internationalised) characters", Severity.LOW,
                [
                    f"Hostname '{analysis_host}' contains non-ASCII characters: "
                    f"{', '.join(sorted({f'U+{ord(c):04X}' for c in non_ascii}))}.",
                    "Internationalised domains are legitimate (e.g. bücher.de) but are also used for "
                    "homograph attacks; the rendered name may look identical to an ASCII domain.",
                ],
            ))
    if "xn--" in host and not norm.is_ip_literal:
        findings.append(_finding(
            "DOM-PUNYCODE-HOST", "Hostname uses punycode (xn--) encoding", Severity.LOW,
            [
                f"Host '{host}' contains punycode label(s); decoded form: '{analysis_host}'.",
                "Punycode is how IDNs are represented in DNS, but 'xn--' hostnames rendered in "
                "address bars have been widely abused for look-alike attacks.",
            ],
        ))

    # --- brand look-alikes inside the subdomain --------------------------------
    if norm.subdomain and not norm.is_ip_literal:
        sub = norm.subdomain.lower()
        sub_tokens = re.split(r"[.\-_]", sub)
        for brand in BRAND_OFFICIAL:
            if _brand_for(brand, registrable):
                continue  # the brand genuinely owns this registrable domain
            exact = brand in sub_tokens or (len(brand) >= 5 and brand in sub)
            homoglyph_token = next(
                (t for t in sub_tokens if t != brand and _fold(t) == brand), None
            )
            typo_token = next(
                (
                    t for t in sub_tokens
                    if len(t) >= 5 and t != brand and _fold(t) != brand
                    and damerau_levenshtein(t, brand, cap=1) <= 1
                ),
                None
            )
            if exact or homoglyph_token or typo_token:
                if homoglyph_token:
                    evidence_lead = (
                        f"Subdomain token '{homoglyph_token}' becomes '{brand}' after homoglyph "
                        f"normalisation."
                    )
                elif typo_token:
                    evidence_lead = (
                        f"Subdomain token '{typo_token}' is within 1 edit of '{brand}'."
                    )
                else:
                    evidence_lead = f"Subdomain '{sub}' contains '{brand}'."
                findings.append(_finding(
                    "DOM-BRAND-IN-SUBDOMAIN",
                    f"Brand look-alike '{brand}' appears in the subdomain of an unrelated domain",
                    Severity.HIGH,
                    [
                        evidence_lead,
                        f"The registrable domain — the part that actually identifies who controls "
                        f"the site — is '{registrable or host}'.",
                        "Everything before the registrable domain is chosen freely by its owner; "
                        "phishing kits exploit this to display a trusted name in the URL.",
                    ],
                ))
                break

    # --- suspicious keyword patterns ------------------------------------------
    host_tokens = re.split(r"[.\-_]", host) + re.split(r"[/.\-_]", norm.path.lower())
    # Whole-token matching only: a substring check flagged benign words that
    # merely CONTAIN a keyword ("updates" ⊃ "update", "insecure" ⊃ "secure").
    # Kit compounds without separators are covered by explicit list entries
    # ("verifyaccount", "webscr").
    keyword_hits: list[str] = []
    for keyword in SUSPICIOUS_HOST_KEYWORDS:
        if any(keyword == token for token in host_tokens):
            keyword_hits.append(keyword)
    brand_tokens = [b for b in BRAND_OFFICIAL
                    if any(b == token for token in re.split(r"[.\-_]", host))
                    and not _brand_for(b, registrable)]
    if brand_tokens and keyword_hits:
        findings.append(_finding(
            "DOM-BRAND-KEYWORD-PATTERN",
            "Brand name combined with credential-harvesting keywords",
            Severity.MEDIUM,
            [
                f"Hostname/path contains brand token(s) {brand_tokens[:3]} and keyword(s) {keyword_hits[:4]}.",
                f"Registrable domain: '{registrable or host}'. This combination is typical of phishing "
                "kits, though marketing pages can look similar.",
            ],
        ))
    elif keyword_hits and not _is_official_domain(registrable):
        findings.append(_finding(
            "DOM-SUSPICIOUS-KEYWORDS",
            "Hostname/path contains keywords common in phishing URLs",
            Severity.LOW,
            [
                f"Matched keyword(s): {', '.join(keyword_hits[:5])}.",
                "These words are also common in legitimate URLs; on their own they are not "
                "evidence of fraud.",
            ],
        ))

    # --- TLD reputation --------------------------------------------------------
    if norm.suffix and not norm.is_ip_literal:
        tld = norm.suffix.split(".")[-1]
        if tld in SUSPICIOUS_TLDS_MEDIUM:
            findings.append(_finding(
                "DOM-SUSPICIOUS-TLD",
                f"Domain uses the '.{tld}' TLD, which is frequently abused",
                Severity.MEDIUM,
                [
                    f"Registrable domain '{registrable}' ends in '.{tld}'.",
                    "Free/cheap or heavily-abused TLDs appear in a disproportionate share of phishing; "
                    "many legitimate sites use them too.",
                ],
            ))
        elif tld in SUSPICIOUS_TLDS_LOW:
            findings.append(_finding(
                "DOM-SUSPICIOUS-TLD",
                f"Domain uses the '.{tld}' TLD (weak abuse signal)",
                Severity.LOW,
                [
                    f"Registrable domain '{registrable}' ends in '.{tld}'.",
                    "Some abuse statistics list this TLD above average; the signal is weak on its own.",
                ],
            ))

    # --- shorteners -------------------------------------------------------------
    if host in URL_SHORTENERS:
        findings.append(_finding(
            "DOM-URL-SHORTENER", "URL is a link shortener", Severity.MEDIUM,
            [
                f"'{host}' is a known URL shortener.",
                "Shorteners obscure the true destination, which phishers exploit; the underlying "
                "link is not necessarily malicious.",
            ],
        ))

    # --- excessive subdomains ----------------------------------------------------
    if norm.subdomain and not norm.is_ip_literal:
        depth = len(norm.subdomain.split("."))
        if depth >= 6:
            findings.append(_finding(
                "DOM-EXCESSIVE-SUBDOMAINS", "Very deep subdomain chain", Severity.MEDIUM,
                [
                    f"Host has {depth} subdomain levels: '{norm.subdomain}'.",
                    "Long subdomain chains are used to push a trusted-looking word far left of "
                    "the registrable domain.",
                ],
            ))
        elif depth >= 4:
            findings.append(_finding(
                "DOM-EXCESSIVE-SUBDOMAINS", "Deep subdomain chain", Severity.LOW,
                [
                    f"Host has {depth} subdomain levels: '{norm.subdomain}'.",
                    "Occasionally legitimate (CDNs); also used to obscure the real domain.",
                ],
            ))

    # --- embedded redirect parameters --------------------------------------------
    if norm.query:
        for name, value in parse_qsl(norm.query, keep_blank_values=True):
            if name.lower() not in REDIRECT_PARAM_NAMES:
                continue
            looks_like_url = bool(re.match(r"^[a-z][a-z0-9+.\-]*://", value, re.IGNORECASE)) or \
                bool(re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}([/?#]|$)", value, re.IGNORECASE))
            if looks_like_url:
                findings.append(_finding(
                    "DOM-REDIRECT-PARAM",
                    "Query parameter appears to carry another URL (open-redirect lure)",
                    Severity.MEDIUM,
                    [
                        f"Parameter '{name}' contains: {value[:120]!r}.",
                        "Such parameters are used to lend a legitimate-looking domain to a "
                        "malicious destination.",
                    ],
                ))
                break

    # --- IP literal / private targets ----------------------------------------------
    if norm.is_ip_literal and norm.ip:
        try:
            reason = classify_ip(ipaddress.ip_address(norm.ip))
        except ValueError:
            reason = None
        if reason:
            findings.append(_finding(
                "DOM-PRIVATE-IP-TARGET", "Target is a private or reserved IP address", Severity.MEDIUM,
                [
                    f"Address '{norm.ip}' is {reason}.",
                    "TrustLens refuses to fetch private/reserved addresses (SSRF protection); "
                    "a public site hosted on such an address cannot be verified.",
                ],
            ))
        else:
            findings.append(_finding(
                "DOM-IP-LITERAL-HOST", "URL points at a raw IP address instead of a domain", Severity.MEDIUM,
                [
                    f"Host '{norm.ip}' is a bare IP literal.",
                    "Phishing infrastructure frequently skips domains and certificates; "
                    "internal tools also use raw IPs, so this is not proof of malice.",
                ],
            ))

    # --- URL shape oddities ------------------------------------------------------------
    if len(norm.url) > 160:
        findings.append(_finding(
            "DOM-LONG-URL", "Unusually long URL", Severity.LOW,
            [
                f"Canonical URL length is {len(norm.url)} characters.",
                "Excessive length is used to hide the true host past the visible edge of an "
                "address bar.",
            ],
        ))
    hyphens = host.count("-")
    if hyphens >= 4:
        findings.append(_finding(
            "DOM-EXCESSIVE-HYPHENS", "Hostname contains many hyphens", Severity.LOW,
            [
                f"Host '{host}' contains {hyphens} hyphen(s).",
                "Hyphen-stuffed hostnames imitate legitimate multi-word domains.",
            ],
        ))
    if norm.url.count("%") >= 5:
        findings.append(_finding(
            "DOM-HEAVY-ENCODING", "URL is heavily percent-encoded", Severity.LOW,
            [
                f"URL contains {norm.url.count('%')} percent-escape sequences.",
                "Encoding obscures the destination from visual inspection.",
            ],
        ))

    # --- executable-looking path ----------------------------------------------------------
    path_lower = norm.path.lower()
    for ext in _EXECUTABLE_EXTS_MEDIUM:
        if path_lower.endswith(ext):
            findings.append(_finding(
                "DOM-EXECUTABLE-DOWNLOAD-LINK", "URL path points at an executable file", Severity.MEDIUM,
                [
                    f"Path '{norm.path[:120]}' ends with '{ext}'.",
                    "TrustLens never downloads files; this is a URL-shape observation only.",
                ],
            ))
            break
    else:
        for ext in _EXECUTABLE_EXTS_LOW:
            if path_lower.endswith(ext):
                findings.append(_finding(
                    "DOM-ARCHIVE-DOWNLOAD-LINK", "URL path points at an archive file", Severity.LOW,
                    [
                        f"Path '{norm.path[:120]}' ends with '{ext}'.",
                        "Archives can carry payloads; many legitimate downloads use them too.",
                    ],
                ))
                break

    return findings
