# TrustLens — Detection & Scoring Methodology

> Principle: **cybersecurity checks produce facts; a deterministic engine produces the verdict;
> the AI only explains.** Absence of findings is "no significant indicators found in the available
> checks" — never "safe". Failed required checks force `inconclusive` — never a clean verdict.

## 1. Severity model

| Severity | Weight (base) | Meaning |
|---|---|---|
| info | 0 | Context / hardening detail; never moves the band |
| low | 2 | Weak indicator, common in legitimate traffic |
| medium | 5 | Notable indicator; meaningful in combination |
| high | 8 | Strong indicator of impersonation / malicious infrastructure |
| critical | 12 | Reserved for definitive compromise evidence |

Intel findings count **double** (authoritative sources deserve more weight than heuristics).
A finding's explicit non-zero `weight` field overrides the table (used by special producers).

## 2. Classification bands and the required/optional check policy

```
authoritative intel hit                       → confirmed_malicious   (wins over everything — see below)
required check failed/timed out               → inconclusive
every CONFIGURED intel provider unavailable   → inconclusive
any high finding OR score ≥ 20                → high_risk
any medium/low finding OR score ≥ 8           → suspicious
nothing above informational                   → low_risk
```

**Required checks** (failure ⇒ `inconclusive`):

- `page-fetch` — the SSRF-safe fetch must complete. Without a completed fetch no verdict is
  issued (timeout, DNS failure, policy refusal, redirect exhaustion all qualify). The caller
  (URL runner / message pipeline) declares this explicitly; in message reports the gate fires
  only when *every* embedded URL failed to fetch — partial failures stay scorable and remain
  visible as evidence.
- `threat-intel` (conditional) — when at least one provider is **configured** (API key present),
  at least one configured provider must answer. If every configured provider is down /
  rate-limited / key-rejected, absence of intel hits is not evidence, so the report is
  `inconclusive`.

**Optional checks** (failure recorded, verdict unchanged): `tls-analysis`, `ct-history`,
`dns-records`, `header-checks`, `correlation`, and *unconfigured* threat-intel providers.
Their unavailability is preserved as evidence (`check_succeeded=false`, excluded from counts and
score, listed in `coverage.unavailable_checks` and `scoring.key_checks_unavailable`) but never
changes the band. A missing optional feed key is a configuration state, not a target signal.

**Precedence, documented:** a successful authoritative feed hit yields `confirmed_malicious`
even when other checks failed. Rationale: positive, feed-confirmed evidence about the target
must stay actionable; the hard rule is that a failed check may never produce a *benign* verdict
(no `low_risk` after a required-check failure — `inconclusive` instead).

Authoritative feeds (single hit suffices): URLhaus URL/host match, PhishTank entry that is
**verified AND valid**, OpenPhish community-feed match, Google Safe Browsing
`MALWARE`/`SOCIAL_ENGINEERING`/`POTENTIALLY_HARMFUL_APPLICATION`, VirusTotal with ≥ 6 adverse
engines (`malicious + suspicious` in v3 stats).

## 3. Heuristic catalogue (offline, deterministic)

| Finding | Severity | Logic / rationale |
|---|---|---|
| `DOM-CREDENTIALS-IN-URL` | high | userinfo before `@` (browser ignores it; classic disguise) |
| `DOM-TYPOSQUAT` | high | Damerau-Levenshtein ≤ 1 (brands ≤ 6 chars) / ≤ 2 (longer) vs ~50 tracked brands, excluding each brand's official domains (incl. major ccTLDs) |
| `DOM-HOMOGLYPH-CONFUSABLE` | high | confusable fold (Cyrillic/Greek look-alikes + digit substitutions `0→o 1→l 3→e 5→s 7→t`) matches a brand exactly |
| `DOM-BRAND-IN-SUBDOMAIN` | high | brand token, homoglyph-folded token, or ≤1-edit token in the subdomain of an unrelated registrable domain |
| `DOM-BRAND-LOOKALIKE-TLD` | medium | exact brand label on a non-official TLD |
| `DOM-MIXED-SCRIPT-HOST` | high | ≥ 2 Unicode scripts in the hostname |
| `DOM-NON-ASCII-HOST` / `DOM-PUNYCODE-HOST` | low | legitimate IDNs exist; flagged for the rendered-look-alike risk |
| `DOM-SUSPICIOUS-TLD` | medium / low | curated free/cheap or heavily-abused TLD tiers |
| `DOM-URL-SHORTENER` | medium | known shortener host |
| `DOM-EXCESSIVE-SUBDOMAINS` | medium (≥6) / low (≥4) | depth hides the registrable domain |
| `DOM-REDIRECT-PARAM` | medium | `url=/next=/goto=…` carrying another URL/domain |
| `DOM-IP-LITERAL-HOST` | medium | raw IP instead of a domain |
| `DOM-PRIVATE-IP-TARGET` | medium | private/reserved IP (also SSRF-refused; never fetched) |
| `DOM-BRAND-KEYWORD-PATTERN` | medium | brand token + credential-harvesting keywords (`login`, `verify`, `secure`, …) |
| `DOM-SUSPICIOUS-KEYWORDS` | low | harvesting keywords alone (also common in legitimate URLs) |
| `DOM-LONG-URL` / `DOM-EXCESSIVE-HYPHENS` / `DOM-HEAVY-ENCODING` | low | shape obfuscation |
| `DOM-EXECUTABLE-DOWNLOAD-LINK` / `DOM-ARCHIVE-DOWNLOAD-LINK` | medium / low | path targets an executable/archive (never downloaded) |

Suppression rules to protect precision: official brand domains (incl. major ccTLDs like
`google.de`, `paypal.co.uk`) are never flagged; keyword findings are suppressed on known-official
registrable domains.

## 4. Fetch & transport signals

| Finding | Severity | Logic |
|---|---|---|
| `FETCH-DNS-FAIL` / `FETCH-FAILED` / `FETCH-BLOCKED-POLICY` / `FETCH-TOO-MANY-REDIRECTS` | low/info/medium/low | coverage events — all force `inconclusive` |
| `FETCH-TLS-DOWNGRADE` | medium | https → http redirect in the chain |
| `FETCH-SIZE-CAP` | low | body exceeded the 1 MB cap (truncated analysis) |
| `HEADER-PLAIN-HTTP` | medium | final page delivered without TLS |
| `HEADER-MIXED-CONTENT` | low | https page referencing `http://` resources (capped excerpt; namespace URLs excluded) |
| `HEADER-HSTS-MISSING`, `HEADER-CSP-MISSING`, `HEADER-FRAMING-OPEN`, `HEADER-CTO-MISSING`, `HEADER-SERVER-VERSION`, `HEADER-XPOWERED-DISCLOSURE`, `HEADER-COOKIE-NOSECURE` | **info** | hardening-quality signals, explicitly not risk indicators (live calibration: example.com and github.com ship without some of these) |

## 5. TLS / CT signals

- **Chain capture & independent verification (full chain on every runtime)**: CPython 3.13+
  exposes the peer-presented chain via `get_unverified_chain()`. On 3.11/3.12 TrustLens layers
  a **pyOpenSSL memory-BIO TLS stream** into the httpcore backend (OpenSSL verifies the chain
  against the system store; the hostname/SAN match is re-checked explicitly; any failure falls
  back to the stdlib layer with leaf-only capture, attributed in `tls.note`). With a full
  chain captured, TrustLens re-verifies it independently of the handshake: cryptographic
  signatures from the leaf up every presented issuer — **RSA PKCS#1 v1.5 and RSASSA-PSS**
  (PSS verified with the certificate's own encoded hash/MGF1/salt parameters; the classic
  `sha*WithRSAEncryption` OIDs use v1.5) / ECDSA / Ed25519 / Ed448 / DSA — validity windows
  (`not_valid_before_utc`/`not_valid_after_utc`), and BasicConstraints (`ca=True` on
  intermediates, `ca=False` on the leaf). **Every** certificate in the chain — leaf,
  intermediates, root — is screened against the distrusted/dead-CA list. The trust anchor
  itself lives in the system store and was validated during the handshake, so a non-self-signed
  top-of-chain is normal, not an error. Chain-verification failures are honest findings
  (`chain verification: …`), never silent passes. Capture methods, in order of preference:
  native `unverified-chain` (3.13+), pyOpenSSL `verified-chain (pyOpenSSL)` /
  `unverified-chain (pyOpenSSL)`, then `leaf-only` — the method used is recorded in every
  report's `tls.note`.

## 5b. DNS-over-HTTPS fallback (restricted networks)

- The passive record checks query the system resolver first; on failure (timeout, refused,
  network down) each query retries over **RFC 8484 DoH on port 443** (Cloudflare, then Google,
  then Quad9 — 2 s per endpoint)
  via dnspython's DoH transport. NXDOMAIN is a definitive answer and is NOT retried over DoH.
- Scope guard: the **fetcher's SSRF pinning resolver deliberately does not use DoH** — changing
  the fetch path's resolver is a security-sensitive change outside this stage's purpose.
- Config: `TRUSTLENS_DNS_USE_DOH` (default on), `TRUSTLENS_DNS_TIMEOUT` (default 3.0 s).

- TLS findings (`TLS-WEAK-KEY`, `TLS-WEAK-SIGNATURE`, `TLS-EXPIRED`, `TLS-EXPIRY-IMMINENT`,
  `TLS-SELF-SIGNED`, `TLS-POLICY` incl. distrusted-CA indicators) are parsed from the presented
  certificate. **A valid certificate is never proof of safety** — look-alike domains can hold
  perfectly valid certificates.
- CT (`crt.sh`): calibrated against real-world noise —
  - `CT-RECENTLY-ISSUED`: **medium only** when the newest cert is < 24 h old *and* the domain has
    < 10 total CT records (brand-new small infra); within 7 days on anything larger → info,
    because CDNs reissue constantly;
  - `CT-HIGH-VOLUME` / `CT-MODERATE-VOLUME`: informational (huge footprints are normal for
    CDNs/multi-tenant SaaS);
  - `CT-MULTIPLE-ISSUERS` (≥ 8 distinct CAs): medium — phishing kits genuinely rotate CAs;
  - `CT-BURST-ISSUANCE` (≥ 3 inserts in 5 min): medium — automated kit deployment.

## 6. Threat-intel sources & degradation

Adapters follow the providers' current official documentation:

| Source | API & auth | Behaviour without key / on failure |
|---|---|---|
| Google Safe Browsing v4 | `threatMatches:find` (documented `client`+`threatInfo` body); `key` query-parameter auth — the endpoint refuses header-based identity (403 "unregistered callers") | unconfigured ⇒ row "unconfigured"; 403 ⇒ `KEY-ERROR`; 429 ⇒ rate-limited (60 s backoff); malformed JSON ⇒ `ERROR` (failed check) |
| URLhaus v1 (abuse.ch) | `POST /v1/url/` and `/v1/host/`; form-encoded; `Auth-Key` header | object-response parsing (`query_status`/`url_details`/`host_details`); failures ⇒ `ERROR` |
| OpenPhish | official **community feed** `https://feed.openphish.com/v3/feed.txt` (no key needed); TrustLens requires any non-empty `TRUSTLENS_OPENPHISH_API_KEY` value (e.g. `community`) as an explicit opt-in — the value is never sent anywhere | feed is cached ≤ 5 min; feed-fetch failures ⇒ `OPENPHISH-ERROR` (failed check, never cached as clean) |
| PhishTank v2 | `POST checkurl.phishtank.com/api/v2/checkurl/` with `app_key` in the body | only **verified+valid** records are authoritative; in-database but unverified/invalid entries yield `PHISHTANK-UNVERIFIED` (info) |
| VirusTotal **v3** | `GET /api/v3/urls/{id}` and `/api/v3/domains/{name}`; `x-apikey` header | On URL 404: passive **domain fallback** (`VT_DOMAIN_FALLBACK`, default on) — a domain match with ≥ 8 malicious engines is authoritative, weaker ones are `VT-LOW-CONFIDENCE` (non-authoritative, `domain_positives=` evidence the scoring engine's authority rule cannot see); both missing ⇒ `VT-NODATA` info (never clean); `VT_SUBMIT_ON_MISS=true` (opt-in, ACTIVE) additionally POSTs unknown URLs for scanning; 401/403 ⇒ `KEY-ERROR`; 429 ⇒ rate-limited; malformed JSON ⇒ `ERROR` |

Cross-cutting rules: API keys never appear in URLs; responses are cached in a TTL (300 s) +
size-bounded (512 entries) cache; failures are never cached as clean results; non-success,
malformed, and rate-limited responses are failed/unavailable checks — never clean results.
The whole stage runs under one wall-clock budget per URL analysis
(`TRUSTLENS_INTEL_BUDGET_SECONDS`, default 60 s): on expiry the remaining provider checks are
cancelled and recorded as failed coverage (`INTEL-BUDGET-EXCEEDED`), findings and
authoritative matches obtained before the timeout are preserved, and a timeout with no
earlier answer keeps the outage ⇒ `inconclusive` rule (never a clean answer).

## 6b. Passive DNS record checks

- Read-only A / MX / NS / TXT lookups on the registrable domain via dnspython (3 s budget,
  parallel queries; NXDOMAIN short-circuits the remaining types).
- Evidence is capped and sanitised: address/nameserver names (max 3 each) and the TXT **count**
  + SPF-presence flag. Raw TXT bodies are never stored or shown (they can carry site-verification
  tokens).
- Every query outcome is recorded (`DNS-RECORDS` summary, per-type `DNS-<T>-UNAVAILABLE`
  failures, `DNS-NXDOMAIN`), each with source, evidence, and success/failure, and feeds the
  optional `dns-records` coverage stage.
- Optional check: a DNS lookup failure or absent records is a coverage/context statement — DNS
  records can be absent or change at any time and are **not proof of legitimacy** — never a
  verdict change, and never a bypass of the fetcher's SSRF validation.

## 7. Message-analysis methodology

- Entity extraction: URLs (scheme-less `www.` normalised, trailing punctuation stripped, cap 10),
  emails, phones (digit-count validated), payment indicators (crypto, gift cards, wires, P2P
  apps, card details, generic demands).
- **Privacy**: extracted email addresses and phone numbers are never stored in reports and never
  sent to the LLM — only their counts are persisted. Only a 500-character excerpt of the message
  is stored; quoted tactic evidence is limited to short lexicon phrases. See §11.
- Tactic families (quoted evidence, soft indicators — **never** proof of fraud): urgency,
  threat_or_consequence, impersonation, credential_harvesting, too_good_to_be_true, secrecy,
  authority_pressure.
- Escalators (verified-evidence-adjacent): `MSG-OTP-REQUEST` (high — no legitimate company asks
  users to relay one-time codes) and `MSG-PAYMENT-PRESSURE` (medium — payment method paired with
  urgency/secrecy instructions).
- Embedded URLs run the full URL pipeline and are **persisted as independent reports**, so the
  message report's embedded-URL links stay retrievable; their findings (including authoritative
  intel hits) inherit into the message report, so fraud verdicts require the same evidence bar
  as URLs. Malformed extracted URLs yield `MSG-URL-INVALID` and are counted in coverage.
- Coverage model (attempted 3): `message-entity-extraction`, `language-analysis`,
  `embedded-url-analysis`. Failed embedded fetches are recorded honestly
  (`embedded-url-fetch (n/m … failed)` in `unavailable_checks`).
- Required-check rule: when embedded URLs exist, the embedded-URL fetch is required — if *every*
  embedded URL failed to complete a fetch, the verdict is `inconclusive`. Failed fetches,
  unparsable URLs (`MSG-URL-INVALID`), and URLs skipped by the aggregate message budget
  (`MSG-URL-SKIPPED`, `TRUSTLENS_MESSAGE_URL_BUDGET_SECONDS`, default 240 s) all count as
  "not fetched"; partial failures stay scorable (dead links remain as evidence with zero
  weight).

## 8. Correlation methodology (rule-based only)

- Indicators recorded per persisted report: registrable domain + host (domain), resolved IPs
  (ip), TLS issuer CN (issuer), message text SHA-256 (message_hash).
- Matching: exact indicator equality across reports; text similarity via TF-IDF cosine over
  `raw_input` (pure-Python IDF over the candidate set; threshold 0.25 — small-corpus IDF
  compresses absolute values).
- Escalation: an indicator previously seen in `confirmed_malicious`/`high_risk` analyses yields
  `CORR-PRIOR-MALICIOUS` (medium); any other repeat yields `CORR-PRIOR-SEEN` (info). Reputation
  history is explicitly labelled context, not proof.
- The AI never decides relationships; it may only summarise what the deterministic matcher found.

## 9. Calibration decisions (from live testing)

- Missing security headers demoted to info: `example.com` (IANA) and `github.com` ship without
  some of them — they are hardening quality, not threat.
- CT volume/recency demoted per §5 after `wikipedia.org`-scale footprints proved noisy.
- Wildcard SAN semantics follow DNS rules (`*.example.org` covers any single label).
- Distrusted-CA list is deliberately conservative (documented incidents/revocations only);
  valid certificates from reputable CAs on look-alike domains are covered by the brand heuristics.

## 10. Known blind spots (stated in every report)

JavaScript-rendered content, client-side redirects, login-page payloads, non-HTTP schemes,
private networks (by policy), and anything behind authenticated walls. Passive analysis cannot
see what only executes in a browser — this is why the product reports evidence and coverage, not
certainty.

## 11. Privacy & data-handling policy (MVP, no user-identity system)

TrustLens has no accounts, so the privacy model is **capability-addressed, redacted-at-source**:

- **Report IDs are the access credential.** Every report gets an unguessable 128-bit random ID
  (`uuid4.hex`); possession of the ID is what grants read access. IDs are not enumerable and
  list endpoints expose metadata only (no `raw_input`, no findings, no entities).
- **Never stored, anywhere:** extracted email addresses and phone numbers (counts only), raw
  message bodies beyond a 500-character excerpt, fetched page bodies, TLS private material,
  anything that goes on-chain except the canonical hash + fixed category tag.
- **Deliberate retention:** reports persist so they can be re-verified. `DELETE
  /api/v1/reports/{report_id}` (capability: hold the ID) removes a report plus its correlation
  indicators and chain-commitment record. `TRUSTLENS_REPORT_RETENTION_DAYS=N` purges everything
  older than N days at startup (0 = keep indefinitely).
- **The AI sees the least possible data:** no raw message bodies, no emails, no phones —
  structured findings with delimited untrusted values only (see architecture §5).
- These are documented MVP trade-offs, not production access control. A multi-tenant deployment
  would need real authentication; this project deliberately does not fake one.

## 13. Multi-tenant authentication & authorization (opt-in)

- `TRUSTLENS_AUTH_REQUIRED=false` (default): local/demo mode — no credentials, behaviour
  unchanged, valid credentials still attach ownership.
- **Hardened bootstrap**: admin rights are NEVER granted to the first arbitrary registration.
  The administrator account is created explicitly from configuration
  (`TRUSTLENS_INITIAL_ADMIN_EMAIL`/`_PASSWORD`, applied idempotently at startup and via
  `python -m app.storage.seed`); self-registration is closed by default when auth is enabled
  (`TRUSTLENS_ALLOW_OPEN_REGISTRATION=true` opens it; admins can always create users; a fresh
  deployment with an empty user table allows exactly one bootstrap registration with role
  `user` so it can never deadlock).
- **Token purposes**: access / email-verify / password-reset tokens are HS256 JWTs with an
  explicit `purpose` claim — a token minted for one purpose is rejected for every other.
- **Lifecycle stubs (no mailer in this MVP)**: `POST /auth/password-reset/request` mints a
  15-minute reset token (returned in the response in development mode; mintable by an operator
  via `python -m app.storage.seed --reset-token <email>`; discarded in production mode until a
  mailer exists) and `POST /auth/password-reset/confirm` applies it; registration returns an
  email-verification token and `POST /auth/verify-email` sets the flag. Responses never reveal
  whether an email exists. `users.updated_at`/`email_verified` track the lifecycle.
- `TRUSTLENS_AUTH_REQUIRED=true`: every analyze/management route requires **Bearer JWT**
  (dashboard users; HS256, `exp` enforced, secret ≥ 32 bytes per RFC 7518) or **X-API-Key**
  (programmatic users; 256-bit keys, only SHA-256 hashes stored, shown exactly once).
- Authorization matrix: `POST /analyze/*` attaches `owner_id` (sub-reports inherit it);
  `GET /reports` filters by owner (admins see all); `GET /reports/{id}` allows owner,
  `is_public` reports, or admins (foreign private reports answer 404 — existence is not
  leaked); `DELETE` and `commit` are strictly owner/admin (403); `GET /verify/*` stays
  public so third parties can check integrity hashes. First registered user becomes admin.
- Owner/visibility live OUTSIDE the report JSON — the canonical integrity hash is unaffected.
- **Schema management**: PostgreSQL deployments run **Alembic migrations** at startup
  (fail-closed on error); SQLite dev/test keeps the automatic create_all + in-place column
  fallback, and the migrations are exercised directly by the test suite
  (`tests/test_migrations.py`, upgrade/downgrade/upgrade cycles).
- Limitation: the reset/verification flows are stubs without a mailer (documented above);
  reset tokens are single-purpose and short-lived but not single-use (no server-side
  revocation list in this MVP).

## 12. Independent report verification

Three verification paths, reporting **independent facts** (never conflated):

1. `GET /api/v1/verify/{report_id}` — recompute the hash of the *stored* report and compare with
   its recorded `integrity` field (`integrity_match`) and the on-chain commitment.
2. `GET /api/v1/verify/{0x…}` — look up a raw 32-byte hash on-chain.
3. `POST /api/v1/verify/report` — anyone pastes an *exported report JSON*; the server validates
   schema + size (≤ 512 kB), recomputes the canonical hash, and reports:
   `integrity_match` (do the supplied contents match the report's own recorded integrity hash?),
   `hash_match` (do they match a caller-supplied expected hash?), and `on_chain.exists` (is the
   recomputed hash committed?). "The hash exists on-chain" and "these contents produce that
   hash" are separate fields with a note explaining the difference. Only the 32-byte hash is
   ever looked up on-chain — report contents never leave the supplied payload.
   The report page's **Copy report JSON** button feeds this flow end-to-end.
