# TrustLens — Testing Report

> Deliverable. Records **observed** results from automated suites and the documented live case
> runs (3 suspicious + 3 benign), originally executed 2026-11-08 on the development machine
> (Windows 11, Python 3.11.9, Node 24, httpx 0.28.1). Updated after the security/robustness
> hardening pass (same day) — see §5 for what changed and how unit-tested vs live-observed
> behaviour is distinguished.

## 1. Automated suites (observed)

| Suite | Command | Result (observed) |
|---|---|---|
| Backend (pytest) | `cd backend && pytest` | **395 passed + 4 skipped** (~1 min; the 4 skipped are `tests/test_intel_live.py`, which run against real provider endpoints only when API keys are configured AND `TRUSTLENS_LIVE_INTEL_TESTS=1` is set) |
| Contracts (Hardhat) | `cd contracts && npx hardhat test` | **17 passing** (~2 s) |
| Frontend (type-check + build + vitest) | `cd frontend && npm run build` + `npm run test` | build clean; oxlint 0 warnings/0 errors; 11 vitest tests (auth token store + API-client auth behaviour) |

**Live-provider contract tests** (`test_intel_live.py`): need BOTH provider keys and an explicit
opt-in (`TRUSTLENS_LIVE_INTEL_TESTS=1`, e.g. PowerShell `$env:TRUSTLENS_LIVE_INTEL_TESTS="1"` before
`pytest tests/test_intel_live.py`) — keys alone are not enough, so plain `pytest` never issues a
network request even on a machine with configured keys. When opted in they exercise the REAL
endpoints (Google's official `testsafebrowsing.appspot.com` test URL only — never live threat
URLs) to catch provider-side response-shape drift that stubbed unit tests cannot see.

Backend suites cover: URL normalisation (24), SSRF range/hostname guards + IP-pinning dial
validation + fail-closed transport (33), safe-fetcher redirect tracing, error taxonomy and
per-hop certificate capture (26), domain heuristics incl. benign-suppression (37), TLS parsing
+ SAN wildcards + final-host/expired/self-signed report flow, crt.sh query building + dual
schema parsing, passive DNS record checks with injected queries (7), scoring engine bands,
required/optional-check policy (outage, precedence, optional-unavailable), threat-intel
adapters against documented response shapes (matches, no-matches, unverified PhishTank entries,
invalid credentials, rate limits, server errors, malformed JSON — all stubbed), storage
round-trips + deletion + retention, API end-to-end (fake network) incl. DELETE and feed-outage
gates, chain commit/verify incl. tamper detection + supplied-report verification, LLM-layer
injection defences + data-exposure (no emails/phones/raw bodies) + unsupported-statement
filtering + fallback, message pipeline (zero/one/multiple/malformed/failed embedded URLs),
passive header checks, correlation (indicator hits, TF-IDF, endpoint).

**No automated test touches the real internet or a live chain** — all network/chain/DNS
boundaries are faked (FakeResolver, FakeTransport, StubRegistryClient, injected DNS query
functions, stubbed sync httpx clients). Live behaviour is covered by §3 and §5.

## 2. Unit-tested vs live-observed — what this report can and cannot claim

| Behaviour | Evidence type |
|---|---|
| SSRF range guards, IP pinning dials the validated IP, fail-closed when transport init fails, blocked targets never contacted | **unit-tested** (mocked resolvers/transports, dial recording) |
| Redirect tracing, body caps, per-hop cert capture reset | **unit-tested** (canned responses with synthetic certs) |
| TLS parsing/SAN/expiry/self-signed + report flow against the final redirect host | **unit-tested** (synthetic certificates); live: chain is validated by the handshake against system roots |
| Live leaf-certificate capture from the httpcore stream | **live-observed** (github.com/example.com scans populated issuer/cert_sha256); capture is leaf-only by design |
| CT (crt.sh) parsing, both API schemas | **unit-tested**; live: crt.sh frequently 502/404s from this network — degrades to "unavailable" honestly |
| DNS record checks (A/MX/NS/TXT) | **unit-tested** with injected queries (NXDOMAIN/timeout/no-answer/malformed); live from this network often times out (dev-network resolver) → honest `dns-records` unavailable |
| Threat-intel adapters (GSB v4, URLhaus v1, OpenPhish feed, PhishTank v2, VT v3) | **unit-tested against documented response shapes** with stubbed clients; live matching requires real API keys (not available on this machine) — live rows honestly read "unconfigured" |
| Scoring policy (required/optional gates, precedence) | **unit-tested** + API-level outage tests |
| Chain commit/verify/tamper/supplied-report verification | **unit-tested** (StubRegistryClient) + **live-observed** on the local Hardhat chain (§4) |
| LLM injection defences & data minimisation | **unit-tested** (stubbed provider captures the exact payload) |
| Message pipeline coverage/persistence | **unit-tested** (fake fetchers, incl. mixed live/dead links) |

## 3. Documented case runs (3 benign + 3 suspicious)

**Safety of the sample set**: benign targets are well-known production sites. Suspicious targets
are **synthetic**: one intentionally-unregistered look-alike domain (nothing is contacted — DNS
fails, `FETCH-DNS-FAIL`) and two phishing-style messages analysed through the offline message
pipeline (no URLs ⇒ no fetches). No live phishing infrastructure, malware hosting, or intel-feed
sample was visited, per the build rules.

Raw API responses are preserved in [`case-runs/`](case-runs/) (B1–S3 JSON + correlation demo).

### Benign cases — expected: no significant indicators (`low_risk`)

| # | Target | Observed classification | Key observed findings | Coverage |
|---|---|---|---|---|
| B1 | `https://example.com/` (IANA reserved doc domain) | **low_risk** | 4 × info: missing HSTS/CSP/framing/nosniff headers (hardening quality only) | 6/9* |
| B2 | `https://www.wikipedia.org/` (Wikimedia) | **low_risk** | none — clean across all completed checks | 6/9* |
| B3 | `https://github.com/` (GitHub) | **low_risk** | 1 × info: Set-Cookie without Secure flag (hardening detail) | 6/9* |

\* Coverage in these recorded runs predates the `dns-records` stage (attempted is now 10).
Re-observed after the hardening pass: example.com and github.com are **low_risk, score 0**, with
`ct-history` honestly unavailable (crt.sh 404/502 from this network) — 8/10 completed. The
distrusted-CA false positives on mainstream certificates (previously 2 × `TLS-POLICY` on
github.com's DigiCert cert) are gone.

Notes: missing-header findings are informational by design (calibrated after the first live run
showed `example.com`/`github.com` tripping `suspicious` on hardening gaps — see methodology §9).
Unavailable TLS/CT/DNS checks are listed in coverage, not treated as clean passes.

### Suspicious cases — expected: detection fires, verdict honest

| # | Target | Observed classification | Key observed findings | Coverage |
|---|---|---|---|---|
| S1 | `http://paypa1.com.verify-account.xyz/login` — synthetic PayPal look-alike (unregistered) | **inconclusive** | `DOM-BRAND-IN-SUBDOMAIN` (high), `DOM-SUSPICIOUS-TLD` (medium), `DOM-SUSPICIOUS-KEYWORDS` (low), `FETCH-DNS-FAIL` (low) | 4/9* |
| S2 | Phishing-style SMS: bank "compromised", urgency, call security team, **read aloud the one-time code** (no URL) | **high_risk** | `MSG-OTP-REQUEST` (high), `MSG-LANGUAGE-TACTICS` (low; tactics: urgency, threat_or_consequence, impersonation, credential_harvesting) | 2/3 |
| S3 | Fraud-style SMS: crypto "guaranteed returns", gift cards, secrecy (no URL) | **suspicious** | `MSG-PAYMENT-PRESSURE` (medium), `MSG-LANGUAGE-TACTICS` (low; tactics: impersonation, too_good_to_be_true, secrecy; payment: cryptocurrency, gift card) | 2/3 |

Reading of S1: detection fired strongly (high-severity brand-in-subdomain with quoted evidence),
but the synthetic domain does not resolve, so the page could not be fetched — per the required-
check policy the verdict is `inconclusive`, **not** a risk band. This is the intended honest
behaviour: a verdict without a completed fetch is never issued.

## 4. Live end-to-end chain verification (local Hardhat, chainId 31337)

Contract `0x5FbDB2315678afecb367f032d93F642f64180aa3`:

| Step | Observed |
|---|---|
| Deploy | tx `0x4de241516d9bc4669f08ea4e386b006ad3ada781fd081e1872a82a6a656741ab` |
| Commit report `32b7af80…` | tx `0x6bb801d1060e424d90903770bd3f5bdd877a4b94ec2410b03a395c44eb85ae1b`, block 2, gas 73 369 |
| Verify by report ID | `integrity_match: true`, `on_chain.exists: true`, reporter `0xf39F…2266`, status `submitted` |
| Verify by unknown raw hash | `exists: false` |
| Duplicate commit | `409 already_committed` |
| Tamper check (SQLite forgery) | `integrity_match: false` + warning (unit-tested: `test_verify_detects_tampered_report`) |

Supplied-report verification (`POST /api/v1/verify/report`) is unit-tested (matching, altered,
malformed, oversized, missing-integrity, unknown/invalid expected hash); it is not part of the
recorded on-chain case run above.

## 5. Hardening pass (2026-11-08) — scope of the recorded changes

- SSRF: no plain-transport fallback (fail-closed), dial-to-validated-IP and never-contacted
  assertions added; TLS analysed against the final redirect host; leaf-only capture explicitly
  documented per report; missing capture recorded as unavailable.
- Scoring policy: required (fetch; configured-feed outage) vs optional checks formalised and
  documented; authoritative precedence; optional unavailability non-gating.
- Threat-intel adapters rewritten to official documentation (VT v2→v3, PhishTank verified+valid,
  OpenPhish community feed, GSB valid threat types); keys out of URLs; bounded expiring caches;
  failures never cached as clean.
- LLM layer: emails/phones and raw bodies excluded from the payload; smuggling-proof
  delimitation; unsupported statements filtered in claims, caveats, actions, and summaries.
- Privacy: emails/phones never stored (counts only); DELETE endpoint + startup retention purge;
  capability-addressed reports documented.
- Message reports: embedded-URL sub-reports persisted (links retrievable), honest coverage
  (attempted 3), malformed URLs and failed fetches represented in `unavailable_checks`.
- New passive DNS record checks (optional stage, attempted 9 → 10) with RFC 8484 DoH fallback
  for restricted networks (fetcher resolver deliberately unchanged).
- Multi-tenant auth (opt-in): JWT + API-key dependencies, ownership matrix, first-user-admin
  bootstrap; web3 client re-reads the deployment file on empty-code answers (Hardhat restarts).
- VirusTotal v3 miss policy: passive domain fallback (default) + opt-in submit-on-miss with
  an hourly submission budget; 429 answers open a Retry-After-aware silent backoff window.
- DoH failover: three independent operators (Cloudflare/Google/Quad9) with 2 s per-endpoint
  budgets; total failure yields the honest `DNS-LOOKUP-FAILED` summary without halting.
- Alembic migrations (baseline + multi-tenant auth) with upgrade/downgrade/upgrade cycle
  tests; PostgreSQL runs them at startup, SQLite keeps the automatic fallback.
- Hardened bootstrap: seeded admin (env/CLI, idempotent), gated self-registration,
  purpose-scoped tokens, password-reset and email-verification stubs.

## 6. Definition of Done — status

| Requirement | Status |
|---|---|
| `docker-compose up` (or documented commands) runs the full app | ✅ BOTH verified: the documented manual commands, and a full `docker compose up --build` observed on Docker 29.x / Compose v5 (fresh build boots chain → deploy → backend → frontend; commit/verify, volume persistence, and chain-restart recovery observed). One caveat: with the native backend also running, loopback `127.0.0.1:8000` reaches the native process — see README §7. |
| Demo flow: submit → investigate → report → commit → independent verification | ✅ observed end-to-end (§4 + demo script `scripts/demo.sh`) |
| Tests pass; testing-report records 3 suspicious + 3 benign | ✅ backend + contracts green + frontend checks clean (counts in §1); this document |
| README: setup, env vars, contract address, tx reference | ✅ |
| Docs: architecture, pipeline, intel sources, security methodology, privacy policy | ✅ architecture.md + methodology.md (incl. §2 policy, §6b DNS, §11 privacy, §12 verification) |
