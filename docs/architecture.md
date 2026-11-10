# TrustLens — Architecture

> Status: Phase 6 (final). This document describes the system as built.

## 1. System overview

```
                    ┌──────────────────────────────────────────────────────────┐
 Browser (React 19 + Vite + TS)                                                 │
   Submit │ Report │ Reports │ Verify                                           │
                    └───────────────────────────┬──────────────────────────────┘
                                                │ /api  (Vite dev proxy → :8000; nginx in Docker)
                    ┌───────────────────────────▼──────────────────────────────┐
                    │ FastAPI (app/main.py)                                    │
                    │  · sliding-window rate limit (per IP, /api/*)            │
                    │  · CORS · uniform error shaping {"error":{code,message}} │
                    └──┬───────────────┬───────────────┬──────────────────────┘
                       │               │               │
        ┌──────────────▼──┐   ┌────────▼────────┐  ┌────▼─────────────────┐
        │ URL pipeline    │   │ Message pipeline│  │ Chain (app/web3)     │
        │ (runner.py)     │   │ (message.py)    │  │ web3.py client       │
        │                 │   │  entity extract │  └────┬─────────────────┘
        │ 1 normalise     │   │  tactic tagging │       │ bytes32 = SHA-256
        │ 2 safe fetch ───┼──►│  embedded URLs ─┼───────┤ of canonical JSON
        │ 3 TLS analyse   │   │  (full URL      │       │ + "url-analysis"
        │ 4 CT history    │   │   pipeline)     │       ▼
        │ 5b header check │   │  deterministic  │  ThreatRegistry.sol
        │ 5c correlate    │   │  scoring        │  (Hardhat node / Sepolia)
        │ 6 threat intel  │   └────────┬────────┘
        │ 7 scoring       │            │
        │ 8 explanation   │            │
        │ 9 correlate     │            │
        └──────┬──────────┘            │
               ▼                       ▼
        SQLite / PostgreSQL  ◄─── reports, chain_commitments, correlation_indicators
```

## 2. Module map (backend)

| Module | Responsibility |
|---|---|
| `pipeline/normalizer.py` | Parse/validate/canonicalise URLs: scheme policy, IDN→punycode, IP-literal de-obfuscation (decimal/hex/octal), invisible-char stripping, tracking-param removal, offline eTLD+1 (tldextract, bundled PSL snapshot) |
| `pipeline/ssrf.py` | SSRF policy layer: hostname blocklist, IPv4/IPv6 range guards (private, loopback, link-local incl. 169.254.169.254 metadata, CGNAT, benchmark, multicast, reserved); IPv4-mapped addresses are unwrapped and re-checked, while NAT64 (64:ff9b::/96), 6to4, and Teredo prefixes are blocked outright, DNS resolution (dnspython + system fallback) |
| `pipeline/fetcher.py` | Safe fetcher: custom httpcore `AsyncNetworkBackend` that resolves+validates and dials the validated IP inside the connect step, for the initial URL AND every redirect hop (TLS still verifies the requested hostname via SNI); **fail-closed**: if the IP-pinning transport cannot be constructed, every fetch is refused with a POLICY error before any request — there is no plain-transport fallback; manual redirect tracing (≤5 hops, each re-validated); **full-chain capture on every runtime** — a pyOpenSSL memory-BIO TLS layer (OpenSSL verification + explicit SAN matching) captures the presented chain on CPython 3.11/3.12, the native `get_unverified_chain()` API on 3.13+, leaf-only otherwise, reset per hop so the FINAL connection's chain is analysed; 1 MB streaming body cap; non-textual bodies never read; honest TrustLensBot UA |
| `pipeline/tls.py` | Certificate analysis: subject/issuer, key type/size, signature algorithm, SAN-vs-hostname (wildcard-aware), expiry windows, self-signed detection, distrusted-CA screening of every chain certificate, and — for full captured chains — **independent re-verification** (signatures incl. **RSASSA-PSS** parameters, validity windows, BasicConstraints) surfaced as `chain_verified` |
| `pipeline/crtsh.py` | Certificate Transparency history via crt.sh (cached 5 min): recency gated to small CT footprints, issuance bursts, volume (informational), issuer diversity |
| `pipeline/domain_heuristics.py` | Offline deterministic heuristics: Damerau-Levenshtein typosquats vs ~50 brands, homoglyph folding (Cyrillic/Greek/digit confusables), mixed-script detection, brand-in-subdomain (exact/homoglyph/typo tokens), suspicious TLDs, shorteners, redirect params, credentials, IP-literal/private targets, URL-shape oddities, executable-looking paths |
| `pipeline/intel.py` | Threat-intel adapters per official docs (GSB v4 `threatMatches`, URLhaus v1 object API, OpenPhish community feed, PhishTank v2 checkurl, VirusTotal v3 with `x-apikey` header) behind one interface; per-provider status (active/unconfigured/rate-limited/failed); TTL+size-bounded caches that never cache failures as clean; keys never in URLs; `answered_providers()` feeds the required threat-intel outage gate |
| `pipeline/headers.py` | Passive header checks on the captured response: HSTS/CSP/framing/nosniff, version disclosure, cookie flags, plain-HTTP, naive mixed-content scan of the capped body excerpt. Hardening gaps are informational; plain-HTTP and mixed content carry real severity |
| `pipeline/correlation.py` | Rule-based correlation: indicator extraction (domain/IP/issuer/message-hash), prior-hit aggregation, TF-IDF cosine over report text (pure Python) |
| `pipeline/dns_records.py` | Passive A/MX/NS/TXT lookups (dnspython, injectable query fn): system resolver with **RFC 8484 DoH fallback on port 443** (Cloudflare → Google; NXDOMAIN never retried); capped/sanitised evidence (TXT count + SPF flag only), per-type success/failure findings, optional `dns-records` coverage stage |
| `pipeline/scoring.py` | Deterministic scoring: severity×category weights, per-ID special rules, required-vs-optional check policy (fetch + configured-feed outage ⇒ inconclusive; optional failures recorded but non-gating; authoritative hits take precedence) → five-band classification |
| `pipeline/runner.py` | Orchestrator: stages 1–9 (incl. DNS records), coverage accounting (attempted 10), final-host TLS analysis with leaf-only capture note, required/optional-check wiring, integrity hash (canonical JSON, excludes regenerable `explanation`) |
| `pipeline/message.py` | Message analysis: entity extraction (emails/phones stored as counts only), 7 tactic families with quoted evidence, OTP-request detector, embedded-URL pipeline **with persisted sub-reports**, honest coverage, indicator recording |
| `llm/client.py` | Provider-agnostic OpenAI-compatible chat client (key in env, never logged) |
| `llm/explain.py` | Injection-safe explanation: structured-findings-only payload (no raw message body, no emails/phones), `<UNTRUSTED-TEXT>` delimitation after smuggling-proof sanitisation, strict jsonschema output, unsupported-statement filtering across claims/caveats/actions AND summary (fallback on violation), classification immutable |
| `llm/rules.py` | Deterministic fallback explainer (same output shape, no network) |
| `web3/registry.py` | web3.py ThreatRegistry client (submit/verify/getReport/revisions), canonical-hash helpers shared with the runner |
| `storage/models.py` | ORM schema: ReportRow (+`owner_id` FK → users, `is_public`), UserRow (email, PBKDF2 hash, API-key hash, role, `email_verified`, `updated_at`), ChainCommitmentRow, CorrelationIndicatorRow |
| `storage/database.py` | Engine/session machinery; **PostgreSQL runs Alembic migrations at startup (fail-closed)**; SQLite keeps the create_all + idempotent in-place column fallback; re-exports the models |
| `storage/seed.py` | Hardened admin bootstrap: creates TRUSTLENS_INITIAL_ADMIN_* idempotently (startup hook + CLI, incl. operator password-reset token minting) |
| `storage/repository.py` | Persistence incl. deletion, retention purge, ownership/visibility queries, and user store |
| `api/auth.py` | Multi-tenant auth: PBKDF2 password hashing, purpose-scoped HS256 JWTs (PyJWT: access/email-verify/password-reset), X-API-Key resolution, `CurrentUser` dependency, auth-required gate, register (gated: open-registration flag / admin / bootstrap) + token + api-key + **verify-email + password-reset** endpoints |
| `api/` | Routes: analyze (URL/message), reports (GET/PATCH/DELETE with owner-or-public checks), commit (owner-only 403), verify (ID / raw hash / **supplied report JSON** — public), correlate, meta, health; rate-limit middleware |

## 3. Report schema (v2.1)

Every report: `schema_version`, `report_id` (uuid4 hex), `created_at`, `input_type`, `raw_input`,
`normalized`, `classification`, `classification_rationale`, `findings[]`, `redirect_chain[]`,
`fetch`, `tls`, `threat_intel`, `ct_history`, `scoring`, `explanation`, `coverage`,
`recommended_actions`, `limitations`, `integrity`, `extras` (headers summary, message entities,
sub-report refs, correlation snapshot).

Each `finding`: `id` (stable, e.g. `DOM-TYPOSQUAT`), `title`, `severity`
(info|low|medium|high|critical), `category`, `weight`, `evidence[]` (quoted facts), `source`,
`check_succeeded` (failed checks are never treated as clean results).

## 4. On-chain design

- `ThreatRegistry.sol` (Solidity 0.8.24): `submitReport(bytes32,string)`, `getReport`,
  `updateStatus` (reporter-only, revision history — contract-level governance only; no API or
  UI caller in this MVP), `verify`, `getRevision`/`getRevisionCount`.
- Committed value: SHA-256 of the report's **canonical JSON** (sorted keys, compact separators,
  excluding `integrity` itself and the regenerable `explanation`). Content (URLs, message text,
  personal data) never goes on-chain.
- Commit flow: recompute hash from the stored report → refuse on mismatch (`integrity_mismatch`)
  or duplicate (`already_committed`) → sign & send → persist receipt (tx hash, block, gas).
- Verify flow: by report ID (recompute + compare + chain read), by raw `0x`-hash (chain read), or
  by **supplied report JSON** (`POST /api/v1/verify/report`: schema+size validated, hash
  recomputed, compared against its own integrity field / an expected hash / the chain —
  "exists on-chain" and "contents match" reported as independent facts) — public, no submission
  required.

## 5. AI layer

- One OpenAI-compatible client covers OpenAI/DeepSeek/Kimi/GLM/OpenRouter/Ollama via env vars.
- The model receives **only** structured findings JSON (sanitised, then wrapped in
  `<UNTRUSTED-TEXT>` delimiters; no raw message bodies, no extracted emails/phones); output must
  pass a strict JSON schema; unsupported statements are stripped everywhere — claims without
  valid finding IDs, safety claims ("is safe" is forbidden outright), and malice claims the
  deterministic verdict does not back; an unsupported summary invalidates the whole reply and the
  rule-based explanation is served instead; the classification is copied from the scoring engine —
  the LLM cannot change it.
- No key or provider failure ⇒ rule-based fallback (same shape, zero network).

## 6. Data stores

| Table | Purpose |
|---|---|
| `reports` | Full report JSON + summary columns |
| `chain_commitments` | Per-report receipt (report hash, tx, contract, block) |
| `correlation_indicators` | `(kind, value, report_id, classification)` rows: domain/IP/issuer/message-hash |

## 7. Frontend

React 19 + Vite + TypeScript. Pages: Submit (URL/Message tabs), Report (risk badge, scoring
grid, explanation card, message entities — emails/phones shown as privacy counts — tactics,
related-incidents card, findings table, redirect chain, TLS incl. leaf-capture note, intel
statuses, coverage, recommended actions, limitations, integrity + on-chain commit + **Copy
report JSON** + **Delete report**), Reports list, Verify (by report ID/hash or by **pasting
report JSON** with an optional expected hash). Vite dev proxy forwards `/api` and `/health` to
:8000; the Docker image uses nginx with the same proxy rules.

## 8. Testing strategy

Unit tests isolate all network/chain boundaries with fakes (FakeResolver, FakeTransport,
StubRegistryClient, injected DNS query functions, stubbed sync httpx clients for intel
adapters) — the backend suite (unit + API + chain + AI + message + headers + correlation + DNS + scoring policy + auth + migrations + TLS capture + settings/intel-status + budget policy) and 17 contract tests run offline. Live behaviour is validated by
explicit smoke runs; the documented 3-suspicious + 3-benign cases and their observed outputs
are recorded in [testing-report.md](testing-report.md) with raw JSON in [case-runs/](case-runs/).
