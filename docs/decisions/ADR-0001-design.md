# ADR-0001 — pg_qsag_audit Design

| Field | Value |
|---|---|
| **ADR Number** | 0001 |
| **Title** | pg_qsag_audit Design |
| **Status** | Accepted (amended) |
| **Date Proposed** | 2026-05-09 |
| **Date Accepted** | 2026-05-09 |
| **Date Amended** | 2026-05-10 (see §7 Amendment Log) |
| **Author** | Muhammad Zaid Naeem (Maintainer, AIXYBER TECH LTD trading as Neoxyber) |
| **Approver** | Muhammad Zaid Naeem (Sole Director, AIXYBER TECH LTD) |
| **Supersedes** | None (this is the first artefact-level ADR) |
| **Superseded By** | None |
| **Related Master ADRs** | ADR-0031 (Open-Source Cryptographic and Audit Substrate Programme; amended 2026-05-09) in the private neoxyber-qsag repository |
| **Related Sibling ADRs** | qsag-anchors ADR-0001-design (federated SCITT TS primitives); qsag-canonical ADR-0001-design (RFC 8785 JCS implementation) |
| **Source-of-authority for amendment** | docs/research/2026-05-10-v01-landscape.md (committed at `1d0d0836dc55ac3efaf204e4ba68667ac77a8e8d`, 2026-05-10) |
| **Scope** | pg_qsag_audit v0.1 design surface, with v0.5 trajectory previewed |
| **Licence** | Apache License 2.0 |

---

## 1. Context

### 1.1 What this ADR locks

This ADR is the design decision record for `pg_qsag_audit`, the third artefact in the Q-SAG open-source substrate programme. It commits to the v0.1 SQL surface, the dual-flavour build-target architecture (`dist/tle/` and `dist/pgrx/`), the SHA3 implementation strategy, the dispatcher state machine, the audit-chain hash linkage, the threat model, the conformance testing discipline, the integration pattern with sibling Q-SAG artefacts, and the v0.5 trajectory.

The master programme ADR (ADR-0031 in the private neoxyber-qsag repository, amended 2026-05-09 at commit `5541d7b32e16b5a1da8b25e17a1c989cff049dde`) commits to the existence of this artefact and to its place in the ten-artefact substrate programme. This ADR-0001 commits to *how* the artefact is designed.

Per the locked ADR discipline in ADR-0031 §4.1 (the two-tier ADR structure: master programme ADRs in `neoxyber-qsag`, per-artefact ADRs in this repository), this ADR-0001 must be committed before any source code lands in `dist/tle/` or `dist/pgrx/`. This is being committed as part of the initial repository scaffolding.

This ADR was amended in place on 2026-05-10 to incorporate three Stage 0 hardenings derived from a comprehensive landscape research synthesis (committed at `1d0d0836dc55ac3efaf204e4ba68667ac77a8e8d` to `docs/research/2026-05-10-v01-landscape.md`). The amendments tighten — they do not reverse — the original design. The full amendment provenance is in §7 Amendment Log.

### 1.2 Why this artefact exists

PostgreSQL is the operational data plane for a substantial fraction of audit-relevant systems in the AI-agent governance horizon: regulator submissions, evidence packs, agent-action ledgers, transparency-service mirrors. EU AI Act Article 12 (full force 2 August 2026), CRA Article 14 (vulnerability reporting from 11 September 2026), eIDAS 2 EUDI Wallets (member-state availability late 2026), and CNSA 2.0 (procurement gate 1 January 2027) all converge on one engineering requirement: tamper-evident logs with cryptographically-agile, post-quantum-aware hash functions, anchored at the database tier where the data lives.

The "seven-year SHA3 absence in PostgreSQL" is a story that has been told often. It is also, on inspection, more nuanced than the headline. OpenSSL has provided SHA3 to `pgcrypto`'s `digest()` function via the EVP layer since OpenSSL 1.1.1 (September 2018). On a recent PostgreSQL build linked against a recent OpenSSL, `SELECT encode(digest('abc', 'sha3-256'), 'hex')` returns the canonical SHA3-256 of `'abc'` — with no third-party extension. The 2018 pgsql-hackers thread "need for SHA3" closed on this rationale: OpenSSL would carry it. That decision has held for over seven years, and it works for most users.

What that decision did not provide — and what `pg_qsag_audit` provides — is the layered set of disciplines that turn a hash function into an audit primitive:

1. **Documentation** that advertises SHA3 explicitly with KAT-verified behaviour and copy-pastable examples, rather than leaving SHA3 silently available via the "any algorithm OpenSSL supports" clause that most engineers and most auditors do not know about.
2. **Portability** to OpenSSL builds without SHA3 (some legacy ARM toolchains, FIPS-stripped builds, certain Bitnami images) via a pure-plpgsql fallback that is KAT-verified to match the OpenSSL-backed result byte-for-byte.
3. **Sandbox-safety on managed tiers** (AWS RDS, Aurora, Supabase) where C extensions are forbidden, via the `pg_tle` Trusted Language Extensions framework. The TLE flavour ships SHA3 plus the audit-chain primitives in pure plpgsql, deployable on every managed tier where `pg_tle` itself is supported.
4. **Negotiation-integrity binding** per NIST CSWP 39 §3.2.3 (final 19 December 2025): the choice of cryptographic implementation is cryptographically bound to the audit trail of the decisions it produces. The dispatcher logs the dispatch decision (pgcrypto vs in-extension fallback) into the audit chain itself, with the negotiated algorithm identifier (`alg_id`) recorded on every audit row.
5. **Audit-chain primitive** with hash-chained tamper-evidence, RFC 8785 canonical input encoding, NIST SP 800-185 KMAC keyed-mode domain separation, typed-algorithm-tag domain separators that enable forward-compatible algorithm migrations, and verifiable end-to-end integrity via `pg_qsag.verify_chain()`.
6. **Regulator-readiness** for EU AI Act Article 12 export views, CRA Article 14 reporting cascade (24h/72h/14d/final from 11 September 2026 onward), and the v0.5 SCITT Signed Statement emitter that anchors database-tier audit events into IETF SCITT Transparency Services.

The defensible novelty of `pg_qsag_audit` lies not in adding SHA3 to PostgreSQL — `pgcrypto` and OpenSSL already cover that path for the majority case — but in providing a portable, KAT-verified, sandbox-safe, dispatcher-aware, regulator-ready SHA3 + audit-chain layer that works identically across managed and self-hosted Postgres tiers, and in the SCITT Signed Statement emission scheduled for v0.5.

### 1.3 Forcing functions

The timeline pressure from ADR-0031 §3 (amended cadence: research-and-implementation calendar periods rather than week-numbered phases) applies to this artefact specifically because three sibling Q-SAG artefacts depend on `pg_qsag_audit` being live before they can ship:

- `qsag-evidence` (artefact #5) requires `pg_qsag_audit` to provide the database-tier hash-chained event source from which audit packs are derived. `qsag-evidence` cannot ship its EU AI Act Annex IV export views without the underlying chain primitive.
- `qsag-ocsf` (artefact #6) emits OCSF v1.8.0 `ai_operation` events sourced from the audit chain that `pg_qsag_audit` maintains. Without the chain, there is no source.
- `qsag-aibom` (artefact #9) declares CycloneDX 1.6 and SPDX 3.0 manifests with linkage assertions whose hashes must be computed via the same primitives `pg_qsag_audit` defines, for cross-artefact verifiability.

The TLE flavour (`dist/tle/`) is targeted to ship first because it is immediately deployable on the Phase 0 development infrastructure (Supabase managed Postgres) without requiring self-hosted Postgres. The pgrx-native flavour (`dist/pgrx/`) follows for self-hosted deployments. Both are scoped within the May–June 2026 calendar period per ADR-0031 §3.

### 1.4 Build philosophy applied

Per ADR-0031 §1.5 and §2.4, this artefact wraps and ports rather than reimplementing from scratch:

- The SHA3-256 / SHA3-384 implementation in the TLE flavour is a clean-room port informed by the Keccak Code Package (XKCP) reference and cross-validated against `tiny_sha3` (Markku-Juhani O. Saarinen). The pgrx-native flavour wraps a vetted Rust Keccak crate (RustCrypto `sha3`).
- The NIST FIPS 202 Known Answer Test corpus is imported verbatim from the NIST CAVP archive (US Government public domain). It is embedded as a regression suite that runs at extension installation time via `pg_qsag.run_kats()`.
- The dispatcher routes to `pgcrypto.digest()` whenever pgcrypto is present and exposes the requested SHA3 algorithm via OpenSSL EVP. The dispatcher does not reimplement what pgcrypto+OpenSSL already provide; it adds the binding, the fallback, and the logging.
- The RFC 8785 canonical input encoding at v0.1 delegates to the application-tier `qsag-canonical` Python implementation (the second substrate artefact). The v0.2 work item is a self-contained pure-pgrx implementation of RFC 8785 to remove the application-tier dependency for self-hosted deployments.
- The audit-chain hash linkage follows the Crosby-Wallach 2009 USENIX Security history-tree pattern at v0.5; at v0.1 the chain is a simpler hash-chain (each event commits to the prior chain head) sufficient for tamper-evidence without the logarithmic-length consistency proofs that v0.5 will add via the Merkle accumulator.
- The SCITT Signed Statement emitter at v0.5 follows IETF `draft-ietf-scitt-architecture-22` and IETF `draft-ietf-cose-merkle-tree-proofs-18`. It does not redefine SCITT semantics; it emits SCITT-conformant payloads from a Postgres trigger.

The artefact's distinguishing engineering contributions are: (a) the dispatcher's CSWP-39 §3.2.3 negotiation-integrity binding logged into the audit chain, with the negotiated algorithm identifier recorded per-row; (b) the typed-algorithm-tag `dsep_hash` construction that enables forward-compatible algorithm migrations via RFC 9162-style consistency-proof anchor rows; (c) the SQL-surface equivalence between the TLE flavour and the pgrx-native flavour, CI-gated; (d) at v0.5, the SCITT Signed Statement emission directly from a Postgres trigger, which to the best of our knowledge no published Postgres extension implements as of May 2026.

---

## 2. Decision

### 2.1 v0.1 SQL surface

`pg_qsag_audit` v0.1 ships the following SQL surface in the `pg_qsag` schema. Every function below is implemented in both the TLE flavour (`dist/tle/`) and the pgrx-native flavour (`dist/pgrx/`) with byte-identical semantics on conformant inputs. The TLE-vs-pgrx SQL-surface equivalence CI job verifies this on every push.

**Hash primitives:**

- **`pg_qsag.sha3_256(input bytea) returns bytea`** — SHA3-256 per NIST FIPS 202. Returns the 32-byte digest of `input`. Strictly typed: `NULL` input returns `NULL`. Empty `bytea` input returns the canonical SHA3-256 of the empty string (`0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`).
- **`pg_qsag.sha3_384(input bytea) returns bytea`** — SHA3-384 per NIST FIPS 202. Returns the 48-byte digest of `input`. Same `NULL`-handling and empty-string canonical-result semantics as `sha3_256`.

**Dispatcher:**

- **`pg_qsag.digest(input bytea, algo text) returns bytea`** — agility-aware dispatcher. `algo` accepts `'sha3-256'` or `'sha3-384'` at v0.1; future algorithms are added by extending this function rather than by defining new function names. The dispatcher implements the four-state state machine documented in §2.2. The dispatch decision (pgcrypto vs in-extension fallback, the OpenSSL EVP version observed, and the resulting `alg_id`) is appended to `pg_qsag.dispatch_log` for the calling session and, if the calling session is inside a chain-append transaction, also into the audit-chain event row per §2.3.
- **`pg_qsag.dispatcher_state() returns table(algo text, path text, openssl_version text, last_observed timestamptz)`** — diagnostic view of the dispatcher's last-observed state per algorithm. Useful for debugging FIPS-stripped-OpenSSL deployments.

**Domain separation:**

- **`pg_qsag.dsep_hash(domain text, payload bytea, algo text default 'sha3-384') returns bytea`** — domain-separated hashing per `H(len_BE32(domain) || domain || payload)`. The 32-bit big-endian length prefix prevents collision between domain-prefix-of-payload and short-payload-with-long-domain. `domain` is UTF-8 normalised to NFC before length computation. Algorithm choice routes through `pg_qsag.digest()`. **The audit-chain construction in §2.3 invokes `dsep_hash` with a typed algorithm-tag domain string of the form `'q-sag-audit:v1:' || alg_id` to enable forward-compatible algorithm migrations; see §2.3 for the full construction.**
- **`pg_qsag.kmac_hash(key bytea, data bytea, customisation text default '', length_bits int default 384) returns bytea`** — KMAC keyed-mode domain separation per NIST SP 800-185. Returns the `length_bits/8`-byte KMAC output. v0.1 supports `length_bits` ∈ {128, 256, 384, 512}; arbitrary lengths are reserved for v0.5+.

**Canonical input encoding:**

- **`pg_qsag.canon_jsonb(input jsonb) returns bytea`** — RFC 8785 JCS canonical encoding of a `jsonb` value. v0.1 delegates to the application-tier `qsag-canonical` Python implementation via a foreign-data-wrapper or HTTP shim depending on deployment topology (configured via `pg_qsag.canon_endpoint` GUC). The v0.2 work item is a self-contained pure-pgrx implementation that removes the application-tier dependency for self-hosted deployments. Identical semantic inputs always produce identical output bytes regardless of the path taken.

**Audit-chain primitive:**

- **`pg_qsag.append(stream uuid, payload jsonb) returns bigint`** — append an audit event to a hash-chained stream. Returns the sequence number of the appended event. Computes the chain-link per the formula in §2.3, including the typed algorithm-tag domain separator that records the negotiated `alg_id` for the call. Writes a row to `pg_qsag.audit_chain(stream, seq, event_hash, chain_hash, payload, alg_id, dispatcher_decision, created_at)`. The full hash linkage formula is documented in §2.3.
- **`pg_qsag.verify_chain(stream uuid, from_seq bigint default 1, to_seq bigint default null) returns table(ok boolean, first_break_seq bigint, observed_chain_hash bytea, expected_chain_hash bytea)`** — verify the integrity of a hash chain over the specified sequence range (default: full chain). Returns one row. `ok=true, first_break_seq=NULL` for an intact chain. `ok=false, first_break_seq=n` plus the observed and expected chain-hash bytes pointing at the first broken link.
- **`pg_qsag.export_chain(stream uuid, from_seq bigint default 1, to_seq bigint default null) returns table(seq bigint, payload jsonb, event_hash bytea, chain_hash bytea, alg_id text, dispatcher_decision jsonb)`** — export an audit chain in stable canonical order for offline verification or for transmission to an external SCITT Transparency Service (e.g. qsag-anchors). The exported rows are sorted by `seq ascending`.

**Conformance and diagnostics:**

- **`pg_qsag.run_kats() returns table(vector_id text, algo text, expected bytea, observed bytea, ok boolean)`** — run the embedded NIST FIPS 202 Known Answer Test corpus and return the per-vector pass/fail map. Called automatically at extension creation time; loading is refused if any vector fails. Can be re-run at any time to verify post-install corpus integrity (e.g. after a Postgres point-release upgrade). The corpus pinned for v0.1 is documented in §2.7.
- **`pg_qsag.version() returns text`** — extension version string in semantic versioning form (e.g. `'0.1.0'`).
- **`pg_qsag.flavour() returns text`** — returns `'tle'` or `'pgrx'` to identify which build flavour is loaded. Exists primarily for the TLE-vs-pgrx SQL-surface equivalence CI job and for diagnostic purposes.

**Errors:**

- **`pg_qsag_invalid_input`** (SQLSTATE `22023`) — raised when input does not satisfy a declared precondition (e.g. unknown algorithm name passed to `pg_qsag.digest`).
- **`pg_qsag_chain_break`** (SQLSTATE `40001`) — raised when `pg_qsag.append` detects that the current chain head does not match the expected predecessor (concurrent appends, manual database modification). The error includes the stream UUID, the expected predecessor hash, and the observed predecessor hash for forensic analysis.
- **`pg_qsag_kat_failure`** (SQLSTATE `XX000`, internal error class) — raised when `pg_qsag.run_kats()` finds any vector failing. Refusal to load on extension creation surfaces as this error class.

The full SQL surface is documented in `dist/tle/README.md` and `dist/pgrx/README.md` (forthcoming with v0.1) with worked examples for each function.

### 2.2 Dispatcher state machine (v0.1)

`pg_qsag.digest()` is a four-state state machine that decides at every call which implementation to use:

**State 1 — pgcrypto-available, EVP exposes algo**: pgcrypto extension is installed in the database, OpenSSL EVP exposes the requested SHA3 algorithm, and a probe call (executed once per session and cached) succeeded. Dispatch routes to `pgcrypto.digest(input, algo)`. Probe is repeated on session start; cache is keyed on `(algo, openssl_version_string)` so an OpenSSL upgrade triggers re-probing. Resulting `alg_id`: `'pgcrypto-' || algo` (e.g. `'pgcrypto-sha3-384'`).

**State 2 — pgcrypto-available, EVP missing algo**: pgcrypto is installed but the probe failed (FIPS-stripped OpenSSL build, ARM legacy toolchain, etc.). Dispatch routes to the in-extension implementation. The decision is logged with `path='fallback', reason='evp_missing_algo'`. Resulting `alg_id`: `'plpgsql-fallback-' || algo` (e.g. `'plpgsql-fallback-sha3-384'`).

**State 3 — pgcrypto-unavailable**: pgcrypto is not installed in the database (managed-cloud tiers without pgcrypto support, or self-hosted Postgres where the operator chose not to install it). Dispatch routes to the in-extension implementation. The decision is logged with `path='fallback', reason='pgcrypto_unavailable'`. Resulting `alg_id`: `'plpgsql-fallback-' || algo`.

**State 4 — fallback-failed**: the in-extension implementation itself fails (KAT vector mismatch detected during the call, or the implementation raises an unexpected error). Raises `pg_qsag_kat_failure`. The audit chain entry that triggered this state is rolled back per Postgres transaction semantics. No `alg_id` is recorded because no row is committed.

State transitions:

```
       ┌─────────────────────────────────────────────┐
       │                                             │
       ▼                                             │
  ┌────────┐  pgcrypto missing      ┌──────────┐    │
  │ State  │ ──────────────────────▶│  State   │    │
  │   1    │                        │    3     │    │
  │pgcrypto│                        │pgcrypto  │    │
  │+ EVP   │  EVP probe fails       │unavail.  │    │
  │ ok     │ ──────────────────────▶│          │    │
  └────────┘                        └──────────┘    │
       │                                  │          │
       │                                  │          │
       ▼ (calls pgcrypto.digest)          ▼ (calls in-extension impl)
   pgcrypto                          ┌──────────┐    │
   returns ok                        │  State 2 │    │
       │                             │pgcrypto  │    │
       ▼                             │+ EVP     │    │
   return digest                     │ missing  │    │
                                     └──────────┘    │
                                          │          │
                                          ▼          │
                                    in-extension     │
                                    impl executes    │
                                          │          │
                                          ▼          │
                              ┌─────────────────┐    │
                              │  KAT failure?   │    │
                              └─────────────────┘    │
                                  │            │     │
                              no  │            │ yes │
                                  ▼            ▼     │
                              return digest  State 4 ┘
                                             raises
                                             pg_qsag_kat_failure
```

The dispatch decision is recorded in `pg_qsag.dispatch_log` (per-session) and, for calls inside a chain-append transaction, is also embedded in the chain event's `alg_id` and `dispatcher_decision` columns per §2.3. This is the NIST CSWP 39 §3.2.3 negotiation-integrity binding: the choice of implementation is part of the auditable trail, not a hidden detail.

**Per-row algorithm-identifier logging.** Beyond logging the dispatch decision once per session in `pg_qsag.dispatch_log`, the dispatcher writes the negotiated `alg_id` value into every audit-chain row produced by `pg_qsag.append`. NIST CSWP 39 §3.2.3 (final 19 December 2025) requires that "implementations must provide a way to determine when deployments have shifted from old to new algorithms" — single-point negotiation logging at session start is insufficient because it does not establish the algorithm provenance of any specific subsequent event. Per-row `alg_id` logging is the corresponding load-bearing implementation pattern.

**Algorithm policy via GUC.** The preferred algorithm for chain operations is configurable via the `pg_qsag_audit.preferred_alg` GUC (default `'sha3-384'`, which is also the v0.1-only supported value). Policy/mechanism separation is per CSWP-39's recommended pattern: cryptographic policy lives in configuration rather than hardcoded in source. Future v0.5+ versions will accept additional values (e.g. `'sha3-512'`, `'kmac-256'`); v0.1 raises `pg_qsag_invalid_input` if any value other than `'sha3-384'` is set.

**No memoisation of digest outputs.** The dispatcher does not memoise digest *outputs* (that would be a security risk against secret-dependent inputs even though we explicitly disclaim side-channel resistance — better to never cache hash outputs by policy). It only memoises the *probe result* per session per `(algo, openssl_version)`.

### 2.3 Audit-chain hash linkage (v0.1)

The v0.1 chain is a simple hash-chain. Each event commits to the prior chain head plus the canonical encoding of its own payload plus a typed algorithm-tag domain-separator hash that prevents domain-shifting attacks and enables forward-compatible algorithm migration.

**Genesis:**
```
H_0 = SHA3-384(UTF8('pg_qsag.stream:' || stream::text))
```

The stream UUID is bound into the genesis hash so that two streams with the same first event do not produce identical chain heads.

**Per-event computation (event n, n ≥ 1):**
```
canonical_payload_n = pg_qsag.canon_jsonb(payload_n)
domain_separator_n = pg_qsag.dsep_hash('q-sag-audit:v1:' || alg_id_n, canonical_payload_n, 'sha3-384')
H_event_n = SHA3-384(canonical_payload_n || domain_separator_n)
H_n = SHA3-384(H_{n-1} || H_event_n)
```

where `alg_id_n` is the negotiated algorithm identifier returned by the dispatcher for event `n` (per §2.2; one of `'pgcrypto-sha3-384'` or `'plpgsql-fallback-sha3-384'` at v0.1).

The chain hash `H_n` is what `pg_qsag.verify_chain` recomputes from the row's `event_hash` (which is `H_event_n`), the prior row's `chain_hash` (which is `H_{n-1}`), and the row's recorded `alg_id` (which feeds the typed algorithm-tag reconstruction).

**Why SHA3-384 and not SHA3-256:**
SHA3-384 provides 192-bit collision resistance classically and ~128-bit collision resistance against quantum adversaries via Brassard-Høyer-Tapp generalisation of Grover. CNSA 2.0 mandates SHA-384 (FIPS 180-4) for NSS use; SHA3-384 is permitted inside specific algorithms and inside hardware components. We choose SHA3-384 over SHA3-256 because the post-quantum collision-resistance margin matters for an audit-chain primitive whose security is needed beyond 2030 (the conservative quantum-cryptanalysis horizon). The cost is 16 extra bytes per event; we accept this trade-off.

**Why canonical input encoding before hashing:**
Without canonicalisation, two semantically-identical events with different JSON serialisations (different key ordering, different whitespace, different number formatting) produce different hashes. This breaks cross-platform verification and makes the chain unverifiable when payloads originate from heterogeneous producers. RFC 8785 JCS gives us byte-stable canonical encoding. v0.1 delegates this to `qsag-canonical` (Python application tier); v0.2 brings it in-extension via a pgrx port.

**Why the domain separator:**
Without `dsep_hash`, an attacker who can choose payloads might construct two different payloads whose `canonical_payload || something` produces equal hashes (a length-extension-style attack on raw-concatenation hash inputs). The domain separator binds the hash to a specific domain string and length-prefixes the domain to prevent collision between short-domain-long-payload and long-domain-short-payload constructions. The domain separator approach follows NIST SP 800-185 KMAC structure.

**Why the typed algorithm-tag domain separator (`'q-sag-audit:v1:' || alg_id`):**
A static domain string (e.g. just `'pg_qsag.event'`) is sufficient to prevent classical length-extension attacks but is inadequate for cryptographic algorithm migrations. If the v1 chain uses SHA3-384 and a future v2 chain uses SHA3-512 or KMAC256, the two chains' event hashes are not cryptographically distinguishable from the perspective of the `dsep_hash` construction unless the algorithm identity is bound into the domain separator. Without this binding, a verifier seeing a "v2 event" cannot prove it was not produced by v1 logic, and a chain that migrated from v1 to v2 cannot offer an RFC 9162-style consistency proof linking the two log states.

The typed algorithm-tag construction (`'q-sag-audit:v1:' || alg_id`) explicitly binds three properties into the domain separator: the substrate identity (`q-sag-audit`, distinguishing this chain from any other application using the same primitives), the chain-version (`v1`, which a future v2 chain would replace with `v2`), and the negotiated algorithm identifier (`alg_id`, the dispatcher output recorded per row). A future v2 chain can then include a *migration anchor row* whose previous-chain-hash field is the v1 `H_n`, whose `alg_id` field declares the new algorithm, and whose `dsep_hash` declares the v2 domain string. This is structurally identical to RFC 9162's "consistency proof" between two log states and aligns the substrate with the SCITT/COSE Receipts ecosystem.

This change to `dsep_hash` semantics is *forward-compatible* for v0.5+ algorithm migrations and *non-breaking* for v0.1 because the chain has not yet been deployed. The construction is locked here so that any chain ever produced by `pg_qsag_audit` carries its algorithm provenance from genesis.

**`pg_qsag.audit_chain` table schema:**
```sql
CREATE TABLE pg_qsag.audit_chain (
    stream uuid NOT NULL,
    seq bigint NOT NULL,
    event_hash bytea NOT NULL,            -- H_event_n (48 bytes for SHA3-384)
    chain_hash bytea NOT NULL,            -- H_n (48 bytes)
    payload jsonb NOT NULL,
    alg_id text NOT NULL,                 -- e.g. 'pgcrypto-sha3-384' or 'plpgsql-fallback-sha3-384'
    dispatcher_decision jsonb NOT NULL,   -- {path, openssl_version, evp_probe, reason}
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (stream, seq)
);
```

The `alg_id` column carries the negotiated algorithm identifier per row. It feeds directly into the typed-algorithm-tag `dsep_hash` reconstruction during `pg_qsag.verify_chain` and into the v0.5 SCITT Signed Statement emitter for algorithm-provenance assertion. The `dispatcher_decision` column carries the richer JSON object (path, OpenSSL version, EVP probe result, fallback reason) for forensic analysis. Together they form the CSWP-39 §3.2.3 negotiation-integrity record: verifiers reading any row know which implementation produced the hash, which OpenSSL version was observed, and which `alg_id` was canonically committed into the chain.

**VACUUM / PITR / logical-replication stability:**
The chain hashes are derived from the row contents (`payload`, `event_hash`, `chain_hash`, `alg_id`), not from physical row identifiers (`ctid`, `xmin`, `xmax`). VACUUM that rewrites the physical row layout does not invalidate the chain. Point-in-time recovery to a consistent transactional state preserves the chain. Logical replication that ships the row contents preserves the chain. Physical replication via streaming WAL preserves the chain trivially (the chain is data, not derived state).

The one operational caveat is **reordering**: if two transactions append to the same stream concurrently, the `seq` allocation must be serialised. v0.1 enforces this via a SERIALIZABLE-isolated transaction around the `pg_qsag.append` call internally. Concurrent append attempts that lose the serialisation race raise `pg_qsag_chain_break` (SQLSTATE `40001`, the standard serialisation-failure class) so that callers retry with the corrected chain head.

### 2.4 Threat model (v0.1)

Documented in detail in [THREAT_MODEL.md](../../THREAT_MODEL.md) (forthcoming with v0.1) and [SECURITY.md](../../SECURITY.md) (committed at `c777767454e9aa9af6a8b1ab4b04c5fbaffc3309`). Summary of v0.1 commitments:

**Defended against:**

- **SHA3 implementation divergence from FIPS 202.** The full NIST CAVP KAT corpus runs at install time and gates loading. CI runs the same corpus against both build flavours on every push. The corpus is documented in §2.7.
- **Dispatcher routing inconsistent with the logged decision.** The CSWP 39 §3.2.3 binding ensures that if the dispatcher claims to have used pgcrypto, the digest was actually computed by pgcrypto, and the negotiated `alg_id` is recorded on every audit row. Test suite includes positive and negative cases for both the pgcrypto-available and pgcrypto-unavailable paths.
- **Audit-chain tampering by a non-superuser writer.** The chain-hash recomputation in `pg_qsag.verify_chain` detects any modification to `payload`, `event_hash`, `chain_hash`, or `alg_id` for any sequence. Modifications by a writer with `INSERT/UPDATE/DELETE` privilege on `pg_qsag.audit_chain` (where the row is owned by the extension) are detected.
- **Length-extension and domain-shifting attacks** against the chain hashing. The typed algorithm-tag `dsep_hash` domain separator and the length-prefix construction prevent these classes of attack.
- **Algorithm-substitution / downgrade attacks** against future chain migrations. The typed algorithm-tag `dsep_hash` records the negotiated `alg_id` per row; a verifier reading a chain that has migrated from v1 to v2 can reconstruct the migration anchor row and prove the chain identity bridge is correctly formed.
- **Concurrent-append races.** SERIALIZABLE isolation around `pg_qsag.append` prevents two parallel transactions from producing inconsistent chain heads.

**Not defended against (acknowledged limits):**

- **Side-channel attacks** against the hashing primitives. The TLE flavour runs in interpreted plpgsql; the pgrx-native flavour runs in Rust without constant-time bytecode emission. Constant-time guarantees are not achievable in either. Do not feed secret-dependent inputs (session keys, unblinded private-key material, password hashes) to `pg_qsag_audit`'s hashing primitives. This is documented in SECURITY.md and the README.
- **Audit-chain rewriting by a Postgres superuser** or someone with filesystem write access to the database server. The chain is **tamper-evident, not tamper-proof**: `pg_qsag.verify_chain` will report the first break, but cannot prevent a sufficiently-privileged attacker from rewriting history. Tamper-proofness requires external anchoring (qsag-anchors handles this) or append-only storage outside Postgres (out of scope for this extension).
- **Confidentiality of inputs.** `pg_qsag_audit` provides integrity (hash-chained tamper-evidence) and authenticity-of-origin (when combined with qsag-anchors), not confidentiality. Inputs are by hypothesis non-secret audit-event content; the database operator is assumed to have appropriate access controls on the underlying tables independent of this extension.
- **`pg_tle` sandbox-escape exposing inputs.** We rely on `pg_tle`'s trusted-language sandbox for installability on managed-cloud tiers, not for confidentiality. A sandbox-escape that exposes the inputs to our hashing primitives is not, by itself, a vulnerability against `pg_qsag_audit`'s claimed security properties — those inputs are by hypothesis non-secret audit-event content. Sandbox-escape against the framework itself should be reported to AWS via `[email protected]` and to us; we coordinate.
- **Theoretical SHA3 / Keccak cryptanalytic attacks**, theoretical attacks on RFC 8785, theoretical attacks on SCITT or COSE Receipts. Out of scope for this artefact; report to NIST or the relevant IETF working group.

**Operational-environment assumptions:**

- The Postgres installation is reasonably patched and is operated by an honest-but-curious or honest operator. We do not defend against an actively malicious database administrator who has already decided to falsify the chain.
- The clock that produces `created_at` timestamps is approximately accurate. Adversarial clock manipulation is a concern for the chain's temporal claims, not for its hash integrity (which is clock-independent).
- Network or storage tampering between Postgres and the disk is out of scope; that is the storage layer's responsibility, not this extension's.

### 2.5 Integration points

- **With `qsag-canonical`** (artefact #2): `pg_qsag.canon_jsonb` at v0.1 delegates to `qsag-canonical`'s Python implementation via a configured endpoint. v0.2 work brings canonicalisation in-extension via a pgrx port; the API surface and output bytes are unchanged.
- **With `qsag-anchors`** (artefact #1): at v0.5, `pg_qsag.export_chain` results plus the SCITT Signed Statement emitter feed into `qsag-anchors` for federated transparency-service anchoring. Cross-artefact verification is end-to-end: a verifier reading a SCITT receipt from `qsag-anchors` can trace the entry back to a specific `(stream, seq, alg_id)` in `pg_qsag.audit_chain` and verify the chain-hash linkage from genesis with the algorithm provenance preserved.
- **With `qsag-evidence`** (artefact #5, forthcoming): `qsag-evidence`'s EU AI Act Annex IV export views consume `pg_qsag.export_chain` results, packaging them with the canonical JSON of each event and the cryptographic proofs into regulator-facing audit packs.
- **With `qsag-ocsf`** (artefact #6, forthcoming): `qsag-ocsf` emits OCSF v1.8.0 `ai_operation` events sourced directly from `pg_qsag.audit_chain` triggers.
- **With `qsag-aibom`** (artefact #9, forthcoming): linkage assertions in CycloneDX 1.6 and SPDX 3.0 manifests use `pg_qsag.dsep_hash` as the canonical hash function for cross-artefact verifiability.
- **With Q-SAG main** (private neoxyber-qsag repository): once v0.1 ships, Q-SAG main migrates database-tier audit logging from its current per-table approach to `pg_qsag.append` calls. The migration is gradual and transactional.
- **With Microsoft AGT and Asqav SDK**: indirect — these consume audit events via `qsag-anchors` and `qsag-evidence`, not directly from `pg_qsag_audit`.

### 2.6 Out of scope for v0.1

The following are explicitly out of scope for v0.1 and reserved for later versions:

- **Merkle-tree accumulator over the audit chain.** Reserved for v0.5. v0.1's hash-chain provides tamper-evidence; v0.5's Merkle accumulator adds logarithmic-length consistency proofs and inclusion proofs, following the Crosby-Wallach 2009 USENIX history-tree pattern (or the RFC 9162 generalisation thereof, which is the construction used by both Sigstore Rekor v2 and SCITT/COSE Receipts).
- **COSE Receipts inclusion-proof emitter.** Reserved for v0.5. Follows IETF `draft-ietf-cose-merkle-tree-proofs-18`. Emits inclusion proofs for individual chain events.
- **SCITT Signed Statement emitter from a Postgres trigger.** Reserved for v0.5. Follows IETF `draft-ietf-scitt-architecture-22`. To the best of our knowledge no published Postgres extension emits SCITT-conformant Signed Statements directly from a trigger as of May 2026; this is the artefact's headline novelty for v0.5.
- **Self-contained pgrx-native canonicalisation.** Reserved for v0.2. v0.1's `canon_jsonb` delegates to `qsag-canonical` Python. v0.2 brings RFC 8785 in-extension to remove the application-tier dependency for self-hosted deployments.
- **EU AI Act Article 12 export views.** Reserved for v0.5. Maps per-event records to Article 12(3) fields with hash-chain proofs of completeness.
- **CRA Article 14 ENISA-Single-Reporting-Platform connector.** Reserved for v0.5. Provides ENISA-Single-Reporting-Platform-shaped exports of vulnerability-related audit events.
- **Native ML-DSA / SLH-DSA / Falcon signature emission.** Reserved for v0.5+. Wraps liboqs and/or RustCrypto. Not part of v0.1's hash-and-chain-only surface.
- **Constant-time hashing implementation.** Reserved for v1.0+, contingent on side-channel-resistant primitives becoming available in plpgsql or pgrx without prohibitive performance cost. v0.1's commitment is documented non-resistance, not future resistance.
- **Hardware-Security-Module (HSM) integration** for key custody. Reserved for v0.5+ subject to demand and to PKCS#11 support landing in pgrx.
- **PostgreSQL major versions older than 14.** v0.1 supports PostgreSQL 14, 15, 16, 17, 18. Versions older than 14 are reserved for never; the engineering cost of supporting deprecated versions is not justified for an audit-chain primitive whose security horizon is 2027+.
- **Permissive-mode-by-default chain operations.** Reserved for never. Strict input validation is a programme-wide commitment.

### 2.7 KAT corpus and conformance pinning (v0.1)

The KAT corpus that gates extension loading (per `pg_qsag.run_kats()` in §2.1) is pinned at v0.1 to the following layered set of vectors. Failure of any vector raises `pg_qsag_kat_failure` (SQLSTATE `XX000`) and refuses extension load. The corpus is checked at install time and CI-pinned to fire on every push for both flavours.

**Layer 1 — NIST FIPS 202 example file (mandatory):**

The full NIST FIPS 202 example file vectors for SHA3-256 and SHA3-384, imported verbatim from the NIST CAVP archive (US Government public domain) and embedded in `docs/conformance/test-vectors/`. At minimum this includes:

- The empty-string vector (catches null-input handling and the canonical empty-string SHA3-256 / SHA3-384 outputs).
- The canonical "abc" vector (catches one-block-no-padding bugs and lane-indexing on small inputs).
- The 448-bit vector (catches single-block-with-padding boundary handling).
- The 896-bit vector (catches two-block padding boundary handling).
- The Monte-Carlo vector at 1,000,000 × 'a' (catches MCT seed and iteration logic; in interpreted-language ports, this vector commonly catches bugs that pass single-input KATs).

**Layer 2 — Keccak team long-message vector (mandatory):**

The Keccak team's published long-message extreme vector exercising the rate boundary across multi-megabyte input. The full ~1 GB vector is the canonical reference; at CI time this is sampled at a minimum of 10 MB streamed through the implementation. This vector class historically catches lane-indexing and pad10*1 transcription errors that smaller inputs miss because the per-block state-permutation logic is exercised over many blocks.

**Layer 3 — Rate-boundary vector at exactly 832 bits for SHA3-384 (mandatory):**

A vector whose message length is exactly equal to the SHA3-384 rate (832 bits / 104 bytes). At this length, the FIPS 202 `pad10*1` rule produces a one-extra-block padding (the trailing `0x06` domain-separator byte followed by `0x00` zero-bytes followed by `0x80` final byte must occupy the entirety of the next block). A SHA3-384 implementation that gets the rate-boundary off-by-one — for example, by treating message-length-equals-rate as a no-extra-block case — produces a divergent digest at exactly this length and only this length, which is otherwise undetectable from generic vectors. This vector is independently authored from the FIPS 202 example file; the expected output is computed against `tiny_sha3` and cross-validated against `pgcrypto.digest()` on a known-good OpenSSL ≥ 3.0 build.

**Layer 4 — Algorithm-tag round-trip and migration-anchor synthesis (mandatory):**

CI tests that the typed algorithm-tag `dsep_hash` construction (per §2.3) round-trips correctly: a chain produced with `alg_id='pgcrypto-sha3-384'` and a chain produced with `alg_id='plpgsql-fallback-sha3-384'` over the same payloads must produce *different* `event_hash` values (because the typed algorithm-tag domain string differs) and the chain-verification logic must correctly distinguish them. Additionally, a synthetic v1→v2 migration anchor row is constructed in CI (with the v1 `H_n` as the previous-chain-hash and a notional `alg_id='pgcrypto-sha3-512'` for v2) and the migration-anchor reconstruction is verified to produce the correct cryptographic bridge.

**Discovery and regression discipline:**

Every fixed SHA3-divergence, dispatcher-binding, or audit-chain-tampering bug must be committed to the public conformance test corpus as a regression test, citing the discovery and the affected versions, per the SECURITY.md hardening commitments. New regression vectors are appended to the corpus; the v0.1 layered set above is the floor, not the ceiling.

**Bug classes the layered KAT corpus is designed to catch (pure-plpgsql fallback specifically):**

1. ρ-offset matrix transcription errors (the 5×5 rotation-offset matrix in Keccak-f[1600] is the most commonly mistyped data in interpreted-language ports).
2. ι round-constant typos (any of the 24 round constants ι[0..23]).
3. Lane indexing convention errors (Keccak uses `A[x,y]` little-endian; column-major versus row-major mistakes are common in plpgsql/SQL).
4. Padding rule errors — `pad10*1` with the FIPS 202 domain-separation byte **0x06** for SHA-3 (NOT `0x1F` for SHAKE, NOT `0x01` for raw Keccak / Ethereum). A port that uses `0x01` will silently produce *Ethereum-style* hashes that pass internal self-consistency tests but fail FIPS 202 KATs. The empty-string and "abc" vectors in Layer 1 catch this class of bug immediately.
5. Rate boundary off-by-one when message length equals exactly the rate (caught by Layer 3 specifically; not always caught by Layer 1 and 2 vectors).

The full bug-class checklist for the pure-plpgsql fallback is documented in `docs/research/2026-05-10-v01-landscape.md` (committed at `1d0d0836dc55ac3efaf204e4ba68667ac77a8e8d`).

---

## 3. Consequences

### 3.1 What this ADR makes true

- The v0.1 SQL surface is locked. Adding to or changing the surface requires a new ADR superseding the relevant clause of this one.
- The dispatcher state machine is locked at four states with the transitions and logging behaviour documented in §2.2, including the per-row `alg_id` logging and the `pg_qsag_audit.preferred_alg` GUC introduced in the 2026-05-10 amendment.
- The audit-chain hash linkage formula is locked: `H_n = SHA3-384(H_{n-1} || H_event_n)` where `H_event_n = SHA3-384(canonical_payload || dsep_hash('q-sag-audit:v1:' || alg_id, canonical_payload, 'sha3-384'))`. Any change to this formula breaks every existing chain and requires a new ADR plus a documented migration path. The typed algorithm-tag construction enables forward-compatible v0.5+ migrations via RFC 9162-style consistency-proof anchor rows, without requiring a re-architecture.
- The TLE flavour and the pgrx-native flavour share one canonical SQL surface. CI verifies this on every push via the SQL-surface equivalence job.
- Audit chains are **tamper-evident, not tamper-proof**. This is a documented commitment, not an aspiration.
- The dispatcher binding is **forensic, not preventative**. The CSWP 39 §3.2.3 record documents the dispatch decision and the negotiated `alg_id`; it does not prevent forcing.
- v0.1 has a runtime dependency on `qsag-canonical` for `canon_jsonb` operation. Self-hosted deployments must run a `qsag-canonical` endpoint reachable from the database. v0.2 removes this dependency.
- The KAT corpus pinning of §2.7 is a hard precondition for v0.1 release. Layer 1 (NIST FIPS 202 example file), Layer 2 (Keccak team long-message vector sampled at minimum 10 MB), Layer 3 (rate-boundary at exactly 832 bits for SHA3-384), and Layer 4 (algorithm-tag round-trip and migration-anchor synthesis) all pass on both flavours, on every Postgres version in the CI matrix, on every push.

### 3.2 What this ADR makes required

- Every release of `pg_qsag_audit` from v0.1 onward must include the layered KAT corpus per §2.7, all passing, with `pg_qsag.run_kats()` gating extension loading. The corpus floor is Layer 1 + Layer 2 + Layer 3 + Layer 4; future releases may extend with regression vectors but may not regress below this floor.
- The `alg_id` column is mandatory in `pg_qsag.audit_chain`. Reading historical chains produced before this amendment (none exist as of the 2026-05-10 amendment date because no v0.1 implementation has shipped) is supported via the migration anchor row pattern documented in §2.3; however, any chain produced by any v0.1 implementation must include `alg_id` from genesis.
- The typed algorithm-tag `dsep_hash` construction (`'q-sag-audit:v1:' || alg_id` as the domain string) is mandatory. Any implementation that uses a static domain string fails the Layer 4 KAT and is non-conforming.
- Every release must publish a CycloneDX 1.6 SBOM and SLSA Level 3 build provenance.
- Every release must publish a JWS-signed `META.json` per PGXN v2 RFC-5 once the SDK supports it.
- THREAT_MODEL.md, STANDARDS.md, `dist/tle/README.md`, `dist/pgrx/README.md`, and the conformance test corpus in `docs/conformance/test-vectors/` must be present and accurate at v0.1 ship time.
- The TLE-vs-pgrx SQL-surface equivalence CI job must pass on every PR. Intentional divergence requires a documented allowlist update and an ADR amendment.
- The CI matrix must cover PostgreSQL 14, 15, 16, 17, 18 × OpenSSL 1.1.1, 3.0, 3.2, 3.5 × x86_64, aarch64. Failure to cover this matrix on a release blocks the release.
- Every fixed SHA3-divergence, dispatcher-binding, or audit-chain-tampering bug must be committed to the public conformance test corpus as a regression test, citing the discovery and the affected versions, per the SECURITY.md hardening commitments.
- Every GitHub Actions workflow used in the build pipeline must pin third-party Actions to commit SHAs (not tags), per the post-tj-actions/changed-files (CVE-2025-30066, March 2025) hardening lesson documented in the research synthesis.

### 3.3 What this ADR makes false (or removes)

- Any prior assumption that `pg_qsag_audit` would ship as two separate repositories (`pg-qsag-audit-tle` and `pg-qsag-audit`). The amended ADR-0031 §2.5 (commit `5541d7b`) consolidates them into one canonical repository with the dual-flavour `dist/tle/` and `dist/pgrx/` structure. This ADR-0001 inherits and reinforces that consolidation.
- Any prior assumption that the dispatcher would silently fall back without logging. The CSWP 39 §3.2.3 binding makes the dispatch decision part of the auditable trail, with per-row `alg_id` recording per the 2026-05-10 amendment.
- Any prior assumption that the chain-hash domain separator could be a static string. The typed algorithm-tag construction is mandatory per §2.3 and enforced by the Layer 4 KAT in §2.7.
- Any prior assumption that v0.1 would include the SCITT Signed Statement emitter. That is v0.5 work. v0.1 ships the audit-chain primitive that v0.5 builds upon.
- Any prior assumption that v0.1 would offer constant-time guarantees. It does not. Side-channel non-resistance is a documented commitment.
- Any prior assumption of support for PostgreSQL versions older than 14. They are not supported and not planned.

### 3.4 Risks documented

- **Risk of subtle divergence between the TLE flavour and the pgrx-native flavour.** Mitigation: the SQL-surface equivalence CI job runs the same SQL test scenarios against both flavours and fails on divergence. Any divergence found post-release is a P0 incident.
- **Risk of dispatcher state-machine incorrectness causing silent wrong-implementation routing.** Mitigation: positive and negative test cases for all four states. Independent fuzzing of the probe logic on adversarial OpenSSL configurations. Per-row `alg_id` recording per the 2026-05-10 amendment makes wrong-routing detectable post-hoc by chain verification.
- **Risk of audit-chain hash-formula evolution breaking existing chains.** Mitigation: the v0.1 formula (with the typed algorithm-tag domain separator) is committed and will not change without a major-version bump and a documented migration path. The typed-tag construction enables RFC 9162-style consistency-proof anchor rows so v0.5+ algorithm migrations do not invalidate existing v1 chains.
- **Risk of `qsag-canonical` dependency at v0.1 making self-hosted deployments operationally complex.** Mitigation: documented operator playbook for running `qsag-canonical` as a sidecar. v0.2 removes the dependency entirely.
- **Risk of `pg_tle` framework changes breaking the TLE flavour.** Mitigation: pinned `pg_tle` version (≥ 1.5.0) in the TLE flavour's manifest. Compatibility testing across `pg_tle` versions on every CI run.
- **Risk of NIST CAVP KAT corpus drift if NIST updates the published vectors.** Mitigation: the embedded corpus is versioned; updates require a release and an ADR-0001 amendment recording the corpus version transition. The March 2025 NIST announcement of the FIPS 202 update is editorial only (no algorithmic change); KAT vectors are expected to be invariant.
- **Risk that the SCITT specification advances in a way that breaks the v0.5 emitter.** Mitigation: track `draft-ietf-scitt-architecture` updates; defer v0.5 ship until SCITT reaches RFC status if pre-RFC drafts continue to break compatibility. This is acceptable; the v0.1 surface is independently useful.
- **Risk of regulatory framework changes (EU AI Act, CRA) altering Article 12 / Article 14 export requirements before v0.5 ships.** Mitigation: the v0.5 export views and CRA cascade connector are design-tracked separately and will be updated as regulatory guidance is published. The v0.1 surface is regulatory-framework-independent. Specifically, the EU Digital Omnibus on AI proposed deferral of Article 12 to 2 December 2027 (status: in trilogue as of May 2026) does not change v0.1 architecture; v0.1 ships against the original 2 August 2026 deadline as a defensive default.

---

## 4. Compliance and conformance

This artefact aligns with:

- **NIST FIPS 202** — SHA-3 Standard. SHA3-256 and SHA3-384 are the v0.1 primary primitives; SHA3-384 is the chain-hash algorithm. The March 2025 NIST announcement of an editorial update to FIPS 202 (no algorithmic change) is monitored; any change to the KAT corpus would trigger an ADR amendment.
- **NIST SP 800-185** — KMAC, TupleHash, ParallelHash. KMAC keyed-mode used in `pg_qsag.kmac_hash`; the `dsep_hash` construction follows the SP 800-185 length-prefix domain-separation pattern with the typed algorithm-tag extension introduced in the 2026-05-10 amendment.
- **NIST CSWP 39** — §3.2.3 negotiation-integrity binding (final 19 December 2025). The dispatcher implements §3.2.3's three substantive requirements: integrity-protected algorithm negotiation, integrity-protecting algorithm at-least-as-strong-as the algorithms it negotiates, and per-row determinable algorithm provenance.
- **NIST CNSA 2.0** — SHA-384 retained for NSS use; SHA3-384 permitted inside specific algorithms and inside hardware components. Our chain-hash choice of SHA3-384 satisfies the CNSA 2.0 internal-use carve-out and the post-quantum collision-resistance requirement (192-bit classical, ~128-bit BHT-quantum).
- **IETF RFC 8785** — JSON Canonicalisation Scheme (JCS). v0.1 delegates to `qsag-canonical`; v0.2 brings in-extension.
- **IETF RFC 8259** — JSON Data Interchange Format. The input grammar for `canon_jsonb`.
- **IETF RFC 9162** — Certificate Transparency v2.0. The v0.5 Merkle accumulator and consistency-proof construction generalises Crosby-Wallach 2009 to the RFC 9162 pattern, aligning the substrate with the SCITT/COSE Receipts and Sigstore Rekor v2 ecosystem.
- **IETF SCITT** — `draft-ietf-scitt-architecture-22`. v0.5 Signed Statement emitter follows this draft.
- **IETF COSE Receipts** — `draft-ietf-cose-merkle-tree-proofs-18`. v0.5 inclusion-proof format follows this draft.
- **PGXN v2** — RFC-2 (binary distribution), RFC-3 (Meta Spec v2 with `contents` taxonomy), RFC-5 (release certification with JWS-signed META.json).
- **EU Regulation 2024/1689** (AI Act) — Article 12 (logging), Article 26 (deployer obligations). v0.5 export views align with Article 12(3) field requirements. v0.1 architecture is unchanged regardless of the Digital Omnibus on AI deferral outcome.
- **EU Regulation 2024/2847** (CRA) — Article 14 (vulnerability reporting cascade). v0.5 connector emits ENISA-Single-Reporting-Platform-shaped exports.
- **Apache License 2.0** — the artefact's licence.
- **Developer Certificate of Origin (DCO)** — every commit includes a `Signed-off-by:` trailer per CONTRIBUTING.md.

Detailed clause-level mappings will live in [STANDARDS.md](../../STANDARDS.md) (forthcoming with v0.1).

---

## 5. References

**Master programme ADRs:**
- ADR-0031 — Open-Source Cryptographic and Audit Substrate Programme (private neoxyber-qsag repository, amended commit `5541d7b32e16b5a1da8b25e17a1c989cff049dde`, 9 May 2026).

**Sibling artefact ADRs:**
- qsag-anchors ADR-0001-design — federated SCITT TS primitives (https://github.com/Neoxyber/qsag-anchors/blob/main/docs/decisions/ADR-0001-design.md).
- qsag-canonical ADR-0001-design — RFC 8785 JCS implementation in Python (https://github.com/Neoxyber/qsag-canonical/blob/main/docs/decisions/ADR-0001-design.md).

**Standards:**
- NIST FIPS 202 — SHA-3 Standard.
- NIST SP 800-185 — KMAC, TupleHash, ParallelHash.
- NIST SP 800-232 — Ascon (finalised 13 August 2025; informative reference for future v0.5+ algorithm additions).
- NIST CSWP 39 — §3.2.3 negotiation-integrity binding (final 19 December 2025).
- NIST CNSA 2.0 — Commercial National Security Algorithm Suite v2.
- IETF RFC 8785 — JSON Canonicalisation Scheme (JCS).
- IETF RFC 8259 — JSON Data Interchange Format.
- IETF RFC 7515 — JSON Web Signature (JWS).
- IETF RFC 9162 — Certificate Transparency v2.0 (informative reference for v0.5 Merkle accumulator and consistency-proof construction).
- IETF draft-ietf-scitt-architecture-22 — SCITT.
- IETF draft-ietf-cose-merkle-tree-proofs-18 — COSE Receipts.
- PGXN v2 RFC-2, RFC-3, RFC-5 — David Wheeler (Tembo) and the PGXN Steering Committee.
- EU Regulation 2024/1689 — Artificial Intelligence Act.
- EU Regulation 2024/2847 — Cyber Resilience Act.

**Academic prior art:**
- Madhwal, Yash; Yanovich, Yury; Anokhin, Ilya. "Blockchain Extension for PostgreSQL Data Storage." In Proceedings of the 3rd Blockchain and Internet of Things Conference (BIOTC 2021), pp. 24-30. ACM, July 2021. DOI: 10.1145/3475992.3476001.
- Crosby, Scott A. and Wallach, Dan S. "Efficient Data Structures for Tamper-Evident Logging." In Proceedings of the 18th USENIX Security Symposium, pp. 317-334. USENIX Association, August 2009.
- Brassard, Gilles; Høyer, Peter; Tapp, Alain. "Quantum Algorithm for the Collision Problem." arXiv:quant-ph/9705002, 1997.
- Dowling, Benjamin; Günther, Felix; Herath, Udyani; Stebila, Douglas. "Secure Logging Schemes and Certificate Transparency." ESORICS 2016, ePrint 2016/452.

**Software references:**
- Keccak Code Package (XKCP) — Bertoni, Daemen, Peeters, Van Assche, Van Keer — https://github.com/XKCP/XKCP.
- tiny_sha3 — Markku-Juhani O. Saarinen — https://github.com/mjosaarinen/tiny_sha3.
- AWS pg_tle — https://github.com/aws/pg_tle.
- pgrx — https://github.com/pgcentralfoundation/pgrx.
- PostgreSQL pgcrypto contrib module — https://github.com/postgres/postgres/tree/master/contrib/pgcrypto.
- RustCrypto sha3 crate — https://github.com/RustCrypto/hashes/tree/master/sha3.

**Project-internal references:**
- pg_qsag_audit README — https://github.com/Neoxyber/pg_qsag_audit/blob/main/README.md (committed at `a6b17482ef617809a238580d6015c29e85457f9a`).
- pg_qsag_audit SECURITY.md — https://github.com/Neoxyber/pg_qsag_audit/blob/main/SECURITY.md (committed at `c777767454e9aa9af6a8b1ab4b04c5fbaffc3309`).
- pg_qsag_audit CONTRIBUTING.md — https://github.com/Neoxyber/pg_qsag_audit/blob/main/CONTRIBUTING.md (committed at `c9251d1cc1f3e55ffd8780ac1e087ca914d82265`).
- pg_qsag_audit NOTICE — https://github.com/Neoxyber/pg_qsag_audit/blob/main/NOTICE (committed at `add7ca7214b6833fdc3cf4e2f0876c34d5682bc7`).
- **pg_qsag_audit landscape research synthesis (source-of-authority for the 2026-05-10 amendment of this ADR) — `docs/research/2026-05-10-v01-landscape.md` (committed at `1d0d0836dc55ac3efaf204e4ba68667ac77a8e8d`).**

---

## 6. Approval

Approved by the sole director of AIXYBER TECH LTD, Muhammad Zaid Naeem, on 9 May 2026. This ADR is committed GPG-signed (Ed25519 key fingerprint `A65AF5B7F02C9EB5B98023D70DB861BBF30F0D7B`, valid until April 2028) and DCO-signed alongside the v0.0.0 scaffolding for `pg_qsag_audit`.

The 2026-05-10 amendment incorporating the three Stage 0 hardenings (typed `dsep_hash` algorithm tag, dispatcher per-row `alg_id` logging, KAT corpus pinning at the rate boundary plus long-message vector) was approved by the same sole director on 10 May 2026, GPG-signed and DCO-signed under the same key. The full amendment provenance is in §7 Amendment Log.

---

## 7. Amendment Log

This section records all amendments to this ADR. Amendments are recorded in chronological order, oldest first. Each amendment entry documents the date, the source-of-authority for the amendment, the specific clauses amended, and the rationale.

**Amendment 1 — 2026-05-10 — Stage 0 hardenings per landscape research synthesis**

| Field | Value |
|---|---|
| Amendment date | 2026-05-10 |
| Approving authority | Muhammad Zaid Naeem (Sole Director, AIXYBER TECH LTD) |
| Source of authority | `docs/research/2026-05-10-v01-landscape.md` (committed at `1d0d0836dc55ac3efaf204e4ba68667ac77a8e8d`) — comprehensive cryptographic, regulatory, and PostgreSQL-extension landscape research synthesis with cut-off date 2026-05-09 |
| Original commit hash | `e3c91e67f5893597ceb373b9c9d4673941ae8330` (this file at the moment immediately before this amendment was applied) |
| Type of change | Tightening (no reversal of any prior decision) |

**Clauses amended:**

1. **Header table** — added `Date Amended` and `Source-of-authority for amendment` rows; status updated to `Accepted (amended)`.
2. **§1.1** — added closing paragraph documenting the 2026-05-10 amendment and pointing readers to §7.
3. **§1.2** — clarified items (4) and (5) to mention the per-row `alg_id` recording and the typed algorithm-tag construction respectively.
4. **§1.4** — added items (a) and (b) to the distinguishing engineering contributions list, covering the per-row `alg_id` logging and the typed-algorithm-tag forward-compatibility construction.
5. **§2.1** — `pg_qsag.dsep_hash` documentation tightened to reference §2.3 for the typed algorithm-tag domain string used in the audit-chain construction; `pg_qsag.append` documentation tightened to record `alg_id` per row; `pg_qsag.export_chain` return type extended with `alg_id` column; `pg_qsag.run_kats` documentation cross-references §2.7 for the corpus pinning.
6. **§2.2** — added three new paragraphs at the end of the section documenting the per-row `alg_id` logging requirement (per CSWP-39 §3.2.3 final), the `pg_qsag_audit.preferred_alg` GUC (policy/mechanism separation), and reaffirming the no-memoisation-of-digest-outputs commitment.
7. **§2.3** — the per-event computation formula's `domain_separator_n` definition was changed from a static-domain construction to a typed algorithm-tag construction (`'q-sag-audit:v1:' || alg_id`); a new prose paragraph "Why the typed algorithm-tag domain separator" was added explaining the forward-compatibility rationale and the RFC 9162 consistency-proof analogy; the `pg_qsag.audit_chain` table schema was extended with the `alg_id text NOT NULL` column; the table-following prose paragraph was tightened to document the per-row `alg_id` field.
8. **§2.4** — added "Algorithm-substitution / downgrade attacks" to the defended-against list; added §2.7 cross-reference for the KAT corpus.
9. **§2.5** — `qsag-anchors` integration paragraph tightened to reference `(stream, seq, alg_id)` triple and the algorithm-provenance preservation through SCITT receipt verification.
10. **§2.6** — Merkle-tree accumulator out-of-scope item tightened to reference RFC 9162 generalisation.
11. **§2.7 (new)** — entirely new subsection documenting the layered KAT corpus pinning (Layer 1: NIST FIPS 202 example file; Layer 2: Keccak team long-message vector at minimum 10 MB; Layer 3: rate-boundary at exactly 832 bits for SHA3-384; Layer 4: algorithm-tag round-trip and migration-anchor synthesis). Includes the bug-class checklist for the pure-plpgsql fallback and cross-references the research synthesis for the full discussion.
12. **§3.1** — fourth bullet (chain-hash linkage formula) updated to reflect the typed algorithm-tag construction; new closing bullet added documenting the §2.7 KAT corpus pinning as a hard precondition for v0.1 release.
13. **§3.2** — three new bullets added: `alg_id` column mandatory; typed `dsep_hash` mandatory; GitHub Actions SHA-pinning mandatory (post-tj-actions/changed-files lesson). CI matrix extended to include OpenSSL 3.5.
14. **§3.3** — new bullet added documenting that any prior assumption of a static `dsep_hash` domain string is removed; existing bullets tightened to reflect the per-row `alg_id` and the typed algorithm-tag.
15. **§3.4** — risk paragraphs tightened: dispatcher state-machine risk now references per-row `alg_id` as a post-hoc detection mechanism; audit-chain hash-formula evolution risk now references the typed-tag construction and RFC 9162 consistency-proof anchors; regulatory framework risk now references the EU Digital Omnibus on AI deferral context with the v0.1-architecture-unchanged commitment.
16. **§4** — CSWP-39 reference updated to reference §3.2.3 explicitly with finalisation date; CNSA 2.0 reference tightened to mention the internal-use carve-out and the BHT-quantum collision floor; new RFC 9162 reference added; EU AI Act reference annotated with the Digital Omnibus context.
17. **§5** — academic prior art expanded to include Brassard-Høyer-Tapp 1997 (quantum collision algorithm) and Dowling et al. ESORICS 2016 (RFC 9162 generalisation); new RFC 9162 standards reference added; project-internal reference added for the research synthesis with full commit hash.
18. **§6** — closing paragraph added documenting the 2026-05-10 amendment approval.

**Rationale (summary):**

The research synthesis identified three concrete tightenings that align the v0.1 design with the 2027–2030 cryptographic, regulatory, and standards horizon. None of the changes reverse a prior decision; all of them tighten an existing decision to reduce technical debt that would otherwise need to be paid down at v0.5+ migration time. Specifically:

- The typed algorithm-tag `dsep_hash` enables the v0.5 SCITT emitter to produce RFC 9162-style consistency proofs across any future algorithm migration without re-architecting the chain primitive.
- The per-row `alg_id` logging satisfies CSWP-39 §3.2.3 final (December 2025) which requires per-event determinable algorithm provenance (single-point session-start logging is insufficient under the final text).
- The KAT corpus pinning at the rate boundary plus the long-message vector closes the bug-class window that has historically caught lane-indexing and `pad10*1` transcription errors in interpreted-language Keccak ports — the exact class of port that the pure-plpgsql TLE flavour belongs to.

The substrate design holds. ADR-0001 is fundamentally sound as originally committed; this amendment refines three implementation specifics for forward-compatibility and standards alignment.

---

*© 2026 AIXYBER TECH LTD (Company No. 16826340), trading as Neoxyber. Registered in England and Wales. ICO Registration: ZC071900. Released under the Apache License, Version 2.0.*
