# ADR-0001 — pg_qsag_audit Design

| Field | Value |
|---|---|
| **ADR Number** | 0001 |
| **Title** | pg_qsag_audit Design |
| **Status** | Accepted |
| **Date Proposed** | 2026-05-09 |
| **Date Accepted** | 2026-05-09 |
| **Author** | Muhammad Zaid Naeem (Maintainer, AIXYBER TECH LTD trading as Neoxyber) |
| **Approver** | Muhammad Zaid Naeem (Sole Director, AIXYBER TECH LTD) |
| **Supersedes** | None (this is the first artefact-level ADR) |
| **Superseded By** | None |
| **Related Master ADRs** | ADR-0031 (Open-Source Cryptographic and Audit Substrate Programme; amended 2026-05-09) in the private neoxyber-qsag repository |
| **Related Sibling ADRs** | qsag-anchors ADR-0001-design (federated SCITT TS primitives); qsag-canonical ADR-0001-design (RFC 8785 JCS implementation) |
| **Scope** | pg_qsag_audit v0.1 design surface, with v0.5 trajectory previewed |
| **Licence** | Apache License 2.0 |

---

## 1. Context

### 1.1 What this ADR locks

This ADR is the design decision record for `pg_qsag_audit`, the third artefact in the Q-SAG open-source substrate programme. It commits to the v0.1 SQL surface, the dual-flavour build-target architecture (`dist/tle/` and `dist/pgrx/`), the SHA3 implementation strategy, the dispatcher state machine, the audit-chain hash linkage, the threat model, the conformance testing discipline, the integration pattern with sibling Q-SAG artefacts, and the v0.5 trajectory.

The master programme ADR (ADR-0031 in the private neoxyber-qsag repository, amended 2026-05-09 at commit `5541d7b32e16b5a1da8b25e17a1c989cff049dde`) commits to the existence of this artefact and to its place in the ten-artefact substrate programme. This ADR-0001 commits to *how* the artefact is designed.

Per the locked ADR discipline in ADR-0031 §4.1 (the two-tier ADR structure: master programme ADRs in `neoxyber-qsag`, per-artefact ADRs in this repository), this ADR-0001 must be committed before any source code lands in `dist/tle/` or `dist/pgrx/`. This is being committed as part of the initial repository scaffolding.

### 1.2 Why this artefact exists

PostgreSQL is the operational data plane for a substantial fraction of audit-relevant systems in the AI-agent governance horizon: regulator submissions, evidence packs, agent-action ledgers, transparency-service mirrors. EU AI Act Article 12 (full force 2 August 2026), CRA Article 14 (vulnerability reporting from 11 September 2026), eIDAS 2 EUDI Wallets (member-state availability late 2026), and CNSA 2.0 (procurement gate 1 January 2027) all converge on one engineering requirement: tamper-evident logs with cryptographically-agile, post-quantum-aware hash functions, anchored at the database tier where the data lives.

The "seven-year SHA3 absence in PostgreSQL" is a story that has been told often. It is also, on inspection, more nuanced than the headline. OpenSSL has provided SHA3 to `pgcrypto`'s `digest()` function via the EVP layer since OpenSSL 1.1.1 (September 2018). On a recent PostgreSQL build linked against a recent OpenSSL, `SELECT encode(digest('abc', 'sha3-256'), 'hex')` returns the canonical SHA3-256 of `'abc'` — with no third-party extension. The 2018 pgsql-hackers thread "need for SHA3" closed on this rationale: OpenSSL would carry it. That decision has held for over seven years, and it works for most users.

What that decision did not provide — and what `pg_qsag_audit` provides — is the layered set of disciplines that turn a hash function into an audit primitive:

1. **Documentation** that advertises SHA3 explicitly with KAT-verified behaviour and copy-pastable examples, rather than leaving SHA3 silently available via the "any algorithm OpenSSL supports" clause that most engineers and most auditors do not know about.
2. **Portability** to OpenSSL builds without SHA3 (some legacy ARM toolchains, FIPS-stripped builds, certain Bitnami images) via a pure-plpgsql fallback that is KAT-verified to match the OpenSSL-backed result byte-for-byte.
3. **Sandbox-safety on managed tiers** (AWS RDS, Aurora, Supabase) where C extensions are forbidden, via the `pg_tle` Trusted Language Extensions framework. The TLE flavour ships SHA3 plus the audit-chain primitives in pure plpgsql, deployable on every managed tier where `pg_tle` itself is supported.
4. **Negotiation-integrity binding** per NIST CSWP 39 §3.2.3 (final 19 December 2025): the choice of cryptographic implementation is cryptographically bound to the audit trail of the decisions it produces. The dispatcher logs the dispatch decision (pgcrypto vs in-extension fallback) into the audit chain itself.
5. **Audit-chain primitive** with hash-chained tamper-evidence, RFC 8785 canonical input encoding, NIST SP 800-185 KMAC keyed-mode domain separation, and verifiable end-to-end integrity via `pg_qsag.verify_chain()`.
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

The artefact's distinguishing engineering contributions are: (a) the dispatcher's CSWP-39 §3.2.3 negotiation-integrity binding logged into the audit chain; (b) the SQL-surface equivalence between the TLE flavour and the pgrx-native flavour, CI-gated; (c) at v0.5, the SCITT Signed Statement emission directly from a Postgres trigger, which to the best of our knowledge no published Postgres extension implements as of May 2026.

---

## 2. Decision

### 2.1 v0.1 SQL surface

`pg_qsag_audit` v0.1 ships the following SQL surface in the `pg_qsag` schema. Every function below is implemented in both the TLE flavour (`dist/tle/`) and the pgrx-native flavour (`dist/pgrx/`) with byte-identical semantics on conformant inputs. The TLE-vs-pgrx SQL-surface equivalence CI job verifies this on every push.

**Hash primitives:**

- **`pg_qsag.sha3_256(input bytea) returns bytea`** — SHA3-256 per NIST FIPS 202. Returns the 32-byte digest of `input`. Strictly typed: `NULL` input returns `NULL`. Empty `bytea` input returns the canonical SHA3-256 of the empty string (`0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`).
- **`pg_qsag.sha3_384(input bytea) returns bytea`** — SHA3-384 per NIST FIPS 202. Returns the 48-byte digest of `input`. Same `NULL`-handling and empty-string canonical-result semantics as `sha3_256`.

**Dispatcher:**

- **`pg_qsag.digest(input bytea, algo text) returns bytea`** — agility-aware dispatcher. `algo` accepts `'sha3-256'` or `'sha3-384'` at v0.1; future algorithms are added by extending this function rather than by defining new function names. The dispatcher implements the four-state state machine documented in §2.2. The dispatch decision (pgcrypto vs in-extension fallback, plus the OpenSSL EVP version observed) is appended to `pg_qsag.dispatch_log` for the calling session and, if the calling session is inside a chain-append transaction, also into the audit-chain event payload per §2.4.
- **`pg_qsag.dispatcher_state() returns table(algo text, path text, openssl_version text, last_observed timestamptz)`** — diagnostic view of the dispatcher's last-observed state per algorithm. Useful for debugging FIPS-stripped-OpenSSL deployments.

**Domain separation:**

- **`pg_qsag.dsep_hash(domain text, payload bytea, algo text default 'sha3-384') returns bytea`** — domain-separated hashing per `H(len_BE32(domain) || domain || payload)`. The 32-bit big-endian length prefix prevents collision between domain-prefix-of-payload and short-payload-with-long-domain. `domain` is UTF-8 normalised to NFC before length computation. Algorithm choice routes through `pg_qsag.digest()`.
- **`pg_qsag.kmac_hash(key bytea, data bytea, customisation text default '', length_bits int default 384) returns bytea`** — KMAC keyed-mode domain separation per NIST SP 800-185. Returns the `length_bits/8`-byte KMAC output. v0.1 supports `length_bits` ∈ {128, 256, 384, 512}; arbitrary lengths are reserved for v0.5+.

**Canonical input encoding:**

- **`pg_qsag.canon_jsonb(input jsonb) returns bytea`** — RFC 8785 JCS canonical encoding of a `jsonb` value. v0.1 delegates to the application-tier `qsag-canonical` Python implementation via a foreign-data-wrapper or HTTP shim depending on deployment topology (configured via `pg_qsag.canon_endpoint` GUC). The v0.2 work item is a self-contained pure-pgrx implementation that removes the application-tier dependency for self-hosted deployments. Identical semantic inputs always produce identical output bytes regardless of the path taken.

**Audit-chain primitive:**

- **`pg_qsag.append(stream uuid, payload jsonb) returns bigint`** — append an audit event to a hash-chained stream. Returns the sequence number of the appended event. Computes `H_n = SHA3-384(H_{n-1} || H_event_n)` where `H_event_n = SHA3-384(canon_jsonb(payload) || dsep_hash('pg_qsag.event', payload, 'sha3-384'))` and `H_0 = SHA3-384('pg_qsag.stream:' || stream::text)`. Writes a row to `pg_qsag.audit_chain(stream, seq, event_hash, chain_hash, payload, dispatcher_decision, created_at)`. The full hash linkage formula is documented in §2.3.
- **`pg_qsag.verify_chain(stream uuid, from_seq bigint default 1, to_seq bigint default null) returns table(ok boolean, first_break_seq bigint, observed_chain_hash bytea, expected_chain_hash bytea)`** — verify the integrity of a hash chain over the specified sequence range (default: full chain). Returns one row. `ok=true, first_break_seq=NULL` for an intact chain. `ok=false, first_break_seq=n` plus the observed and expected chain-hash bytes pointing at the first broken link.
- **`pg_qsag.export_chain(stream uuid, from_seq bigint default 1, to_seq bigint default null) returns table(seq bigint, payload jsonb, event_hash bytea, chain_hash bytea, dispatcher_decision jsonb)`** — export an audit chain in stable canonical order for offline verification or for transmission to an external SCITT Transparency Service (e.g. qsag-anchors). The exported rows are sorted by `seq ascending`.

**Conformance and diagnostics:**

- **`pg_qsag.run_kats() returns table(vector_id text, algo text, expected bytea, observed bytea, ok boolean)`** — run the embedded NIST FIPS 202 Known Answer Test corpus and return the per-vector pass/fail map. Called automatically at extension creation time; loading is refused if any vector fails. Can be re-run at any time to verify post-install corpus integrity (e.g. after a Postgres point-release upgrade).
- **`pg_qsag.version() returns text`** — extension version string in semantic versioning form (e.g. `'0.1.0'`).
- **`pg_qsag.flavour() returns text`** — returns `'tle'` or `'pgrx'` to identify which build flavour is loaded. Exists primarily for the TLE-vs-pgrx SQL-surface equivalence CI job and for diagnostic purposes.

**Errors:**

- **`pg_qsag_invalid_input`** (SQLSTATE `22023`) — raised when input does not satisfy a declared precondition (e.g. unknown algorithm name passed to `pg_qsag.digest`).
- **`pg_qsag_chain_break`** (SQLSTATE `40001`) — raised when `pg_qsag.append` detects that the current chain head does not match the expected predecessor (concurrent appends, manual database modification). The error includes the stream UUID, the expected predecessor hash, and the observed predecessor hash for forensic analysis.
- **`pg_qsag_kat_failure`** (SQLSTATE `XX000`, internal error class) — raised when `pg_qsag.run_kats()` finds any vector failing. Refusal to load on extension creation surfaces as this error class.

The full SQL surface is documented in `dist/tle/README.md` and `dist/pgrx/README.md` (forthcoming with v0.1) with worked examples for each function.

### 2.2 Dispatcher state machine (v0.1)

`pg_qsag.digest()` is a four-state state machine that decides at every call which implementation to use:

**State 1 — pgcrypto-available, EVP exposes algo**: pgcrypto extension is installed in the database, OpenSSL EVP exposes the requested SHA3 algorithm, and a probe call (executed once per session and cached) succeeded. Dispatch routes to `pgcrypto.digest(input, algo)`. Probe is repeated on session start; cache is keyed on `(algo, openssl_version_string)` so an OpenSSL upgrade triggers re-probing.

**State 2 — pgcrypto-available, EVP missing algo**: pgcrypto is installed but the probe failed (FIPS-stripped OpenSSL build, ARM legacy toolchain, etc.). Dispatch routes to the in-extension implementation. The decision is logged with `path='fallback', reason='evp_missing_algo'`.

**State 3 — pgcrypto-unavailable**: pgcrypto is not installed in the database (managed-cloud tiers without pgcrypto support, or self-hosted Postgres where the operator chose not to install it). Dispatch routes to the in-extension implementation. The decision is logged with `path='fallback', reason='pgcrypto_unavailable'`.

**State 4 — fallback-failed**: the in-extension implementation itself fails (KAT vector mismatch detected during the call, or the implementation raises an unexpected error). Raises `pg_qsag_kat_failure`. The audit chain entry that triggered this state is rolled back per Postgres transaction semantics.

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

The dispatch decision is recorded in `pg_qsag.dispatch_log` (per-session) and, for calls inside a chain-append transaction, is also embedded in the chain event's `dispatcher_decision` column per §2.3. This is the NIST CSWP 39 §3.2.3 negotiation-integrity binding: the choice of implementation is part of the auditable trail, not a hidden detail.

The dispatcher does not memoise digest *outputs* (that would be a security risk against secret-dependent inputs even though we explicitly disclaim side-channel resistance — better to never cache hash outputs by policy). It only memoises the *probe result* per session per `(algo, openssl_version)`.

### 2.3 Audit-chain hash linkage (v0.1)

The v0.1 chain is a simple hash-chain. Each event commits to the prior chain head plus the canonical encoding of its own payload plus a domain-separator hash that prevents domain-shifting attacks.

**Genesis:**
```
H_0 = SHA3-384(UTF8('pg_qsag.stream:' || stream::text))
```

The stream UUID is bound into the genesis hash so that two streams with the same first event do not produce identical chain heads.

**Per-event computation (event n, n ≥ 1):**
```
canonical_payload_n = pg_qsag.canon_jsonb(payload_n)
domain_separator_n = pg_qsag.dsep_hash('pg_qsag.event', canonical_payload_n, 'sha3-384')
H_event_n = SHA3-384(canonical_payload_n || domain_separator_n)
H_n = SHA3-384(H_{n-1} || H_event_n)
```

The chain hash `H_n` is what `pg_qsag.verify_chain` recomputes from the row's `event_hash` (which is `H_event_n`) and the prior row's `chain_hash` (which is `H_{n-1}`).

**Why SHA3-384 and not SHA3-256:**
SHA3-384 provides 192-bit collision resistance classically and 96-bit collision resistance against quantum adversaries via Brassard-Høyer-Tapp generalisation of Grover. CNSA 2.0 mandates SHA-384 (FIPS 180-4) for NSS use; SHA3-384 is permitted inside specific algorithms. We choose SHA3-384 over SHA3-256 because the post-quantum collision-resistance margin matters for an audit-chain primitive whose security is needed beyond 2030 (the conservative quantum-cryptanalysis horizon). The cost is 16 extra bytes per event; we accept this trade-off.

**Why canonical input encoding before hashing:**
Without canonicalisation, two semantically-identical events with different JSON serialisations (different key ordering, different whitespace, different number formatting) produce different hashes. This breaks cross-platform verification and makes the chain unverifiable when payloads originate from heterogeneous producers. RFC 8785 JCS gives us byte-stable canonical encoding. v0.1 delegates this to `qsag-canonical` (Python application tier); v0.2 brings it in-extension via a pgrx port.

**Why the domain separator:**
Without `dsep_hash`, an attacker who can choose payloads might construct two different payloads whose `canonical_payload || something` produces equal hashes (a length-extension-style attack on raw-concatenation hash inputs). The domain separator binds the hash to a specific domain string ("pg_qsag.event") and length-prefixes the domain to prevent collision between short-domain-long-payload and long-domain-short-payload constructions. The domain separator approach follows NIST SP 800-185 KMAC structure.

**`pg_qsag.audit_chain` table schema:**
```sql
CREATE TABLE pg_qsag.audit_chain (
    stream uuid NOT NULL,
    seq bigint NOT NULL,
    event_hash bytea NOT NULL,            -- H_event_n (48 bytes for SHA3-384)
    chain_hash bytea NOT NULL,            -- H_n (48 bytes)
    payload jsonb NOT NULL,
    dispatcher_decision jsonb NOT NULL,   -- {path, openssl_version, evp_probe, reason}
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (stream, seq)
);
```

The `dispatcher_decision` column is the CSWP 39 §3.2.3 negotiation-integrity record: it documents which implementation produced the hash. Verifiers reading this row know whether the digest was computed by pgcrypto+OpenSSL EVP or by the in-extension fallback, and which OpenSSL version was observed if pgcrypto was used.

**VACUUM / PITR / logical-replication stability:**
The chain hashes are derived from the row contents (`payload`, `event_hash`, `chain_hash`), not from physical row identifiers (`ctid`, `xmin`, `xmax`). VACUUM that rewrites the physical row layout does not invalidate the chain. Point-in-time recovery to a consistent transactional state preserves the chain. Logical replication that ships the row contents preserves the chain. Physical replication via streaming WAL preserves the chain trivially (the chain is data, not derived state).

The one operational caveat is **reordering**: if two transactions append to the same stream concurrently, the `seq` allocation must be serialised. v0.1 enforces this via a SERIALIZABLE-isolated transaction around the `pg_qsag.append` call internally. Concurrent append attempts that lose the serialisation race raise `pg_qsag_chain_break` (SQLSTATE `40001`, the standard serialisation-failure class) so that callers retry with the corrected chain head.

### 2.4 Threat model (v0.1)

Documented in detail in [THREAT_MODEL.md](../../THREAT_MODEL.md) (forthcoming with v0.1) and [SECURITY.md](../../SECURITY.md) (committed at `c777767454e9aa9af6a8b1ab4b04c5fbaffc3309`). Summary of v0.1 commitments:

**Defended against:**

- **SHA3 implementation divergence from FIPS 202.** The full NIST CAVP KAT corpus runs at install time and gates loading. CI runs the same corpus against both build flavours on every push.
- **Dispatcher routing inconsistent with the logged decision.** The CSWP 39 §3.2.3 binding ensures that if the dispatcher claims to have used pgcrypto, the digest was actually computed by pgcrypto. Test suite includes positive and negative cases for both the pgcrypto-available and pgcrypto-unavailable paths.
- **Audit-chain tampering by a non-superuser writer.** The chain-hash recomputation in `pg_qsag.verify_chain` detects any modification to `payload`, `event_hash`, or `chain_hash` for any sequence. Modifications by a writer with `INSERT/UPDATE/DELETE` privilege on `pg_qsag.audit_chain` (where the row is owned by the extension) are detected.
- **Length-extension and domain-shifting attacks** against the chain hashing. The `dsep_hash` domain separator and the length-prefix construction prevent these classes of attack.
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
- **With `qsag-anchors`** (artefact #1): at v0.5, `pg_qsag.export_chain` results plus the SCITT Signed Statement emitter feed into `qsag-anchors` for federated transparency-service anchoring. Cross-artefact verification is end-to-end: a verifier reading a SCITT receipt from `qsag-anchors` can trace the entry back to a specific `(stream, seq)` in `pg_qsag.audit_chain` and verify the chain-hash linkage from genesis.
- **With `qsag-evidence`** (artefact #5, forthcoming): `qsag-evidence`'s EU AI Act Annex IV export views consume `pg_qsag.export_chain` results, packaging them with the canonical JSON of each event and the cryptographic proofs into regulator-facing audit packs.
- **With `qsag-ocsf`** (artefact #6, forthcoming): `qsag-ocsf` emits OCSF v1.8.0 `ai_operation` events sourced directly from `pg_qsag.audit_chain` triggers.
- **With `qsag-aibom`** (artefact #9, forthcoming): linkage assertions in CycloneDX 1.6 and SPDX 3.0 manifests use `pg_qsag.dsep_hash` as the canonical hash function for cross-artefact verifiability.
- **With Q-SAG main** (private neoxyber-qsag repository): once v0.1 ships, Q-SAG main migrates database-tier audit logging from its current per-table approach to `pg_qsag.append` calls. The migration is gradual and transactional.
- **With Microsoft AGT and Asqav SDK**: indirect — these consume audit events via `qsag-anchors` and `qsag-evidence`, not directly from `pg_qsag_audit`.

### 2.6 Out of scope for v0.1

The following are explicitly out of scope for v0.1 and reserved for later versions:

- **Merkle-tree accumulator over the audit chain.** Reserved for v0.5. v0.1's hash-chain provides tamper-evidence; v0.5's Merkle accumulator adds logarithmic-length consistency proofs and inclusion proofs, following the Crosby-Wallach 2009 USENIX history-tree pattern.
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

---

## 3. Consequences

### 3.1 What this ADR makes true

- The v0.1 SQL surface is locked. Adding to or changing the surface requires a new ADR superseding the relevant clause of this one.
- The dispatcher state machine is locked at four states with the transitions and logging behaviour documented in §2.2.
- The audit-chain hash linkage formula is locked: `H_n = SHA3-384(H_{n-1} || H_event_n)` where `H_event_n = SHA3-384(canonical_payload || dsep_hash('pg_qsag.event', canonical_payload, 'sha3-384'))`. Any change to this formula breaks every existing chain and requires a new ADR plus a documented migration path.
- The TLE flavour and the pgrx-native flavour share one canonical SQL surface. CI verifies this on every push via the SQL-surface equivalence job.
- Audit chains are **tamper-evident, not tamper-proof**. This is a documented commitment, not an aspiration.
- The dispatcher binding is **forensic, not preventative**. The CSWP 39 §3.2.3 record documents the dispatch decision; it does not prevent forcing.
- v0.1 has a runtime dependency on `qsag-canonical` for `canon_jsonb` operation. Self-hosted deployments must run a `qsag-canonical` endpoint reachable from the database. v0.2 removes this dependency.

### 3.2 What this ADR makes required

- Every release of `pg_qsag_audit` from v0.1 onward must include the full NIST FIPS 202 KAT corpus, all passing, with `pg_qsag.run_kats()` gating extension loading.
- Every release must publish a CycloneDX 1.6 SBOM and SLSA Level 3 build provenance.
- Every release must publish a JWS-signed `META.json` per PGXN v2 RFC-5 once the SDK supports it.
- THREAT_MODEL.md, STANDARDS.md, `dist/tle/README.md`, `dist/pgrx/README.md`, and the conformance test corpus in `docs/conformance/test-vectors/` must be present and accurate at v0.1 ship time.
- The TLE-vs-pgrx SQL-surface equivalence CI job must pass on every PR. Intentional divergence requires a documented allowlist update and an ADR amendment.
- The CI matrix must cover PostgreSQL 14, 15, 16, 17, 18 × OpenSSL 1.1.1, 3.0, 3.2 × x86_64, aarch64. Failure to cover this matrix on a release blocks the release.
- Every fixed SHA3-divergence, dispatcher-binding, or audit-chain-tampering bug must be committed to the public conformance test corpus as a regression test, citing the discovery and the affected versions, per the SECURITY.md hardening commitments.

### 3.3 What this ADR makes false (or removes)

- Any prior assumption that `pg_qsag_audit` would ship as two separate repositories (`pg-qsag-audit-tle` and `pg-qsag-audit`). The amended ADR-0031 §2.5 (commit `5541d7b`) consolidates them into one canonical repository with the dual-flavour `dist/tle/` and `dist/pgrx/` structure. This ADR-0001 inherits and reinforces that consolidation.
- Any prior assumption that the dispatcher would silently fall back without logging. The CSWP 39 §3.2.3 binding makes the dispatch decision part of the auditable trail.
- Any prior assumption that v0.1 would include the SCITT Signed Statement emitter. That is v0.5 work. v0.1 ships the audit-chain primitive that v0.5 builds upon.
- Any prior assumption that v0.1 would offer constant-time guarantees. It does not. Side-channel non-resistance is a documented commitment.
- Any prior assumption of support for PostgreSQL versions older than 14. They are not supported and not planned.

### 3.4 Risks documented

- **Risk of subtle divergence between the TLE flavour and the pgrx-native flavour.** Mitigation: the SQL-surface equivalence CI job runs the same SQL test scenarios against both flavours and fails on divergence. Any divergence found post-release is a P0 incident.
- **Risk of dispatcher state-machine incorrectness causing silent wrong-implementation routing.** Mitigation: positive and negative test cases for all four states. Independent fuzzing of the probe logic on adversarial OpenSSL configurations.
- **Risk of audit-chain hash-formula evolution breaking existing chains.** Mitigation: the v0.1 formula is committed and will not change without a major-version bump and a documented migration path. v0.5's Merkle accumulator extends rather than replaces the v0.1 chain.
- **Risk of `qsag-canonical` dependency at v0.1 making self-hosted deployments operationally complex.** Mitigation: documented operator playbook for running `qsag-canonical` as a sidecar. v0.2 removes the dependency entirely.
- **Risk of `pg_tle` framework changes breaking the TLE flavour.** Mitigation: pinned `pg_tle` version in the TLE flavour's manifest. Compatibility testing across `pg_tle` versions on every CI run.
- **Risk of NIST CAVP KAT corpus drift if NIST updates the published vectors.** Mitigation: the embedded corpus is versioned; updates require a release and an ADR-0001 amendment recording the corpus version transition.
- **Risk that the SCITT specification advances in a way that breaks the v0.5 emitter.** Mitigation: track `draft-ietf-scitt-architecture` updates; defer v0.5 ship until SCITT reaches RFC status if pre-RFC drafts continue to break compatibility. This is acceptable; the v0.1 surface is independently useful.
- **Risk of regulatory framework changes (EU AI Act, CRA) altering Article 12 / Article 14 export requirements before v0.5 ships.** Mitigation: the v0.5 export views and CRA cascade connector are design-tracked separately and will be updated as regulatory guidance is published. The v0.1 surface is regulatory-framework-independent.

---

## 4. Compliance and conformance

This artefact aligns with:

- **NIST FIPS 202** — SHA-3 Standard. SHA3-256 and SHA3-384 are the v0.1 primary primitives; SHA3-384 is the chain-hash algorithm.
- **NIST SP 800-185** — KMAC, TupleHash, ParallelHash. KMAC keyed-mode used in `pg_qsag.kmac_hash`; the dsep_hash construction follows the SP 800-185 length-prefix domain-separation pattern.
- **NIST CSWP 39** — Crypto Agility (final 19 December 2025). §3.2.3 negotiation-integrity binding implemented by the dispatcher; the dispatch decision is bound into the audit chain.
- **NIST CNSA 2.0** — SHA-384 retained for NSS use; SHA3-384 permitted inside specific algorithms. Our chain-hash choice of SHA3-384 satisfies the CNSA 2.0 post-quantum collision-resistance requirement.
- **IETF RFC 8785** — JSON Canonicalisation Scheme (JCS). v0.1 delegates to `qsag-canonical`; v0.2 brings in-extension.
- **IETF RFC 8259** — JSON Data Interchange Format. The input grammar for `canon_jsonb`.
- **IETF SCITT** — `draft-ietf-scitt-architecture-22`. v0.5 Signed Statement emitter follows this draft.
- **IETF COSE Receipts** — `draft-ietf-cose-merkle-tree-proofs-18`. v0.5 inclusion-proof format follows this draft.
- **PGXN v2** — RFC-2 (binary distribution), RFC-3 (Meta Spec v2 with `contents` taxonomy), RFC-5 (release certification with JWS-signed META.json).
- **EU Regulation 2024/1689** (AI Act) — Article 12 (logging), Article 26 (deployer obligations). v0.5 export views align with Article 12(3) field requirements.
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
- NIST CSWP 39 — Crypto Agility (final 19 December 2025).
- NIST CNSA 2.0 — Commercial National Security Algorithm Suite v2.
- IETF RFC 8785 — JSON Canonicalisation Scheme (JCS).
- IETF RFC 8259 — JSON Data Interchange Format.
- IETF RFC 7515 — JSON Web Signature (JWS).
- IETF draft-ietf-scitt-architecture-22 — SCITT.
- IETF draft-ietf-cose-merkle-tree-proofs-18 — COSE Receipts.
- PGXN v2 RFC-2, RFC-3, RFC-5 — David Wheeler (Tembo) and the PGXN Steering Committee.
- EU Regulation 2024/1689 — Artificial Intelligence Act.
- EU Regulation 2024/2847 — Cyber Resilience Act.

**Academic prior art:**
- Madhwal, Yash; Yanovich, Yury; Anokhin, Ilya. "Blockchain Extension for PostgreSQL Data Storage." In Proceedings of the 3rd Blockchain and Internet of Things Conference (BIOTC 2021), pp. 24-30. ACM, July 2021. DOI: 10.1145/3475992.3476001.
- Crosby, Scott A. and Wallach, Dan S. "Efficient Data Structures for Tamper-Evident Logging." In Proceedings of the 18th USENIX Security Symposium, pp. 317-334. USENIX Association, August 2009.

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

---

## 6. Approval

Approved by the sole director of AIXYBER TECH LTD, Muhammad Zaid Naeem, on 9 May 2026. This ADR is committed GPG-signed (Ed25519 key fingerprint `A65AF5B7F02C9EB5B98023D70DB861BBF30F0D7B`, valid until April 2028) and DCO-signed alongside the v0.0.0 scaffolding for `pg_qsag_audit`.

---

*© 2026 AIXYBER TECH LTD (Company No. 16826340), trading as Neoxyber. Registered in England and Wales. ICO Registration: ZC071900. Released under the Apache License, Version 2.0.*
