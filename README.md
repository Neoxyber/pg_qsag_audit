# pg-qsag-audit

> Portable, KAT-verified, sandbox-safe SHA-3 and append-only audit-chain primitives for PostgreSQL. Dual-flavour TLE and pgrx packaging from a single source tree. Part of the Q-SAG open-source substrate programme.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Status](https://img.shields.io/badge/status-pre--v0.1%20scaffolding-orange.svg)](#status)
[![Standards](https://img.shields.io/badge/standards-FIPS%20202%20%7C%20SP%20800--185%20%7C%20RFC%208785%20%7C%20SCITT%20%7C%20CSWP%2039-informational.svg)](#standards)

`pg-qsag-audit` is part of the **Q-SAG open-source substrate programme** — a research effort to build a set of post-quantum cryptographic and audit primitives for AI-agent governance. The substrate is stewarded by AIXYBER TECH LTD (trading as Neoxyber) under the [Apache License 2.0](LICENSE).

This repository is in the structuring and scaffolding stage. The code, tests, and documentation will be built up iteratively under public version control. There is no shipped release yet.

---

## What this library is for

`pg-qsag-audit` adds a portable, deterministic, sandbox-safe SHA-3 implementation to PostgreSQL, together with the append-only audit-chain primitives that downstream substrate components depend on. It is intended to be the database-tier substrate for tamper-evident AI audit logs.

The library ships in two build flavours from one source tree:

- **TLE flavour** (`dist/tle/`) — pg_tle SQL-only packaging. Compatible with managed-PostgreSQL tiers where unprivileged extensions are the only option (managed cloud databases that support pg_tle, such as AWS RDS, Aurora, and Supabase). Closes the day-one deployment gap for development environments.
- **pgrx flavour** (`dist/pgrx/`) — pgrx-native Rust packaging. Full SHA-3 and audit-chain primitives at native speed. Targets self-hosted PostgreSQL from production deployment onward.

Both flavours share the same SQL surface, the same SECURITY policy, the same NIST FIPS 202 test vector corpus, the same maintainer GPG signing identity, and one canonical PGXN registration. Migration between flavours requires no application change.

---

## Why this gap exists

The "SHA-3 absent from PostgreSQL" framing is, on inspection, more nuanced than the headline.

OpenSSL has provided SHA-3 to `pgcrypto`'s `digest()` function via the EVP layer since OpenSSL 1.1.1 (September 2018). On a recent PostgreSQL build linked against a recent OpenSSL, `SELECT encode(digest('abc', 'sha3-256'), 'hex')` returns the canonical SHA-3-256 of `'abc'` — with no third-party extension. That path covers the majority case, and it works for most users.

What that decision did not provide is what `pg-qsag-audit` provides:

1. **Documentation.** The PostgreSQL `pgcrypto` documentation lists only `md5, sha1, sha224, sha256, sha384, sha512` as standard digest algorithms. SHA-3 is silently available via the "any algorithm OpenSSL supports" clause but is not advertised. Most engineers and most auditors do not know it works. `pg-qsag-audit` advertises it explicitly, with test-vector-verified behaviour and copy-pastable examples.
2. **Portability.** OpenSSL builds without SHA-3 still exist (some legacy ARM toolchains, FIPS-stripped builds, certain container images). A pure-plpgsql fallback in the TLE flavour, verified against the OpenSSL-backed result byte-for-byte using the official NIST test vectors, makes the SHA-3 path portable to every supported PostgreSQL deployment regardless of the OpenSSL build configuration.
3. **Sandbox-safety on managed tiers.** Managed PostgreSQL services that forbid customer-installed C extensions support the `pg_tle` framework instead. The TLE flavour of `pg-qsag-audit` ships SHA-3 plus the audit-chain primitives in pure plpgsql, deployable on any managed tier where `pg_tle` itself is supported. No customer-managed C-extension installation required.
4. **Negotiation-integrity binding.** When both the OpenSSL-backed path and the in-extension fallback are available, the dispatcher logs which path was chosen into the audit chain itself, with the choice cryptographically bound to the audit trail of decisions it produces. This is the discipline NIST CSWP 39 §3.2.3 calls for.
5. **AI audit alignment.** The audit-chain primitives are intended to record the operations of AI agents — what an agent did, when, under what policy, with what cryptographic identity — in a tamper-evident chain at the database tier where the data already lives.

The defensible novelty of `pg-qsag-audit` is not adding SHA-3 to PostgreSQL — `pgcrypto` and OpenSSL already cover that path for most deployments. It is providing a portable, test-vector-verified, sandbox-safe, dispatcher-aware, AI-audit-aligned SHA-3 and audit-chain layer that works identically across managed and self-hosted PostgreSQL tiers.

---

## What this library is not

It is important to be honest about scope.

This library is not a replacement for `pgcrypto`. It complements it. Where OpenSSL exposes the requested SHA-3 algorithm, the dispatcher routes to `pgcrypto.digest()`. The library exists to make sure the SHA-3 path is reachable even when `pgcrypto` is unavailable or when its OpenSSL is SHA-3-stripped.

This library is not a replacement for `pgaudit`. `pgaudit` records SQL statements as text log entries. This library records cryptographically chained AI-operation events as structured `jsonb` with hash-chained linkage. The two solve different problems and can be used together.

This library is not a blockchain. The audit chain is a single-stream append-only hash chain anchored within the PostgreSQL database. There is no consensus protocol, no token, no on-chain economics. The chain is verifiable end-to-end by anyone with read access to the audit table.

This library is not side-channel resistant. The TLE flavour runs in interpreted plpgsql; the pgrx flavour runs in a Rust process inside the PostgreSQL backend without constant-time guarantees. Do not feed secret-dependent inputs (session keys, unblinded private-key material) to its hashing primitives. The library exists for audit-event content hashing and chain accumulation, where inputs are by hypothesis non-secret.

---

## Locked v0.1 scope

The first numbered release will consist of the following SQL surface and supporting components:

| Component | Purpose |
|---|---|
| `pg_qsag.sha3_256(input bytea) returns bytea` | SHA-3-256. Pure-plpgsql Keccak-f[1600] sponge in the TLE flavour; native pgrx wrapper over a vetted Rust Keccak crate in the pgrx flavour. Both flavours pass the full NIST FIPS 202 test vector corpus. |
| `pg_qsag.sha3_384(input bytea) returns bytea` | SHA-3-384. Same dual implementation. |
| `pg_qsag.digest(input bytea, algo text) returns bytea` | Agility-aware dispatcher. When `pgcrypto` is present and OpenSSL exposes the requested algorithm, routes to `pgcrypto.digest()` for native-speed evaluation. When `pgcrypto` is absent or the algorithm is missing, falls back to the in-extension implementation. The dispatch decision is logged into the audit chain as a NIST CSWP 39 §3.2.3-aligned negotiation-integrity record. |
| `pg_qsag.dsep_hash(domain text, payload bytea, algo text) returns bytea` | Domain-separated hashing per `H(len_BE32(domain) || domain || payload)`, with an optional KMAC-style keyed mode per NIST SP 800-185. |
| `pg_qsag.canon_jsonb(input jsonb) returns bytea` | RFC 8785 JCS canonical encoding for `jsonb` inputs. Identical semantic inputs produce identical hashes regardless of key ordering. |
| `pg_qsag.append(stream uuid, payload jsonb) returns bigint` | Append an audit event to a hash-chained stream. Computes `H = SHA3-384(prev || H_event)` where `H_event = SHA3-384(canonical_jsonb || domain_separator)`. Writes to `pg_qsag.audit_chain`. |
| `pg_qsag.verify_chain(stream uuid) returns (ok boolean, first_break_seq bigint)` | Verify the integrity of a hash chain end-to-end. Returns `(true, NULL)` for an intact chain; returns `(false, n)` pointing at the first broken link if the chain has been tampered with. |
| `pg_qsag.tuplehash256(...)` | TupleHash256 (NIST SP 800-185) for unambiguous multi-field hashing. |
| `pg_qsag.run_kats()` | Embedded NIST FIPS 202 test vector regression suite. Returns per-vector pass/fail map at install time. |

The audit chain schema reserves first-class fields for `algorithm_status_at_use` (so the choice of hash function is itself part of the audit trail), AI incident record fields aligned to NIST AI 600-1, and EU AI Act Article 18-19 retention metadata.

A later minor release is expected to add a Merkle-tree accumulator with logarithmic-length consistency and inclusion proofs, a COSE-Receipts inclusion-proof emitter per IETF SCITT, and SCITT Signed Statement emission directly from a PostgreSQL trigger. These are intent, not commitment; specific scope and release tag will be set in the relevant Architecture Decision Records when implementation begins.

---

## Status

This repository is in the pre-v0.1 structuring phase. The work currently in progress is:

- Locking the architecture and committing the structure document (in the master programme repository)
- Drafting the SQL surface against NIST FIPS 202 and SP 800-185
- Setting up the dual-flavour build pipeline (TLE and pgrx from one source tree)
- Writing the v0.1 module scaffolding

No code beyond scaffolding is being claimed as functional yet. There is no PGXN publication. There is no `pg_tle` registry entry. There is no Zenodo DOI. The SQL surface described above is intent, not implementation.

---

## Installation

Functional installation paths will land with v0.1. When they do, the dual-flavour structure will support two install paths:

### Managed PostgreSQL (TLE flavour)

```sql
-- Once the dbdev publication lands at v0.1:
SELECT dbdev.install('neoxyber@pg_qsag_audit');
CREATE EXTENSION pg_qsag_audit;
```

Or via the AWS `pg_tle` framework directly, the TLE will install via `pgtle.install_extension()` from the `dist/tle/` distribution.

### Self-hosted PostgreSQL (pgrx flavour)

```bash
# Once PGXN publication lands at v0.1:
pgxn install pg_qsag_audit

# Or build from source:
cd dist/pgrx
cargo pgrx install
```

Then in the database:

```sql
CREATE EXTENSION pg_qsag_audit;
```

Both flavours will expose identical SQL surfaces. An audit chain populated under one flavour can be read and verified under the other; migration requires no re-hashing of the existing chain.

---

## Standards alignment

The intended alignment, to be verified by published test results when v0.1 ships:

- **NIST FIPS 202** (SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions). SHA-3-256 and SHA-3-384 are the primary primitives at v0.1.
- **NIST SP 800-185** (SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, ParallelHash). TupleHash256 is the primitive used for unambiguous multi-field hashing.
- **NIST CSWP 39** (Crypto Agility, final December 2025). §3.2.3 negotiation-integrity binding is implemented by the dispatcher.
- **NIST CNSA 2.0** (Commercial National Security Algorithm Suite 2.0). SHA-3-384 is the strongest standard SHA-3 variant permitted inside specific algorithms under CNSA 2.0.
- **IETF RFC 8785** (JSON Canonicalisation Scheme). Input encoding for `canon_jsonb`.
- **IETF SCITT** (Supply Chain Integrity, Transparency and Trust, draft-22). SCITT Signed Statement emission is intent for a later release.
- **IETF COSE Receipts** (draft `cose-merkle-tree-proofs`). Inclusion-proof format intent for a later release.
- **EU AI Act Regulation 2024/1689**. Article 12 (logging) and Article 18-19 (record retention) inform the audit-chain schema fields.
- **PGXN v2 packaging RFCs**. The release artefacts target PGXN v2 distribution discipline.

Detailed clause-level traceability matrices will be published with v0.1 in `docs/conformance/`.

---

## How this fits the broader substrate programme

The Q-SAG open-source substrate programme is a planned set of ten libraries. `pg-qsag-audit` is the fourth front-of-priority library; it depends on `qsag-pq-primitives` for cryptographic operations and uses the same canonical encoding as `qsag-canonical` to ensure hashes computed in PostgreSQL match hashes computed in Python.

The four front-of-priority libraries, in dependency order:

1. **qsag-pq-primitives** — wrappers and dependency-checklist verification over vetted upstream post-quantum implementations
2. **qsag-canonical** — canonicalisation, pre-hash, binding, policy
3. **qsag-anchors** — post-quantum trust-anchor primitives, including RFC 9794 hybrid-chain taxonomy
4. **pg-qsag-audit** *(this library)* — append-only SHA-3 audit chain primitives for PostgreSQL, in dual TLE and pgrx flavours

Six reserved libraries are structured but not yet implemented. Each will activate when its triggering external standard, hardware availability, or peer-reviewed academic result lands:

5. `qsag-threshold` · 6. `qsag-composite` · 7. `qsag-attest` · 8. `qsag-fn-dsa` · 9. `qsag-incident` · 10. `qsag-zk-attest`

The overall programme is documented in the substrate-programme overview at the steward's `.well-known` location.

---

## Honest gaps

This section is mandatory for every substrate library and will grow over time as more is learned.

- **Side-channel resistance** is not a property of this library. The TLE flavour runs in interpreted plpgsql; the pgrx flavour runs in a Rust process inside the PostgreSQL backend without constant-time guarantees. Hashing primitives must not be fed secret-dependent inputs.
- **PostgreSQL `MemoryContext` zeroisation** of key material in the pgrx flavour is best-effort. The standard PostgreSQL memory model does not guarantee that allocations are zeroised before being returned to the system. This is a limitation of the platform, not of this library.
- **TLE flavour performance** is materially lower than the pgrx flavour because pure plpgsql implementation of Keccak is interpreted. The TLE flavour exists for portability and managed-cloud compatibility, not for high-throughput hashing. Self-hosted deployments with significant audit-volume should use the pgrx flavour.
- **Audit chain compactness over time**. A single-stream append-only hash chain grows linearly with the number of events. The Merkle-tree accumulator intended for a later release provides logarithmic-length proofs; until that ships, the simple chain is the only primitive available.
- **SCITT draft churn**. The SCITT specification is still moving. The Signed Statement emission intent for a later release pins to a specific draft revision; consumers should expect the pinned version to change as the specification evolves.

---

## Contributing

Contributions are welcome from cryptographers, PostgreSQL extension developers, SCITT contributors, and AI-audit researchers. Before contributing, please read:

- [Contributing guide](CONTRIBUTING.md) — Developer Certificate of Origin sign-off, contributor ladder, AI-assistance disclosure
- [Code of Conduct](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
- [Security policy](SECURITY.md) — coordinated vulnerability disclosure

All commits must be DCO-signed (`git commit -s`). Maintainer commits are additionally GPG-signed. Pre-push hooks scan every push for credential leaks across multiple patterns.

The most valuable contributions at this stage are: additional NIST test vectors that exercise SHA-3 edge cases; sandbox-escape proofs of concept against the TLE flavour (filed via `security@aixybertech.com` under coordinated disclosure); interoperability test cases against other SCITT Transparency Service implementations; prior-art citations the maintainer has missed in the PostgreSQL extension or audit-chain literature.

---

## Security

Security disclosures: **`security@aixybertech.com`**

PGP key fingerprint: `A65AF5B7F02C9EB5B98023D70DB861BBF30F0D7B`

Fetch the public key:

```
gpg --keyserver keys.openpgp.org --recv-keys A65AF5B7F02C9EB5B98023D70DB861BBF30F0D7B
```

For the full disclosure procedure, acknowledgement window, and safe-harbour terms, see [SECURITY.md](SECURITY.md).

---

## Maintainer

Maintainer: **Muhammad Zaid Naeem** — `zaidnaeem@aixybertech.com`

---

## Legal

`pg-qsag-audit` is licensed under the [Apache License 2.0](LICENSE). See the [NOTICE](NOTICE) file for required attribution and third-party component acknowledgements.

---

© 2026 AIXYBER TECH LTD (Company No. 16826340), trading as Neoxyber. Registered in England and Wales. ICO Registration: ZC071900. Released under the Apache License, Version 2.0.
