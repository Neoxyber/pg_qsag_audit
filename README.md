# pg_qsag_audit

> Portable, KAT-verified, sandbox-safe SHA3 plus audit-chain primitives for PostgreSQL. Ships as both pg_tle (managed-cloud) and pgrx-native (self-hosted) builds in a single canonical repository. Part of the Q-SAG open-source substrate programme.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Status](https://img.shields.io/badge/status-v0.0.0%20scaffolding-orange.svg)](#status)
[![Standards](https://img.shields.io/badge/standards-FIPS%20202%20%7C%20RFC%208785%20%7C%20SCITT%20%7C%20OWASP%20ASI%202026-informational.svg)](#standards)

`pg_qsag_audit` is the third artefact in the Q-SAG open-source substrate programme — a family of post-quantum cryptographic and audit primitives for AI-agent governance, designed for the 2027-and-onwards horizon. The substrate is maintained by AIXYBER TECH LTD (trading as Neoxyber) under [Apache License 2.0](LICENSE).

---

## What this artefact does

`pg_qsag_audit` adds a portable, deterministic, sandbox-safe SHA3 path to PostgreSQL, plus the audit-chain primitives that downstream Q-SAG components rely on. It ships in two build flavours from one source tree:

- **`dist/tle/`** — pg_tle SQL-only flavour. Compatible with managed-Postgres tiers (AWS RDS, Aurora, Supabase) where unprivileged extensions are the only option. Closes the day-one deployment gap for the Phase 0 development environment.
- **`dist/pgrx/`** — pgrx-native Rust flavour. Full SHA3 + audit-chain primitives at C-speed. Targets self-hosted Postgres (Scaleway, Civo, on-prem) from Phase 1 onward.

Both flavours share the same SQL surface, the same SECURITY policy, the same NIST FIPS 202 KAT corpus, the same maintainer GPG signing identity, and one canonical PGXN registration. Migration between flavours requires no application change.

At v0.1, the published SQL surface includes:

- **`pg_qsag.sha3_256(input bytea) returns bytea`** and **`pg_qsag.sha3_384(input bytea) returns bytea`** — pure-plpgsql Keccak-f[1600] sponge construction in the TLE flavour, native pgrx wrappers over a vetted Rust Keccak crate in the pgrx flavour. Both flavours pass the full FIPS 202 short-message and Monte Carlo KAT corpus.
- **`pg_qsag.digest(input bytea, algo text) returns bytea`** — agility-aware dispatcher. When `pgcrypto` is present and OpenSSL exposes the requested SHA3 algorithm (which it has done since OpenSSL 1.1.1, September 2018), the dispatcher routes to `pgcrypto.digest()` for full-speed evaluation. When `pgcrypto` is absent or the algorithm is missing, the dispatcher falls back to the in-extension implementation. The dispatch decision is logged into the audit chain as a NIST CSWP-39 §3.2.3-aligned negotiation-integrity record so that the choice of implementation is itself part of the auditable trail.
- **`pg_qsag.dsep_hash(domain text, payload bytea, algo text) returns bytea`** — domain-separated hashing per `H(len_BE32(domain) || domain || payload)`, with optional KMAC-style keyed mode (NIST SP 800-185).
- **`pg_qsag.canon_jsonb(input jsonb) returns bytea`** — RFC 8785 JCS canonical encoding for jsonb inputs. Identical semantic inputs always produce identical hashes regardless of key ordering. (At v0.1 this is a thin SQL wrapper that delegates to the application-tier `qsag-canonical` Python implementation; in v0.2 it becomes a self-contained pure-pgrx implementation.)
- **`pg_qsag.append(stream uuid, payload jsonb) returns bigint`** — append an audit event to a hash-chained stream. Computes `H = SHA3-384(prev || H_event)` where `H_event = SHA3-384(canonical_jsonb || domain_separator)`. Writes to `pg_qsag.audit_chain`.
- **`pg_qsag.verify_chain(stream uuid) returns (ok boolean, first_break_seq bigint)`** — verify the integrity of a hash chain end-to-end. Returns `(true, NULL)` for an intact chain; returns `(false, n)` pointing at the first broken link if the chain has been tampered with.
- **NIST FIPS 202 KAT corpus** embedded as a regression suite (`pg_qsag.run_kats()` returns the per-vector pass/fail map at install time).

At v0.5, the artefact's headline novelty layer ships:

- **Merkle-tree accumulator** with logarithmic-length consistency and inclusion proofs over the audit chain (Crosby & Wallach 2009 USENIX Security pattern, applied to a pgrx-resident history tree).
- **COSE-Receipts inclusion-proof emitter** per IETF `draft-ietf-cose-merkle-tree-proofs-18`.
- **SCITT Signed Statement emitter** per IETF `draft-ietf-scitt-architecture-22`. To the best of our knowledge, no published Postgres extension emits SCITT-conformant Signed Statements directly from a trigger as of May 2026.
- **VACUUM / PITR / logical-replication-stable linkage** so the audit chain survives the standard Postgres operational lifecycle without false-positive break detection.
- **EU AI Act Article 12 export views** mapping per-event records to Article 12(3) fields with hash-chain proofs of completeness, plus a CRA Article 14 connector for ENISA-Single-Reporting-Platform-shaped exports.

## Why this gap matters

The "seven-year absence of SHA3 in PostgreSQL" is a story that has been told often. It is also, on inspection, more nuanced than the headline.

OpenSSL has provided SHA3 to `pgcrypto`'s `digest()` function via the EVP layer since OpenSSL 1.1.1 (September 2018). On a recent PostgreSQL build linked against a recent OpenSSL, `SELECT encode(digest('abc', 'sha3-256'), 'hex')` returns the canonical SHA3-256 of `'abc'` — with no third-party extension. The 2018 pgsql-hackers thread "need for SHA3" closed on this rationale: OpenSSL would carry it. That decision has held for over seven years, and it works for most users.

What that decision did not provide is what `pg_qsag_audit` provides:

1. **Documentation.** The PostgreSQL 14–18 `pgcrypto` documentation lists only `md5, sha1, sha224, sha256, sha384, sha512` as standard digest algorithms. SHA3 is silently available via the "any algorithm OpenSSL supports" clause but is not advertised. Most engineers and most auditors do not know it works. `pg_qsag_audit` advertises it explicitly, with KAT-verified behaviour and copy-pastable examples.
2. **Portability.** OpenSSL builds without SHA3 still exist (some legacy ARM toolchains, FIPS-stripped builds, certain Bitnami images). A pure-plpgsql fallback in the TLE flavour, KAT-verified to match the OpenSSL-backed result byte-for-byte, makes the SHA3 path portable to every supported PostgreSQL deployment regardless of the OpenSSL build configuration.
3. **Sandbox-safety on managed tiers.** `pg_tle` (AWS Trusted Language Extensions) forbids C extensions on RDS, Aurora, and Supabase managed Postgres. The TLE flavour of `pg_qsag_audit` ships SHA3 plus the audit-chain primitives in pure plpgsql, deployable on every managed tier where `pg_tle` itself is supported. No customer-managed C-extension installation required.
4. **Regulatory readiness.** EU AI Act Article 12 (full force 2 August 2026), CRA Article 14 (vulnerability reporting from 11 September 2026), eIDAS 2 EUDI Wallets (member-state availability late 2026), and CNSA 2.0 (procurement gate 1 January 2027) all converge on one engineering requirement: tamper-evident logs with cryptographically-agile, post-quantum-aware hash functions, anchored at the database tier where the data lives. `pg_qsag_audit` ships the primitives for that requirement at the v0.1 surface and the headline differentiator (SCITT Signed Statement emission from a Postgres trigger) at v0.5.
5. **Negotiation-integrity binding.** NIST CSWP 39 §3.2.3 (final 19 December 2025) requires that the choice of cryptographic implementation be cryptographically bound to the audit trail of the decisions it produces. The `pg_qsag.digest()` dispatcher logs the dispatch decision (pgcrypto vs in-extension fallback) into the audit chain itself. To the best of our knowledge, no published Postgres extension implements this discipline as of May 2026.

The defensible novelty of `pg_qsag_audit` lies not in adding SHA3 to PostgreSQL — `pgcrypto` and OpenSSL already cover that path for the majority case — but in providing a **portable, KAT-verified, sandbox-safe, dispatcher-aware, regulator-ready** SHA3 + audit-chain layer that works identically across managed and self-hosted Postgres tiers, and in the SCITT/COSE-Receipts/Merkle-accumulator layer scheduled for v0.5.

## Status

This repository is at **v0.0.0 — scaffolding**. The repository structure, ADR discipline, security posture, dual-flavour build-target layout, and contribution guidelines are in place. The v0.1 implementation is in progress. The TLE flavour is targeted to ship first (the simpler primitive surface, immediately deployable on Supabase/RDS for Phase 0 development). The pgrx-native flavour follows. Both v0.1 builds are scheduled across **May–June 2026** per the locked Q-SAG substrate programme roadmap (ADR-0031 §3, amended 9 May 2026).

Q-SAG itself is under active development. This artefact is being built as part of that ongoing work. Production use is not recommended until v0.5 at the earliest, by which point the conformance test corpus will have been audited against the official NIST FIPS 202 KAT corpus, the Merkle-accumulator implementation will be reviewed against the Crosby-Wallach reference, and the SCITT Signed Statement emitter will have been validated against the SCITT Reference Implementation.

## Installation

> v0.0.0 ships scaffolding only; functional installation paths land at v0.1.

When v0.1 ships, the dual-flavour structure means there are two install paths — one for managed-cloud users, one for self-hosted users — and the choice is made at deploy time, not at code time.

### Managed cloud (AWS RDS, Aurora, Supabase) — TLE flavour

```sql
-- Once dbdev publication lands at v0.1:
SELECT dbdev.install('neoxyber@pg_qsag_audit');
CREATE EXTENSION pg_qsag_audit;
```

Or, on RDS/Aurora using the AWS pg_tle framework directly, the TLE will install via `pgtle.install_extension()` from the `dist/tle/` distribution.

### Self-hosted PostgreSQL — pgrx-native flavour

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

Both flavours expose identical SQL surfaces. An audit chain populated under one flavour can be read and verified under the other; migration requires no re-hashing of the existing chain.

## Quick start

> Not yet available. v0.1 will include a minimal end-to-end example demonstrating: (1) creating an audit-chain stream, (2) appending a hash-chained event, (3) verifying the chain's integrity, (4) inspecting the dispatch decision log.

## Documentation

- [Threat model](THREAT_MODEL.md) — what this artefact defends and what it does not (forthcoming with v0.1)
- [Standards alignment](STANDARDS.md) — FIPS 202, FIPS 204/205, RFC 8785, SCITT, COSE Receipts, EU AI Act Article 12, CRA Article 14, CSWP 39 mappings (forthcoming with v0.1)
- [Architecture](docs/architecture.md) — design overview, dual-flavour build-target layout, dispatcher state machine (forthcoming with v0.1)
- [Architecture Decision Records](docs/decisions/) — ADR-0001 design decision and onward (forthcoming with v0.1)
- [Conformance test vectors](docs/conformance/test-vectors/) — official NIST FIPS 202 KAT corpus, plus the bidirectional clause-to-test traceability matrix (forthcoming with v0.1)
- [TLE flavour install guide](dist/tle/README.md) — managed-cloud deployment via dbdev or `pg_tle` (forthcoming with v0.1)
- [pgrx flavour install guide](dist/pgrx/README.md) — self-hosted deployment via PGXN or source (forthcoming with v0.1)

## Standards

`pg_qsag_audit` aligns with the following standards:

- **NIST FIPS 202** — SHA-3 Standard (SHA3-256 and SHA3-384 are the primary primitives at v0.1)
- **NIST SP 800-185** — KMAC, TupleHash (used in the keyed-mode of `pg_qsag.dsep_hash`)
- **NIST CSWP 39** — Crypto Agility (final 19 December 2025; §3.2.3 negotiation-integrity binding implemented by the dispatcher)
- **NIST CNSA 2.0** — SHA-384 retained for NSS use; SHA3-384 permitted inside specific algorithms
- **IETF RFC 8785** — JSON Canonicalisation Scheme (input encoding for hashing)
- **IETF SCITT** — `draft-ietf-scitt-architecture-22` (Signed Statement emitter at v0.5)
- **IETF COSE Receipts** — `draft-ietf-cose-merkle-tree-proofs-18` (inclusion-proof format at v0.5)
- **EU AI Act Regulation 2024/1689** — Article 12 (logging), Article 26 (deployer obligations)
- **EU CRA Regulation 2024/2847** — Article 14 (vulnerability reporting cascade)
- **PGXN v2** — RFC-2 (trunk binary distribution), RFC-3 (Meta Spec v2 with `contents` taxonomy supporting both TLE and loadable-module entries in one distribution), RFC-5 (release certification with JWS-signed META.json)

Detailed clause-level mappings live in [STANDARDS.md](STANDARDS.md) (forthcoming with v0.1).

## Differences from existing implementations and related projects

| Project | Layer | SHA3 in SQL | Sandbox-safe TLE | Dispatcher with audit binding | Hash-chained audit primitive | SCITT Signed Statement emitter |
|---|---|---|---|---|---|---|
| **pg_qsag_audit** | Postgres extension (TLE + pgrx) | Yes | Yes | Yes (CSWP 39 §3.2.3) | Yes (v0.1) | Yes (v0.5) |
| `pgcrypto` + OpenSSL EVP | Postgres core contrib | Yes (via "any OpenSSL algorithm" clause, undocumented) | No (C extension) | No | No | No |
| `pgaudit` | Postgres extension (C) | No | No | No | No (text logging only) | No |
| `immudb` + `pgaudit` integration | Two-database architecture | N/A (immudb-side hashing) | No | No | Yes (immudb-side) | No |
| `pg_credereum` (PostgresPro prototype) | Postgres extension prototype | No | No | No | Partial (blockchain-style) | No |
| Madhwal et al. BIOTC 2021 | Python + Postgres prototype | Application-tier | N/A | No | Yes (Merkle-style) | No |

`pg_qsag_audit` does not replace `pgcrypto`, `pgaudit`, or `immudb`. It complements them. The closest commercial prior art (`pgaudit` + `immudb`) is a two-database architecture; `pg_qsag_audit` keeps the database boundary intact. The closest academic prior art (Madhwal et al., *Blockchain Extension for PostgreSQL Data Storage*, ACM BIOTC 2021) is a Python-side prototype; `pg_qsag_audit` is in-database with PGXN packaging discipline. The closest in-database prototype (`pg_credereum`) does not provide SCITT/COSE Receipts emission or NIST CSWP-39 dispatcher binding.

If you know of a project we have missed, please open an issue. The "to the best of our knowledge as of May 2026" caveats above are honest about the state of our research; they should be falsified if better information exists.

## Related artefacts

`pg_qsag_audit` is one of ten sibling artefacts in the Q-SAG open-source substrate programme. The full list, in shipping order per the amended ADR-0031 §2.2:

1. [qsag-anchors](https://github.com/Neoxyber/qsag-anchors) — federated SCITT Transparency Service primitives
2. [qsag-canonical](https://github.com/Neoxyber/qsag-canonical) — strict RFC 8785 JCS implementation in Python
3. **pg_qsag_audit** *(this repository)* — portable, KAT-verified, sandbox-safe SHA3 + audit-chain primitives for PostgreSQL (TLE flavour and pgrx-native flavour in one canonical repository)
4. [qsag-pq-primitives](https://github.com/Neoxyber/qsag-pq-primitives) — PyO3 wrapper, profile-aware dispatch over liboqs and RustCrypto
5. [qsag-evidence](https://github.com/Neoxyber/qsag-evidence) — regulator-facing audit-pack export (EU AI Act Annex IV, DORA, CRA SRP, C2PA 2.3)
6. [qsag-ocsf](https://github.com/Neoxyber/qsag-ocsf) — OCSF v1.8.0 ai_operation event emitter
7. [qsag-cascade](https://github.com/Neoxyber/qsag-cascade) — verifiable cascading-kill primitive
8. [qsag-coalition](https://github.com/Neoxyber/qsag-coalition) — graph-based coalition / Sybil detection
9. [qsag-aibom](https://github.com/Neoxyber/qsag-aibom) — CycloneDX 1.6 + SPDX 3.0 + EAT-AI emitter
10. [qsag-confidential](https://github.com/Neoxyber/qsag-confidential) — TEE attestation receipt format

Three big-bet artefacts (`qsag-mca` threshold ML-DSA master-control-authority, `qsag-a2a-verifier` runtime A2A/MCP descriptor verifier, `qsag-escalation` cryptographically-witnessed external escalation channel) are reserved per ADR-0031 §2.3 and ship in 2026 H2 conditional on funding and on successful execution of the ten core artefacts.

## Contributing

We welcome contributions from the cryptography, PostgreSQL extension, SCITT, and AI-agent-governance communities. Before contributing, please read:

- [Contributing guide](CONTRIBUTING.md) — DCO sign-off, PR process, ADR discipline (forthcoming with v0.1)
- [Code of Conduct](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
- [Security policy](SECURITY.md) — coordinated vulnerability disclosure (forthcoming with v0.1)

All commits must be DCO-signed (`git commit -s`). Maintainer commits are additionally GPG-signed with the maintainer's published Ed25519 key. Pre-push hooks scan every push for credential leaks across 33 patterns; see `.pre-commit-config.yaml`.

The most valuable contributions to this artefact, in rough order of impact: (1) additional KAT vectors that demonstrate or guard against SHA3 implementation bugs; (2) sandbox-escape proofs of concept against the TLE flavour (filed via `[email protected]` under coordinated disclosure); (3) interoperability test cases against other SCITT Transparency Service implementations; (4) prior-art citations we have missed in the Differences-from-existing-implementations table.

## Security

Security disclosures: **[email protected]**

PGP key fingerprint: `A65AF5B7F02C9EB5B98023D70DB861BBF30F0D7B`

Fetch the public key:

```
gpg --keyserver keys.openpgp.org --recv-keys A65AF5B7F02C9EB5B98023D70DB861BBF30F0D7B
```

For full disclosure procedure, acknowledgement window, safe-harbour terms, and EU CRA Article 14 reporting cascade alignment, see [SECURITY.md](SECURITY.md) (forthcoming with v0.1).

`pg_qsag_audit` does not provide side-channel resistance. The TLE flavour runs in interpreted plpgsql; the pgrx flavour runs in a Rust process inside the Postgres backend without constant-time guarantees. Do not feed secret-dependent inputs (such as session keys or unblinded private-key material) to its hashing primitives. Use it for audit-event content hashing and Merkle accumulation, where inputs are by hypothesis non-secret.

## Maintainer

Maintainer: **Muhammad Zaid Naeem (Neoxyber)** — [email protected]

## Legal

`pg_qsag_audit` is licensed under the [Apache License 2.0](LICENSE). See the [NOTICE](NOTICE) file for required attribution and third-party component acknowledgements (forthcoming with v0.1, including Keccak Code Package, tiny_sha3 reference, NIST CAVP test vectors, AWS pg_tle, PostgreSQL pgcrypto, and Madhwal et al. BIOTC 2021 academic prior-art citation).

For company facts (legal entity, registration, ICO), see [COMPANY_FACTS.md](COMPANY_FACTS.md).

The hosted Q-SAG demo at [qsag.neoxyber.com](https://qsag.neoxyber.com) is provided free of charge for research, education, and testing purposes only. It is not a commercial product, has no SLA, and is not suitable for production deployment on safety-critical systems.

---

© 2026 AIXYBER TECH LTD (Company No. 16826340), trading as Neoxyber.
Registered in England and Wales. ICO Registration: ZC071900.
Released under the Apache License, Version 2.0.
