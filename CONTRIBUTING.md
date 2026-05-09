# Contributing to pg_qsag_audit

Thank you for your interest in contributing to `pg_qsag_audit`, part of the Q-SAG open-source substrate programme operated by AIXYBER TECH LTD (trading as Neoxyber).

This document explains how to contribute code, documentation, and ideas. It is short by design — the goal is to make contributing low-friction while keeping the project legally clean and technically sound.

---

## Before you start

1. **Read the [README](README.md)** to understand what this artefact does, where it sits in the broader Q-SAG substrate programme, and how the dual-flavour structure (`dist/tle/` for managed-cloud, `dist/pgrx/` for self-hosted) shapes the codebase.
2. **Read the [Code of Conduct](CODE_OF_CONDUCT.md)** — Contributor Covenant 2.1. Reports route to `[email protected]`.
3. **Read the [Security Policy](SECURITY.md)** if your contribution relates to security. Vulnerabilities go to `[email protected]` (PGP encryption recommended), not to public GitHub issues. Note: the SECURITY.md scope and the EU CRA Article 14 reporting cascade are the load-bearing security commitments — please familiarise yourself with what is and is not in scope before filing.

---

## Ways to contribute

In rough order of impact, the most valuable contributions to `pg_qsag_audit` are:

- **Additional NIST FIPS 202 Known Answer Test vectors.** Edge-case inputs that demonstrate or guard against SHA3-256 / SHA3-384 implementation bugs in either build flavour are some of the most valuable contributions to a project like this. Particularly welcome: 1-bit-shy and 1-bit-over rate-boundary inputs, padding-edge inputs, and Monte Carlo seeds that catch sponge-state regressions.
- **Sandbox-escape proofs of concept against the TLE flavour.** File via the CVD channel in [SECURITY.md](SECURITY.md), not as a public issue. We coordinate with AWS where a finding affects the `pg_tle` framework itself.
- **Interoperability test cases against other SCITT Transparency Service implementations.** Once v0.5 ships the SCITT Signed Statement emitter, cross-validation against other implementations (e.g. the SCITT Reference Implementation, Microsoft's SCITT prototypes) is high-value.
- **Prior-art citations we have missed.** The README's "Differences from existing implementations" table is hedged "to the best of our knowledge as of May 2026". We genuinely want to be falsified if you know of a counter-example. Open an issue with the citation.
- **Bug reports.** Open a GitHub Issue with a clear title, a minimal failing SQL or pgrx test case, the affected build flavour (`dist/tle/`, `dist/pgrx/`, or both), the PostgreSQL major version, the OpenSSL version (`SELECT version()` and `pg_config --configure | grep ssl`), and the `pg_qsag_audit` version, commit hash, or release tag where you observed the issue.
- **Feature proposals.** Open a GitHub Issue or Discussion describing the use case and rough design. For substantial changes (e.g., adding a new SQL surface function, adding support for an additional hash algorithm, adding a new build flavour beyond TLE and pgrx), expect to write or co-author an Architecture Decision Record (ADR) — see below.
- **Code submissions.** Fork the repository, create a feature branch, push your changes, and open a Pull Request. Details below.
- **Documentation improvements.** Same workflow as code. Documentation improvements are reviewed with the same care as source changes.
- **Pull request reviews.** Constructive technical review from anyone is welcome.

---

## Pull request workflow

### 1. Fork and clone

```
git clone https://github.com/<your-username>/pg_qsag_audit.git
cd pg_qsag_audit
git remote add upstream https://github.com/Neoxyber/pg_qsag_audit.git
```

### 2. Create a feature branch

Branch naming convention: `<type>/<short-description>`. Types: `feat/`, `fix/`, `docs/`, `test/`, `refactor/`, `chore/`. Add a flavour suffix when the change is scoped to one build flavour: `feat/sha3-384-tle`, `fix/dispatcher-binding-pgrx`.

```
git checkout -b fix/dispatcher-edge-case-fips-stripped-openssl
```

### 3. Make your changes

This is where the dual-flavour structure matters. Read the rules carefully.

- **Keep commits focused.** One logical change per commit. Multiple commits per PR are fine if each is independently coherent.
- **Decide which flavour(s) your change affects.** Most behavioural changes need to touch *both* `dist/tle/` (pure plpgsql) and `dist/pgrx/` (Rust + pgrx) so that the SQL-surface equivalence guarantee holds. PRs that update only one flavour will be flagged in review and you'll be asked to either (a) extend the change to the other flavour or (b) document explicitly in the PR description why the change is flavour-specific (e.g. a Rust-only memory-safety fix that has no plpgsql equivalent, or a plpgsql-only performance optimisation that doesn't apply to the pgrx flavour).
- **Follow the existing code style.** (Style guide will be expanded with v0.1.)
- **Add or update tests for any code change.** Every behavioural change must be covered by tests in both build flavours where applicable. SHA3 changes must include the corresponding NIST FIPS 202 KAT vectors. Dispatcher changes must include tests covering both the pgcrypto-available and pgcrypto-unavailable paths.
- **Update documentation if your change affects user-visible behaviour.** This includes the SQL surface in `dist/tle/README.md` and `dist/pgrx/README.md`, the threat model in `THREAT_MODEL.md`, the standards alignment in `STANDARDS.md`, and the conformance test corpus in `docs/conformance/test-vectors/`.
- **The TLE-vs-pgrx SQL-surface equivalence CI job must pass.** This job runs the same SQL test scenarios against both flavours and fails if they diverge in observable behaviour. If your change intentionally introduces a divergence (e.g. a deprecation in one flavour ahead of the other), document this in the PR and update the equivalence-job allowlist with justification.

### 4. Sign your commits (DCO)

Every commit must include a `Signed-off-by:` line attesting that you have the right to contribute the code under the project's Apache 2.0 licence. This is the **Developer Certificate of Origin** (DCO) — see https://developercertificate.org for the full text.

Add the sign-off automatically by using the `-s` flag:

```
git commit -s -m "fix(dispatcher): correctly fall back to plpgsql on FIPS-stripped OpenSSL"
```

The DCO sign-off looks like this in the commit message:

```
Signed-off-by: Your Name <[email protected]>
```

The name and email must match a real identity you can be reached at. Pull requests with unsigned commits will not be merged.

We do **not** require a Contributor License Agreement (CLA). Contributors retain copyright to their contributions and licence them to the project under Apache 2.0 via the DCO sign-off.

### 5. Sign your commits (GPG, recommended)

GPG signing is encouraged for all contributors and required for maintainer commits. If you have a GPG key configured, add `-S` to your commit:

```
git commit -S -s -m "fix(dispatcher): correctly fall back to plpgsql on FIPS-stripped OpenSSL"
```

This produces commits that show as "Verified" on GitHub, providing cryptographic attestation that the commit came from you.

The repository's pre-push hook (`qsag-secret-scan`, 33 patterns) runs automatically on every push and blocks pushes that contain credential-shaped strings. See `.pre-commit-config.yaml`.

### 6. Push and open a PR

```
git push origin fix/dispatcher-edge-case-fips-stripped-openssl
```

Then open a PR against `main` on GitHub. Fill in the PR template (forthcoming with v0.1) — at minimum:

- A clear summary of what changed and why.
- The specific NIST / IETF / OWASP / EU clause(s) the change implements or affects.
- The build flavour(s) the change touches (`dist/tle/`, `dist/pgrx/`, or both), with explicit justification if it is single-flavour.
- Links to any related issues, ADRs (per-artefact in this repo, or master-programme ADRs in the private `neoxyber-qsag` repo where relevant), or external standards.
- A note on testing performed, including which KAT vectors were added or updated, and which CI jobs were verified to pass locally.
- A note on any breaking changes (we use semantic versioning, and a single SHA3 fix may produce different bytes for previously-mishandled inputs, which by definition breaks any audit chain that committed to the buggy bytes).

### 7. Review

- The maintainer will review within roughly 7 days for non-trivial PRs.
- Discussion happens in line comments on the PR.
- Be open to feedback. Constructive disagreement is welcome and expected.
- Once approved, the maintainer will merge — typically as a squash-merge for clean history, occasionally as a merge commit when commit-by-commit history is meaningful.

---

## Architecture Decision Records (ADRs)

Substantial design changes — new public SQL surface, changes to the dispatcher binding, deviations from FIPS 202 / RFC 8785 / SCITT specifications, additions of new build flavours, anything that affects the threat model in `SECURITY.md` — must be accompanied by an ADR.

The Q-SAG substrate programme operates a **two-tier ADR structure** (locked in master ADR-0031 §4.1):

- **Per-artefact ADRs** live in this repository at `docs/decisions/`, starting with [ADR-0001](docs/decisions/ADR-0001-design.md) (forthcoming) and incrementing by one for every subsequent design decision specific to `pg_qsag_audit`. These document cryptographic choices, API surface, conformance criteria, threat model, and integration points specific to this artefact.
- **Master programme ADRs** live in the private `neoxyber-qsag` repository and track decisions affecting the substrate programme as a whole. The public-facing master ADR is [ADR-0031](https://github.com/Neoxyber/neoxyber-qsag) (programme lock; commit `5541d7b32e16b5a1da8b25e17a1c989cff049dde`). Public ADR amendments are documented in the master ADR's own Amendment Log section.

The ADR format (per-artefact or master) is:

- Header table (number, title, status, dates, author, approver, supersedes, superseded by, related ADRs, scope)
- Context (why this decision is being made now)
- Decision (what is being committed to)
- Consequences (what becomes true / false / required after this decision)
- Compliance and conformance (which standards / regulations this decision affects)
- References (primary sources, prior ADRs, related GitHub issues / PRs)

ADR numbering is sequential within each tier. ADRs are never deleted — they are superseded by later ADRs that explicitly reference the predecessor, or amended in place when the change is a same-day correction documented in the ADR's own Amendment Log (the latter pattern is rare and reserved for very-recent corrections; supersession is the default for non-trivial changes).

If you propose a change that needs an ADR but you are not sure how to write one, open a Discussion or draft PR — the maintainer will help you co-author it.

---

## Standards and conformance

`pg_qsag_audit` aligns with the following standards (the full alignment matrix lives in [STANDARDS.md](STANDARDS.md), forthcoming with v0.1):

- **NIST FIPS 202** — SHA-3 Standard. SHA3-256 and SHA3-384 are the v0.1 primary primitives.
- **NIST SP 800-185** — KMAC, TupleHash. Used in the keyed mode of `pg_qsag.dsep_hash`.
- **NIST CSWP 39** — Crypto Agility (final 19 December 2025). §3.2.3 negotiation-integrity binding implemented by the dispatcher.
- **NIST CNSA 2.0** — SHA-384 retained for NSS use; SHA3-384 permitted inside specific algorithms.
- **IETF RFC 8785** — JSON Canonicalisation Scheme (input encoding for hashing).
- **IETF SCITT** — `draft-ietf-scitt-architecture-22` (Signed Statement emitter at v0.5).
- **IETF COSE Receipts** — `draft-ietf-cose-merkle-tree-proofs-18` (inclusion-proof format at v0.5).
- **EU AI Act Regulation 2024/1689** — Article 12 (logging), Article 26 (deployer obligations).
- **EU CRA Regulation 2024/2847** — Article 14 (vulnerability reporting cascade).
- **PGXN v2** — RFC-2 (trunk binary distribution), RFC-3 (Meta Spec v2 with `contents` taxonomy supporting both TLE and loadable-module entries in one distribution), RFC-5 (release certification with JWS-signed META.json).

Contributions that affect standards-conformance must:

- Cite the specific NIST / IETF / EU clause the change implements or affects.
- Include or update conformance tests in `docs/conformance/test-vectors/`.
- Pass the official NIST FIPS 202 KAT corpus and any imported test corpora from upstream Keccak / SHA3 implementations.
- Update the bidirectional clause-to-test traceability matrix when adding new tests or behaviour.

---

## PGXN v2 publication intent

`pg_qsag_audit` is designed to be a flagship example of the [PGXN v2 multi-target distribution pattern](https://github.com/pgxn/rfcs/pull/3) (David Wheeler, Tembo). Both build flavours ship from a single repository under one canonical extension name (`pg_qsag_audit`), with a single `META.json` per RFC-3 Meta Spec v2 declaring both `dist/tle/` (TLE) and `dist/pgrx/` (loadable_module) entries via the `contents` taxonomy.

Contributions that affect the public surface should keep this in mind:

- The on-disk extension name (`pg_qsag_audit.control` filename and `CREATE EXTENSION pg_qsag_audit;` invocation) is shared across both flavours and matches the canonical PGXN registration name.
- Once PGXN v2 RFC-5 release certification ships in the SDK, every release publishes a JWS-signed `META.json` per RFC 7515 JSON Serialization. PRs that change the public surface change the signed payload, and the signing flow is part of the release-CI not the per-PR-CI.
- Once Trunk binary distribution per RFC-2 is supported, releases will additionally publish `.trunk` packages per platform. Cross-flavour trunk packaging is forward-track work, not v0.1.
- Supabase `dbdev` publishing of the TLE flavour uses the canonical name with a publisher prefix (`neoxyber@pg_qsag_audit`). The TLE-flavour dbdev manifest is generated from the same source tree as the PGXN distribution; do not introduce divergence between them without a master ADR justifying the split.

If your contribution affects how the artefact is packaged for any of these registries, raise it explicitly in the PR description so the release-CI implications can be reviewed.

---

## Style and tooling (v0.1 forthcoming)

The following will be enforced once v0.1 ships:

- **Rust (`dist/pgrx/`)**: `cargo fmt` for formatting, `cargo clippy --all-targets -- -D warnings` for linting, `cargo test` plus `cargo pgrx test` for tests.
- **PL/pgSQL (`dist/tle/`)**: `pg_format` (or equivalent) for formatting, `pgTAP` for tests, `pgindent` discipline for any C-language fragments.
- **SQL surface contracts**: a shared test suite that exercises the same SQL surface against both build flavours and fails if they diverge.
- **Markdown**: `markdownlint` with the project's configuration.
- **Pre-commit hooks**: `.pre-commit-config.yaml` runs the `qsag-secret-scan` library (33 patterns) before each push, scanning all files for credential-shaped strings.
- **CI**: GitHub Actions matrix on PostgreSQL 14, 15, 16, 17, 18 × OpenSSL 1.1.1, 3.0, 3.2 × x86_64 and aarch64. NIST FIPS 202 KAT corpus runs on every job. TLE-vs-pgrx SQL-surface equivalence runs on every job. CI fails on any KAT vector failure or any equivalence divergence.

Until v0.1, contributors should follow the conventions of the existing code in their PR.

---

## Communication

- **GitHub Issues**: bugs, feature requests, focused technical discussions on a single change.
- **GitHub Discussions** (when enabled): broader design discussions, questions, ideas not yet a concrete proposal.
- **Email**: `[email protected]` for general correspondence; `[email protected]` for public information; `[email protected]` for vulnerability disclosure (PGP recommended); `[email protected]` for Code of Conduct reports and director-direct correspondence.

We aim to acknowledge issues and PRs within 7 days. Substantive review may take longer for complex changes — particularly changes that touch the cryptographic primitives, the dispatcher binding, or the audit-chain hash linkage, all of which deserve careful review.

---

## Recognition

Contributors are credited in:

- The git history (DCO sign-off and GPG signature, where applicable).
- Release notes for the version in which their contribution shipped.
- The `CHANGELOG.md` entry for that release.
- The `CONTRIBUTORS.md` file (forthcoming with v0.1).

We do not currently operate a paid bug-bounty programme — see [SECURITY.md](SECURITY.md) for our roadmap on that.

---

## Legal summary

- All contributions are licensed under [Apache License 2.0](LICENSE).
- Contributors retain copyright to their contributions; the DCO sign-off licenses them to the project.
- The legal entity behind the project is AIXYBER TECH LTD (Company No. 16826340), trading as Neoxyber. Full company facts in [COMPANY_FACTS.md](COMPANY_FACTS.md).

---

*Maintainer: Muhammad Zaid Naeem (Neoxyber) — [email protected]*

*© 2026 AIXYBER TECH LTD (Company No. 16826340), trading as Neoxyber. Registered in England and Wales. ICO Registration: ZC071900. Released under the Apache License, Version 2.0.*
