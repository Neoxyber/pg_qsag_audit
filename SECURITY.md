# Security Policy

> **Coordinated Vulnerability Disclosure (CVD) for `pg_qsag_audit`** — part of the Q-SAG open-source substrate programme operated by AIXYBER TECH LTD (trading as Neoxyber).

We take security seriously. `pg_qsag_audit` is a database-tier audit-chain primitive: every event appended to its hash-chained audit log commits to bytes hashed via SHA3-384, and downstream Q-SAG components (qsag-anchors, qsag-evidence, the Q-SAG main application) verify those chains to detect tampering. A bug in the SHA3 implementation, in the dispatcher's negotiation-integrity binding, in the canonical input encoding, or in the chain-link computation cascades silently into audit-chain breaks that go undetected by `pg_qsag.verify_chain()`. Because audit chains exist precisely to detect tampering after a compromise, a silent tampering-pass is the worst possible failure mode for this artefact. Please disclose responsibly.

---

## Reporting a vulnerability

**Email:** `[email protected]`

**Encryption (strongly recommended):** Encrypt your report with our PGP key.

**PGP key fingerprint:** `A65AF5B7F02C9EB5B98023D70DB861BBF30F0D7B`

**Fetch the public key:**

```
gpg --keyserver keys.openpgp.org --recv-keys A65AF5B7F02C9EB5B98023D70DB861BBF30F0D7B
```

The key is an Ed25519 key issued to `Muhammad Zaid Naeem (AIXYBER TECH LTD) <[email protected]>`, valid until April 2028.

**Please include in your report:**

- A description of the vulnerability and the affected component(s), specifying which build flavour is affected: `dist/tle/` (pg_tle SQL-only), `dist/pgrx/` (pgrx-native Rust), or both.
- A minimal failing scenario — a SQL script or pgrx test case that demonstrates the bug end-to-end.
- The PostgreSQL major version, the OpenSSL version (`SELECT version()` and `pg_config --configure | grep ssl`), and the `pg_qsag_audit` version, commit hash, or release tag where you observed the issue.
- For dispatcher-related bugs: the contents of `pg_qsag.dispatch_log` for the affected session, demonstrating which dispatch path was taken when the bug manifested.
- For audit-chain bugs: the affected stream UUID, the sequence number where divergence appears, and the expected vs observed hash at that link.
- Any potential impact you are aware of (e.g., known Q-SAG deployments or third-party systems that rely on the chain integrity guarantee).
- Whether you have disclosed this elsewhere, and if so, when.
- How you would like to be credited (real name, handle, organisation, or anonymous).

**Please do not:**

- Open a public GitHub issue for security disclosures.
- Post details on social media, forums, or mailing lists before coordinated disclosure.
- Publish proof-of-concept inputs that produce silent chain-tampering passes on production systems before remediation.
- Test exploits against any Postgres instance you do not own or have explicit permission to test.

---

## What you can expect from us

| Stage | Target time | Notes |
|---|---|---|
| **Acknowledgement** | Within 72 hours | A human reply confirming receipt and assigning a tracking reference. |
| **Initial assessment** | Within 7 days | Severity triage, scope confirmation, and a target patch date. |
| **Status updates** | Every 14 days | Until the issue is resolved or otherwise closed. |
| **Coordinated disclosure window** | 90 days from acknowledgement | The default window for public disclosure of a fixed vulnerability. May be extended by mutual agreement for complex issues, or shortened for actively exploited vulnerabilities (see EU CRA Article 14 cascade below). |
| **Credit** | At public disclosure | We name reporters in release notes, the project changelog, and the GitHub Security Advisory unless the reporter prefers to remain anonymous. |

We commit to:

- Treating every report seriously, regardless of perceived severity.
- Not pursuing legal action against good-faith security research conducted in compliance with this policy.
- Working collaboratively with reporters on coordinated disclosure timing.
- Being transparent about our findings and the fix in public release notes once disclosure is appropriate.
- For SHA3-divergence and audit-chain-tampering bugs specifically: publishing the failing test scenario in our conformance test corpus once the fix lands, so other Postgres-extension implementations and downstream Q-SAG components can guard against the same class of bug.

### EU CRA Article 14 reporting cascade

EU Cyber Resilience Act Article 14 (Regulation 2024/2847) becomes operational on 11 September 2026 with the ENISA Single Reporting Platform. From that date, actively-exploited vulnerabilities in `pg_qsag_audit` follow the legally-mandated cascade rather than the 90-day default disclosure window:

| Stage | Target time from awareness | Audience |
|---|---|---|
| **Early warning** | 24 hours | ENISA Single Reporting Platform |
| **Detailed notification** | 72 hours | ENISA Single Reporting Platform |
| **Status update** | 14 days | ENISA Single Reporting Platform |
| **Final report** | At resolution | ENISA Single Reporting Platform plus public Security Advisory |

We coordinate with reporters on this cascade and will accelerate public disclosure when active exploitation is observed. Reporters do not need to file with ENISA themselves — that is our responsibility as the manufacturer under CRA. Reporters retain the option of independent public disclosure if our cascade response stalls, per the standard CVD escape valve.

---

## Safe harbour

We support good-faith security research. If you make a good-faith effort to comply with this policy, we will:

- Consider your research to be authorised in the meaning of the **UK Computer Misuse Act 1990 (Section 1)** and analogous legislation in your jurisdiction (including, for relevant cases, US Computer Fraud and Abuse Act and EU NIS2 / GDPR Art 32 considerations for security research).
- Not initiate civil or criminal proceedings against you for the research itself.
- Work with you if a third party (e.g., a managed-Postgres provider, a hosting provider, or a downstream Q-SAG operator) initiates legal action, to the extent we are able.

To benefit from this safe-harbour:

- Make a good-faith effort to avoid privacy violations, data destruction, and service disruption.
- Only test on infrastructure that you own, infrastructure provided by us for testing, or systems where you have explicit permission from the owner. **Do not test against managed-Postgres tiers (RDS, Aurora, Supabase, Cloud SQL, Azure Database for PostgreSQL, Neon, Crunchy Bridge) without authorisation from both us and the relevant cloud provider.**
- Do not access, copy, modify, or download user data beyond the minimum necessary to demonstrate the vulnerability.
- Report the vulnerability to us promptly via the channel above and do not disclose publicly until we have had a reasonable time to remediate, or until the EU CRA Article 14 cascade has run its course for actively-exploited vulnerabilities.

This safe-harbour does **not** apply if you:

- Violate any other applicable law (e.g., access systems you have no right to test, attempt to defraud, or harm a third party).
- Demand payment as a condition of disclosure (extortion).
- Knowingly disclose details of a vulnerability publicly before coordinated disclosure.

---

## Scope

**In scope:**

- The source code in this repository (`pg_qsag_audit`) at any released version or commit on the `main` branch, in both build flavours (`dist/tle/` and `dist/pgrx/`).
- Any binary artefacts published by the maintainer to PGXN, dbdev, or PostgreSQL APT/YUM repositories under the `pg_qsag_audit` name.
- Bugs in the SHA3-256 or SHA3-384 implementation in either build flavour that produce output diverging from the NIST FIPS 202 Known Answer Test corpus.
- Bugs in `pg_qsag.digest()` (the dispatcher) that produce a dispatch decision inconsistent with the NIST CSWP 39 §3.2.3 negotiation-integrity binding — for example, dispatching to the in-extension fallback while logging a pgcrypto dispatch decision, or vice versa.
- Bugs in the audit-chain primitive that allow tampering with appended events without `pg_qsag.verify_chain()` reporting the break (the worst-case silent-pass failure mode).
- Bugs in `pg_qsag.canon_jsonb()` (RFC 8785 JCS canonical input encoding) that produce divergent canonical bytes for the same input.
- Bugs in `pg_qsag.dsep_hash()` (NIST SP 800-185 KMAC keyed-mode and TupleHash domain separation).
- Denial-of-service vulnerabilities: stack-overflow on deeply-nested input, quadratic behaviour on adversarial inputs, memory exhaustion, infinite loops in either build flavour.
- Memory-safety issues in the pgrx-native flavour (use-after-free, double-free, out-of-bounds access, data races).
- Sandbox-escape against the TLE flavour. **Note**: the trusted-language sandbox in `pg_tle` is implemented and maintained by AWS, not by us. Sandbox-escape against the framework itself should also be reported to AWS via `[email protected]` and to us; we will coordinate.

**Out of scope:**

- Vulnerabilities in `pgcrypto` itself or in OpenSSL — please report to the PostgreSQL Global Development Group at `[email protected]` and the OpenSSL project at `[email protected]` respectively. We will track upstream fixes and update our dispatcher accordingly.
- Vulnerabilities in the `pg_tle` framework itself — please report to AWS at `[email protected]`. We will coordinate.
- Vulnerabilities in `liboqs`, `RustCrypto`, the Ascon reference, the Keccak Code Package, or other upstream cryptographic libraries — please report to the relevant upstream project. We will track and update our pinned versions as upstream fixes ship.
- Theoretical attacks on SHA3 / Keccak itself — please report to NIST and to the Keccak design team. We will revisit our algorithm choices if the academic consensus shifts.
- Theoretical attacks on RFC 8785, SCITT, or COSE Receipts — please report to the relevant IETF working group. We will track and update.
- Social engineering, physical attacks, or denial-of-service attacks against our infrastructure (`qsag.neoxyber.com`, `github.com/Neoxyber`).
- Vulnerabilities affecting versions of `pg_qsag_audit` that are no longer supported (typically anything older than the most recent stable minor release once we reach v1.0).
- Reports that consist only of automated scanner output without a working proof of concept against this extension.

---

## Specific security model

This artefact's security claims are precise; please read them carefully before reporting.

**We rely on `pg_tle`'s trusted-language sandbox for installability, not for confidentiality.** The TLE flavour ships in pure plpgsql so that it can be installed on managed-Postgres tiers where C extensions are forbidden. We do not depend on the sandbox to protect the *confidentiality* of inputs to our hashing primitives. If you find a `pg_tle` sandbox-escape, that is a vulnerability against `pg_tle` (and we'll help coordinate); but a sandbox-escape that exposes the inputs to our hashing primitives is not, by itself, a vulnerability against `pg_qsag_audit`'s claimed security properties — those inputs are by hypothesis non-secret audit-event content.

**We do not claim side-channel resistance.** The TLE flavour runs in interpreted plpgsql with substantial per-statement overhead; constant-time guarantees are not achievable in this language. The pgrx-native flavour runs in a Rust process inside the Postgres backend without constant-time bytecode emission. Side-channel attacks (timing, cache, power, memory pressure) on either flavour are documented out-of-scope. **Do not feed secret-dependent inputs (such as session keys, unblinded private-key material, or password hashes) to `pg_qsag_audit`'s hashing primitives.** Use it for audit-event content hashing and Merkle accumulation, where inputs are by hypothesis non-secret. Reports of timing variability on non-secret inputs are useful as performance issues but are not vulnerability disclosures.

**KAT-corpus integrity is checked at install time.** Both build flavours run `pg_qsag.run_kats()` on extension creation and refuse to load if any FIPS 202 vector fails. This catches build-time corruption of the corpus or upstream-library changes that drift from FIPS 202 conformance. The published SHA-256 of the embedded test-vector blob is recorded in the repository and is cross-checkable at install time.

**The audit chain is tamper-evident, not tamper-proof.** A sufficiently privileged attacker (Postgres superuser, or someone with write access to the database server's filesystem) can rewrite history. What `pg_qsag_audit` provides is *evidence* that history has been rewritten: `pg_qsag.verify_chain()` will report the first break in the chain. Tamper-proofness requires anchoring the chain externally (qsag-anchors handles this) or in append-only storage (out of scope for this extension).

**The dispatcher's binding is forensic, not preventative.** The CSWP 39 §3.2.3 negotiation-integrity record in the audit chain documents which implementation was used for each hash. It does not prevent an attacker from forcing a dispatch to a weaker path; it ensures that if such a forcing occurs, the audit chain records it.

---

## What is **not** a vulnerability

The following are not vulnerabilities for the purposes of this policy and do not warrant a CVD report:

- Performance differences between the TLE flavour and the pgrx-native flavour. The TLE flavour is expected to be 2–3 orders of magnitude slower than pgcrypto (it implements Keccak-f[1600] in interpreted plpgsql) and is documented as such in `BENCHMARKS.md`. These are by design, not bugs.
- Differences in OpenSSL EVP availability across managed-Postgres tiers. Some tiers ship FIPS-stripped OpenSSL builds without SHA3 in the EVP layer; the dispatcher correctly falls back to the in-extension implementation in those cases. This is the dispatcher working as designed.
- The `pg_tle` framework's own performance and sandbox limitations. These are upstream concerns.
- The fact that `pg_qsag_audit` does not provide side-channel resistance, does not provide tamper-proofness, and does not provide confidentiality of inputs. These are documented out-of-scope and are not bugs.
- The fact that `pg_qsag_audit` cannot prevent a Postgres superuser from rewriting the audit chain. The chain is tamper-evident, not tamper-proof. Anchor the chain externally (qsag-anchors) for tamper-proofness.
- API design preferences ("you should support feature X"). These belong in regular GitHub issues or Discussions.
- Compliance gaps (e.g., "you should be ISO 42001 certified", "you should be in scope for FIPS 140-3 validation"). These belong in regular GitHub issues. Compliance certification is a v1.0 deliverable.

---

## Bug bounty programme

We do not currently operate a paid bug bounty programme. We expect to add one once Tier 1 grant funding lands (target Q3 2026) and earmarks a portion for security research compensation. Until then, all CVD work is unpaid; we credit reporters publicly and offer letters of recommendation for academic and professional contexts.

---

## Hardening commitments

We commit to the following ongoing security practices for `pg_qsag_audit`:

- Every commit on the `main` branch is GPG-signed by the maintainer (fingerprint above) and DCO-signed (`Signed-off-by` trailer).
- Every push is scanned by the `qsag-secret-scan` pre-push hook (33 patterns covering API keys, OAuth tokens, private keys, cloud-provider credentials, database connection strings, JWT secrets, signing keys, and high-entropy strings).
- Every release is GPG-signed by the maintainer.
- Every release is Sigstore-signed via GitHub Actions OIDC; the Rekor v2 transparency-log entry is recorded.
- Every release ships with a CycloneDX 1.6 SBOM.
- Every release ships with SLSA Level 3 build provenance via `slsa-framework/slsa-github-generator`.
- Every release publishes a PGXN v2 RFC-5-conformant JWS-signed `META.json` once the PGXN v2 SDK supports it (target: align with the SDK's first stable release).
- Dependencies are pinned and audited; updates are applied within 14 days for any advisory rated High or Critical.
- We participate in the GitHub Security Advisory database and assign CVE numbers via GitHub's CNA process for every accepted vulnerability.
- Every fixed SHA3-divergence, dispatcher-binding, or audit-chain-tampering bug is committed to the public conformance test corpus as a regression test, citing the discovery and the affected versions.
- The full NIST FIPS 202 Known Answer Test corpus runs on every CI job; CI fails if any vector fails.
- The TLE flavour and the pgrx-native flavour are tested for SQL-surface equivalence on every CI job; CI fails if a divergence is detected.

---

## Contact summary

| Purpose | Address |
|---|---|
| **Security disclosures (PGP recommended)** | [email protected] |
| **PGP fingerprint** | `A65AF5B7F02C9EB5B98023D70DB861BBF30F0D7B` |
| **General correspondence** | [email protected] |
| **Code of Conduct reports** | [email protected] |
| **Public information** | [email protected] |

---

*Maintainer: Muhammad Zaid Naeem (Neoxyber). For company details see [COMPANY_FACTS.md](COMPANY_FACTS.md).*

*© 2026 AIXYBER TECH LTD (Company No. 16826340), trading as Neoxyber. Registered in England and Wales. ICO Registration: ZC071900. Released under the Apache License, Version 2.0.*
