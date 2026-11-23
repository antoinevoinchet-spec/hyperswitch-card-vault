# Hyperswitch Card Vault - Rust Locker

> [!WARNING]
> **Unofficial fork — study project.** This is a personal fork of [juspay/hyperswitch-card-vault](https://github.com/juspay/hyperswitch-card-vault). It is not affiliated with or endorsed by Juspay.
> This code is not audited and not PCI DSS compliant: do not use in production, and never store real card or personal data in it.
> Development on this fork is done with an AI coding assistant (Claude Code).

## About this fork

The code in this repository is modified from the original [juspay/hyperswitch-card-vault](https://github.com/juspay/hyperswitch-card-vault). It remains under the original Apache-2.0 license (see [LICENSE](./LICENSE)). Changes made in this fork are listed below.

### Changes from the original

- `README.md`: added this notice and section; reworded the overview so that it makes no compliance claim.
- `CLAUDE.md`: added working rules for the AI coding assistant.
- `.github/workflows/CI-pr.yml`: removed the steps that used the upstream bot's secrets to push automatic formatting and `Cargo.lock` fixes; formatting and `Cargo.lock` are now checked only, and the workflow token is read-only.
- Audit log (one metadata-only entry per vault operation, written to a new `audit_log` table; an operation whose entry cannot be written returns an error):
  - `src/audit.rs`: new module with the entry types, the append-only sink trait, the fail-closed `record` function and its tests.
  - `migrations/2026-11-20-000000_create_audit_log/up.sql` and `down.sql`: new migration creating and dropping the `audit_log` table.
  - `src/storage/schema.rs`: added the `audit_log` table.
  - `src/storage/db.rs`: added the PostgreSQL implementation of the audit sink.
  - `src/storage/caching.rs` and `src/storage/caching/audit.rs`: forward audit writes through the cache layer without caching them.
  - `src/custom_extractors.rs`: added the `AuditRequestId` extractor.
  - `src/lib.rs`: registered the `audit` module.
  - `src/routes/data.rs`, `src/routes/routes_v2/data.rs`, `src/routes/entity.rs`, `src/routes/key_migration.rs`, `src/routes/key_custodian.rs`: each handler records its operation.
  - `docs/superpowers/specs/2026-11-20-audit-log-design.md` and `docs/superpowers/plans/2026-11-20-audit-log.md`: design and implementation plan.
- Demo, end-to-end tests and custodian audit rows (see [demo/README.md](./demo/README.md)):
  - `demo/run.sh` and `demo/README.md`: new one-command demo of a test card's journey, with the audit rows it leaves, and its explanation.
  - `Makefile`: added the `demo` target.
  - `tests/vault_e2e.rs`: new end-to-end tests that start the vault against a real PostgreSQL (card journey rows, fail-closed retrieve, custodian rows, refused custodian key).
  - `.github/workflows/CI-pr.yml`: added the `integration-db` job, which runs those tests and the demo against a PostgreSQL service; existing jobs are unchanged.
  - `src/tenant.rs`: added an audit-only storage per tenant, usable before the custodians unlock it.
  - `src/routes/key_custodian.rs`: `/custodian/key1`, `/custodian/key2` and a failed `/custodian/decrypt` now write an `audit_log` row, and a key is refused when its row cannot be written.
  - `src/audit.rs`: removed `emit_audit_event`, which had no caller left.
  - `src/storage.rs`: the database connection URI now percent-encodes the space in its `options` value, which libpq 18 and later reject (found by the new CI job), with a unit test.
  - `docs/tokenization.md`: new page on what the vault already does for tokenization.
  - `docs/superpowers/specs/2026-11-23-demo-and-ci-db-design.md` and `docs/superpowers/plans/2026-11-23-demo-and-ci-db.md`: design and implementation plan.
- Keyed duplicate-check hash (the hash of the card number kept in `hash_table` is now an HMAC-SHA512 under a key derived from the tenant master key, instead of a plain SHA-512):
  - `src/crypto/hash_manager/managers/sha.rs`: new `CardDedupHmac` type (HKDF-SHA512 key derivation and HMAC-SHA512, both from `ring`), with unit tests including an RFC 4231 vector.
  - `src/routes/data.rs`: `/data/add` uses `CardDedupHmac` instead of `Sha512` for the duplicate check.
  - `src/routes/data/transformers.rs`: unit test of `get_hash` with the keyed hash.
  - `tests/vault_e2e.rs`: two end-to-end tests (one row for a card stored by two merchants, replaced since by the merchant-scoped test below; the stored value is not a plain SHA-512).
  - `docs/tokenization.md`: describes the keyed hash, what happens to rows written before it, and updated line references.
  - `docs/superpowers/specs/2026-11-23-keyed-card-hash-design.md` and `docs/superpowers/plans/2026-11-23-keyed-card-hash.md`: design and implementation plan.
- Threat model table (each protection linked to the test that proves it, each known limit to the text that describes it):
  - `docs/threat-model.md`: new table of threats, attacks, controls, evidence and status.
  - `scripts/check-threat-model.sh`: new script that checks that every test, line and demo check cited in the table exists.
  - `.github/workflows/CI-pr.yml`: added the `threat-model` job, which runs that script on every pull request; existing jobs are unchanged.
  - `docs/tokenization.md`: added a link to the table.
  - `docs/superpowers/specs/2026-11-23-threat-model-table-design.md` and `docs/superpowers/plans/2026-11-23-threat-model-table.md`: design and implementation plan.
- Duplicate-check hash scoped to the merchant and customer (for rows written after this change, the same card stored by two merchants, or two customers of one merchant, no longer shares a hash row, so a database reader cannot link them; older rows are not converted):
  - `src/crypto/hash_manager/managers/sha.rs`: `CardDedupHmac::from_master_key` takes the merchant and customer ids, adds them to the HKDF context (now `v2`), each preceded by its length; unit tests for two merchants, two customers and unambiguous framing.
  - `src/routes/data.rs`: `/data/add` passes the merchant and customer ids of the request.
  - `src/routes/data/transformers.rs`: its unit test passes a scope.
  - `tests/vault_e2e.rs`: `same_card_for_two_merchants_gets_two_hash_rows` replaces the shared-row test; new tests show that a card known only to another merchant or customer takes the new-card path, and that a hash row written under the former tenant-wide context is not matched.
  - `docs/threat-model.md`: rows T24 and T25 proven, new evidence for T11, new open rows T28 (rows written before the change) and T29 (a caller's own deleted card), moved line references.
  - `docs/tokenization.md`: describes the scope, the remaining paths and the rows written before the change; updated line references.
  - `docs/superpowers/specs/2026-11-23-merchant-scoped-dedup-design.md` and `docs/superpowers/plans/2026-11-23-merchant-scoped-dedup.md`: design and implementation plan.
- Re-hash job for the duplicate-check hash (`utils rehash` recomputes every stored card's hash under the current master key and the merchant and customer scope, so the older rows of the previous entry are converted once it has run; it can be run again without harm, resumes after an interruption, and is recorded in the audit log):
  - `src/domain/hash.rs`: the job (one row at a time, state recomputed from the rows, an older duplicate of the same merchant and customer detached, unused hash rows deleted), its counts and their balance check, with unit tests.
  - `src/bin/utils.rs`: new `rehash` subcommand; custodian keys read from standard input; prints counts only.
  - `src/storage.rs`, `src/storage/db.rs`, `src/storage/caching/hash_table.rs`: storage primitives for the job (rows by cursor, update of a row's hash id, hash row by id, deletes of unused hash rows), forwarded by the cache, refused with the `kv` feature.
  - `src/audit.rs`: `rehash_row`, `rehash_cleanup` and `rehash_run` operations, with a unit test.
  - `src/routes/data.rs`: the hash helpers are visible inside the crate, so the job computes the hash exactly as `/data/add` does.
  - `src/routes/key_custodian.rs`: the function that unlocks the master key with the custodian keys is public, so the command unlocks it as the vault does.
  - `tests/vault_e2e.rs`: twelve end-to-end tests of the job (rows written before the scope, the older duplicate, the newer copy kept after a key change, a second run, an interrupted run, audit rows, an unwritable audit table during the rows and during the clean-up, rows under another master key, an empty tenant, wrong custodian keys, a batch size of 0).
  - `docs/threat-model.md`: T28 proven once the job has run, new evidence for T22 (still open: rotation is not implemented), T21 and T29 wording, new open row T30 (a run next to a live vault), moved line references.
  - `docs/tokenization.md`: describes the job, how to run it, what it leaves, and updated line references.
  - `docs/superpowers/specs/2026-11-23-rehash-job-design.md` and `docs/superpowers/plans/2026-11-23-rehash-job.md`: design and implementation plan.
- CI hygiene (a check of the dependencies, OpenSSF Scorecard as an unpublished report, and the two re-hash paths that were only compiled):
  - `deny.toml`: new cargo-deny configuration (known vulnerabilities of the RustSec database, accepted licenses, crates.io and two upstream git repositories as the only sources); the known vulnerabilities of the original code are listed with their reason until 2027-02-21.
  - `.github/workflows/dependencies.yml`: new workflow running that check on pull requests, on `main` and weekly.
  - `.github/workflows/scorecard.yml`: new workflow running OpenSSF Scorecard without publishing its results (no badge); the results stay in the run for 5 days.
  - `.github/workflows/CI-pr.yml`: added the jobs "Re-hash without the key_custodian feature" and "Re-hash refusal with the kv feature"; existing jobs are unchanged.
  - `tests/vault_e2e.rs`: the end-to-end tests also build without the `key_custodian` feature (the custodian-only tests are left out); new test `rehash_refuses_to_run_with_kv`.
  - `docs/threat-model.md`: T28 cites the new test and the run without custodians; new rows T31 (dependency check, not tested), T32 to T34 (open); moved line references.
  - `docs/tokenization.md`: the two re-hash paths are now tested, with the limit of the `kv` test; moved line references.
  - `docs/superpowers/specs/2026-11-23-hygiene-ci-design.md` and `docs/superpowers/plans/2026-11-23-hygiene-ci.md`: design and implementation plan.
- Master key rotation (`utils rotate-master-key` re-encrypts every merchant key of a tenant under a new master key, then recomputes every duplicate-check hash under it; it resumes after an interruption, refuses a mix of keys, and is recorded in the audit log; merchant keys and cards are not re-encrypted):
  - `src/domain/master_key.rs`: new module with the job (read-only check of every merchant row, rewrite with its audit entry first and a conditional update, final check, then the re-hash job), with unit tests.
  - `src/domain.rs`: registered the module.
  - `src/bin/utils.rs`: new `rotate-master-key` subcommand; keys read from standard input; prints counts only; a refused input is recorded as a failed run.
  - `src/storage.rs`, `src/storage/types.rs`, `src/storage/db.rs`, `src/storage/caching/merchant.rs`: storage primitives for the job (merchant rows by cursor, conditional update of a row's encrypted key), forwarded by the cache without caching.
  - `src/audit.rs`: `master_key_rotation_row` and `master_key_rotation_run` operations, with a unit test.
  - `tests/vault_e2e.rs`: thirteen end-to-end tests of the rotation (cards read back for two merchants, the former key opens no row, duplicates still detected, resume from a mixed state, wrong custodian keys, the same master key, a row under a third key, audit and output without a key, an unwritable audit table, an empty tenant, a batch size of 0, the `kv` refusal, an external key manager); `Vault::start` now calls a variant that takes extra environment variables.
  - `.github/workflows/CI-pr.yml`: added the jobs "Master key rotation without the key_custodian feature", "Master key rotation refusal with the kv feature" and "Master key rotation with an external key manager" (Juspay's Hyperswitch Encryption Service built from source at `v0.1.14`); existing jobs are unchanged.
  - `docs/threat-model.md`: T22 proven; T23 cites the external key manager test; new open rows T35 (former key with an older copy of the database) and T36 (the configuration change is manual); moved line references.
  - `docs/tokenization.md`: describes the rotation, how to run it, what it refuses, covers and leaves open; moved line references.
  - `docs/superpowers/specs/2026-11-23-master-key-rotation-design.md` and `docs/superpowers/plans/2026-11-23-master-key-rotation.md`: design and implementation plan.

## Demo

`make demo` shows the vault in a few seconds once built: two custodians unlock it (one wrong key
first), a public test card is stored, read back, fingerprinted and deleted, and the audit log is
printed with checks proving that it never holds the card number or a key. It needs Rust, PostgreSQL
14 or later, `jq`, `curl` and `openssl`, and leaves nothing behind. Each step is explained in
[demo/README.md](./demo/README.md). What the vault already does for tokenization is described in
[docs/tokenization.md](./docs/tokenization.md).

Which protections are proven, by which test, and which limits are still open: see the
[threat model table](./docs/threat-model.md).

## Overview

The Hyperswitch Card Vault is a highly performant and a secure vault to save sensitive data such as payment card details, bank account details etc.

It is designed in an polymorphic manner to handle and store any type of sensitive information making it highly scalable with extensive coverage of payment methods and processors.

Hyperswitch Card Vault stores personal identifiable information (PII) with encryption algorithms. Compliance with standards such as PCI DSS or GDPR is assessed for an audited operating organisation, not for source code; this fork makes no such claim.

Here's a quick guide to [Get Started](./docs/guides/setup.md) with setting up Hyperswitch Card Vault.

### How does Hyperswitch Card Vault work?

- Your application will communicate with Hyperswitch Card Vault via a middleware.
- All requests and responses to and from the middleware are signed and encrypted with the JWS and JWE algorithms.
- The locker supports CRD APIs on the /data and /cards endpoints - <API Reference to be linked>
- Cards are stored against the combination of merchant and customer identifiers.
- Internal hashing checks are in place to avoid data duplication.

![General Work Flow](./docs/imgs/general-block-diagram.png)

### Key Hierarchy

- Master Key - AES generated key to that is encrypted/decrypted by the custodian keys to run the locker and associated configurations.
- Custodian Keys - AES generated key that is used to encrypt and decrypt the master key. It broken into two keys (key 1 and key 2) and available with two custodians to enhance security.

![Key Hierarchy](./docs/imgs/locker-key-hierarchy.png)

### Setup Guide

Follow this guide to setup Hyperswitch Card Vault - [Get Started](./docs/guides/setup.md)
