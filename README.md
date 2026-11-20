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
