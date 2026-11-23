# Master key rotation (T22): design

Date: 2026-11-23 (UTC). Branch: `feat/master-key-rotation`, from `main` at `e203ed5`. Status:
decisions R1 and R2 taken by the owner; plan to follow in `docs/superpowers/plans/2026-11-23-master-key-rotation.md`.

## Intent

A tenant's master key cannot be changed today. Changing its value would make every merchant key
unreadable, so every stored card, and would change every duplicate-check hash (T22, `open`). A key
that cannot be changed stays exposed for as long as it lives: after a custodian leaves, after a
suspected leak, or on a schedule. This ticket adds a rotation of the master key and proves each
effect with a test that fails when the control it describes is removed. This is a study fork; see
`CLAUDE.md` for what may not be claimed about it.

Research reused: grand-angle report of 2026-11-23 on this ticket, kept outside the repository (ideas
I1, I2, I3 and I6 adopted, I7 rejected, I4 asked as R1, I5 and I8 left for later). Comparable
products, read on 2026-11-23:

- HashiCorp Vault Transit separates `rotate` (new key version), `rewrap` (re-encrypts a ciphertext
  under the newest version without returning the plaintext) and raising `min_decryption_version`
  (older versions stop decrypting): https://developer.hashicorp.com/vault/api-docs/secret/transit.
  Vault's `operator rekey` changes the unseal key shares only, and can require the new shares to be
  entered again before it switches: https://developer.hashicorp.com/vault/api-docs/system/rekey.
- Azure Key Vault and Google Cloud KMS rotate the key that wraps data keys; data already encrypted is
  not re-encrypted, and destroying a version still in use loses data:
  https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation (updated
  2026-06-12), https://docs.cloud.google.com/kms/docs/key-rotation.
- AWS KMS keeps every former key material and re-encrypts nothing, so it does not meet criterion 4 of
  this ticket; it records a `RotateKey` event: https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html.
- Lockbox (Ruby) rotates by decrypting with the previous keys and encrypting with the current one,
  then removing the previous keys: https://github.com/ankane/lockbox. Tink warns that a key id
  prefix is only a hint: https://developers.google.com/tink/design/keysets.
- CipherSweet recomputes its blind indexes under the new key when it rotates; no source read freezes
  a derived index key: https://ciphersweet.paragonie.com/php/key-rotation.

## What a rotation covers, and what it does not (idea I3)

The rotation replaces the key that wraps each merchant key. The merchant keys themselves, and so
the encrypted cards, do not change (rotating merchant keys is excluded by the owner's scope). It
therefore answers a routine change of master key (schedule, a custodian who leaves). It does not
answer a leak of the master key together with a copy of the database: the former key and an older
backup still give the merchant keys, which still decrypt the cards stored today. That remains
`open` in the table, with the text that describes it. Backups taken before the rotation can be read
only with the former key: the former key must be kept outside the vault until those backups expire,
then destroyed (idea I2). This fork writes no tool for either step.

## Current state (read in the code on 2026-11-23)

- Key chain: with `key_custodian`, the configuration holds the master key encrypted with AES-GCM
  under the custodian key (key 1 and key 2 joined, 32 bytes); `aes_decrypt_custodian_key`
  (`src/routes/key_custodian.rs:221-240`) unlocks it. Without `key_custodian`, the configuration
  holds the master key itself (hex). `utils master-key` generates a new master key, encrypted under
  new custodian keys, and prints the three values (`src/bin/utils.rs:142-160`).
- Each merchant row (`merchant`: `id`, `merchant_id` primary key, `enc_key`, `created_at`) holds the
  merchant key encrypted with `GcmAes256` under the master key (`src/storage/types.rs:465-496`). Card
  data in `locker.enc_data` is encrypted with the merchant key
  (`src/crypto/keymanager/internal_keymanager.rs:126-145`).
- `GcmAes256` (from `ring`) draws a random nonce for each encryption and authenticates the
  ciphertext: a decryption under any other key fails. That failure tells, without a stored version,
  which of two keys wrapped a row.
- The storage traits can read one merchant by id and insert one; they cannot list merchant rows or
  update one (`src/storage.rs:494-521`). The in-memory cache keeps decrypted merchants by id
  (`src/storage/caching/merchant.rs`).
- The duplicate-check key is derived from the master key (`CardDedupHmac`,
  `src/crypto/hash_manager/managers/sha.rs:96-130`). `utils rehash` recomputes every hash under the
  current master key, resumes without stored state, and is tested after a change of key
  (`rehash_converges_rows_hashed_under_another_master_key`).
- With `external_key_manager` enabled, cards are encrypted by the external service, merchant rows
  may still exist for merchants not yet transferred, and the master key still keys the
  duplicate-check hash (T23).
- With `kv`, the re-hash job refuses to run (`rehash_refuses_to_run_with_kv`).

## Requirements

- **D1** After a rotation, every `merchant.enc_key` of the tenant opens under the new master key,
  and the merchant key inside is the same as before.
  Verifiable by: e2e test that decrypts each row with the new key in the test and compares it with
  the key decrypted with the former key before the run; seen failing when the re-encryption of a row
  is removed.
- **D2** After a rotation, every card stored before it, for at least two merchants, is returned
  unchanged by `/data/retrieve` from a vault started with the new master key and new custodian keys.
  Verifiable by: e2e test (HTTP 200, same card number); seen failing when the re-encryption of a
  merchant row is removed.
- **D3** After a rotation, the former master key opens no rewritten `merchant.enc_key`.
  Verifiable by: e2e test that tries the former key on every row; seen failing when the former
  ciphertext is kept.
- **D4** After a rotation (and the hash step decided in R1), an add of a card already stored by the
  same merchant and customer returns `duplicated` and stores no copy.
  Verifiable by: e2e test; seen failing when the hash step is removed.
- **D5** A rotation interrupted then run again gives the same state as one complete run: no
  progress is stored, each row tells by itself which key wraps it. Covered interruptions: after some
  merchant rows (option `--max-rows`, exit code 2), and between the merchant rows and the hash step.
  Verifiable by: e2e test on two databases with the same data set (one complete run, one
  interrupted then resumed), comparing a canonical state (for each merchant: opens under the new
  key, not under the former, same merchant key; each `locker` row byte for byte; each cited hash
  equal to the one recomputed under the new key).
- **D6** Wrong custodian keys (former or new), a new encrypted master key that the new custodian
  keys do not open, or a new master key equal to the former one change no row.
  Verifiable by: e2e tests comparing a snapshot of `merchant`, `locker` and `hash_table` before and
  after; each seen failing when its refusal is removed.
- **D7** No mix of master keys: before any write, every merchant row is read and must open under the
  former or the new key; otherwise the run stops with no change. After the last row, every row must
  open under the new key and none under the former; otherwise the run fails before the hash step.
  Verifiable by: e2e test with one row wrapped under a third key (no change, exit 1); unit test of
  the final check.
- **D8** Audit: one entry per rewritten merchant row (merchant id only), written before the row
  changes, and one entry per run with its outcome, also on a refused run when the database can be
  reached. No entry and no output holds a key, a custodian key, a merchant key, a hash, or any value
  derived from them; the output holds counts only. If an entry cannot be written, the run stops and
  the row it was about to change is unchanged.
  Verifiable by: e2e test reading every `audit_log` row and the command output as text, checking
  them against every key, key part, merchant key and hash of the test (`assert_no_secret`); e2e
  test with `audit_log` made unwritable (snapshot unchanged).
- **D9** Keys arrive on standard input only, never as arguments. With `key_custodian`: former key 1,
  former key 2, new encrypted master key, new key 1, new key 2, one per line. Without it: the new
  master key (hex), one line; the former one comes from the configuration, as for the vault.
  Verifiable by: the e2e helper passes every key through standard input; the command defines no key
  option (read in `src/bin/utils.rs`).
- **D10** Modes: the rotation tests run with and without `key_custodian`; with `kv`, the command
  refuses before any write.
  Verifiable by: the e2e tests in both modes (a CI job added for the mode without custodians); a
  `kv` test that sees the refusal, the snapshot unchanged and a failed run entry.
- **D13** (R2) With an external key manager, the rotation works and is proven against the real
  service the vault talks to (Juspay's Hyperswitch Encryption Service, Apache-2.0, self-hosted,
  tag `v0.1.14`, built from source at commit `18423c5864676604a226e18ea3fff433224b3010`): cards stored through the service for two merchants read back
  after the rotation, the same card added again returns `duplicated`, a merchant row still waiting
  for `/key/transfer` opens under the new master key and not the former one, and `/key/transfer`
  then moves it to the service.
  Verifiable by: e2e test run in a CI job added for this mode, with the service and its database
  as job services; seen failing when the hash step, then the rewrite of merchant rows, is removed.
- **D11** No change visible to callers of the existing routes, no migration, no configuration
  change, no new dependency. `cargo test -j 4` (at least 61 passed), the e2e suite (0 failed, at
  least 20 plus the new tests) and `make demo` (`DEMO OK`) still pass.
  Verifiable by: those commands, and
  `git diff --name-only main -- migrations config demo Cargo.toml Cargo.lock deny.toml CLAUDE.md .typos.toml LICENSE scripts`
  returning nothing.
- **D12** The threat model table, `docs/tokenization.md` and `README.md` describe the state after
  this ticket: what is proven, and what stays `open` (the leak case of the section above, the manual
  configuration step, the modes not covered); every moved `file:line` is corrected and reread.
  Verifiable by: `scripts/check-threat-model.sh` returns 0; `grep -c -i -E 'GHSA|advisories'`
  returns 0 on the three documents; `README.md` lists every file of `git diff --name-only main`.

## Goals, non-goals, anti-goals

- Goal: an operator can replace a tenant's master key; afterwards cards read back, duplicates are
  still detected, and the former key opens nothing that was rewritten.
- Non-goals: rotating merchant keys or re-encrypting cards; rotating the JWE keys; changing the
  custodian key shares without changing the master key (Vault's `rekey`, idea I5); writing the new
  key into the configuration; destroying the former key; running next to a live vault.
- Anti-goals: hand-written cryptography (only `GcmAes256`, `CardDedupHmac` and `ring`); a key
  version column or a progress table; any key on the command line or in an output; an attack demo.

## Approaches considered

- Where it runs: a `utils` subcommand on a stopped vault (chosen, as W1 for the re-hash job: no new
  network entry point that handles every merchant key, and the vault's cache never mixes two keys)
  versus a route of the running vault (a vault holding both keys while serving cards, its cache
  holding merchants read under the former key, and an entry point kept for good).
- Telling which key wraps a row: try the new key, then the former one, the AES-GCM tag deciding
  (chosen, idea I1; Lockbox works this way) versus a key id prefix in the blob (idea I7: a format
  change, so a data migration in all but name) versus a version column (rejected by I4 in an earlier
  ticket: needs a migration).
- The duplicate-check hashes: recompute them with the existing job under the new key versus freeze
  the current hash key under the new master key (decision I3's exit path). Decision R1.

## Design

### Command

`utils rotate-master-key --tenant <id> [--batch-size <n>] [--max-rows <n>]` in `src/bin/utils.rs`,
built like `utils rehash`: same configuration, keys on standard input (D9), counts only on output,
exit code 0 when done, 2 when `--max-rows` stopped it, 1 on any error with its kind only.

Run: stop the vault; back up the database; generate the new key with `utils master-key`; run the
command, the current custodians typing the former keys and the new custodians the new ones; put the
new encrypted master key into the configuration (or the raw key, without custodians); start the
vault and unlock it with the new custodian keys. After the configuration change, `utils rehash` run
with the new keys is the check that the configuration holds the right key: it decrypts every card,
and reports `moved: 0` once the rotation's hash step has run.

### Steps (in `src/domain/`, new module `master_key.rs`)

1. Unlock: the former master key as `utils rehash` does; the new one with
   `aes_decrypt_custodian_key` on the new encrypted key and the new custodian keys. Refuse if either
   fails, or if both keys are equal. No row is read yet.
2. Pre-check, read only: read every merchant row by `id` cursor, `--batch-size` at a time; each must
   open under the new or the former key. A row that opens under neither stops the run (D7). With
   `kv`, the read of `locker` that the hash step needs is attempted here too, so that its refusal
   comes before any write.
3. Rewrite: for each row that opens only under the former key, write its audit entry, then
   `UPDATE merchant SET enc_key = <new> WHERE merchant_id = $1 AND enc_key = <read value>` (0 rows
   changed stops the run: someone else changed it). A row that opens under the new key is counted
   as current and not written.
4. Final check: read every row again; each must open under the new key and none under the former
   (D3, D7).
5. Hash step: per R1.
6. One run entry in the audit log, with the outcome.

Nothing is stored about progress: a run stopped anywhere is finished by running the command again
with the same keys, while the configuration still holds the former key. Until the command exits 0,
the vault must not be started: some merchants open only under one key and some only under the other.

### External key manager mode (R2)

- The command reads the same configuration as the vault, so with `external_key_manager.url` set,
  the hash step decrypts cards through the service, exactly as `/data/retrieve` does. The service
  holds its own master key and entity keys; this rotation does not touch them (rotating the
  service's keys is the service's own feature).
- Test set-up: the service is built from source at the pinned commit with no optional feature
  (its published image is built with the `release` feature, which requires AWS KMS and mutual TLS:
  read in its `Cargo.toml` and `Dockerfile` on 2026-11-23). It keeps its keys under its own AES-256
  key and serves plain HTTP. Its database lives on the same PostgreSQL; its migrations, read at the
  pinned commit, are applied by a job step; the
  vault and `utils` get `LOCKER__EXTERNAL_KEY_MANAGER__…` variables. Without mutual TLS (the
  `Enabled` variant), since both run on the job's private network. A merchant row waiting for
  transfer is written by the test, encrypted with `GcmAes256` under the former master key, as an
  older deployment left it.
- Local runs need Docker; with 8 GB of RAM, the service runs alone, without the vault's other
  services.

### Storage primitives (`src/storage.rs`, `src/storage/db.rs`, cache layer)

- `MerchantInterface`: read a batch of encrypted merchant rows after an `id` cursor; update one
  row's `enc_key` from an expected old value. Bound parameters only. The cache forwards both without
  caching, and drops the merchant's cached entry on update.

### Audit (`src/audit.rs`)

New operations `master_key_rotation_row` (merchant id) and `master_key_rotation_run` (outcome),
through `audit::record` and `PendingAudit`, as for the re-hash job.

### Files

`src/bin/utils.rs`, `src/domain.rs` and `src/domain/master_key.rs`, `src/storage.rs`,
`src/storage/db.rs`, `src/storage/caching/merchant.rs`, `src/audit.rs`, `tests/vault_e2e.rs`,
`.github/workflows/CI-pr.yml` (added jobs only: rotation without `key_custodian`, `kv` refusal,
external key manager), `docs/threat-model.md`, `docs/tokenization.md`,
`README.md`, this design and its plan.

## Table changes planned (`docs/threat-model.md`)

- T22 becomes `proven` for the rotation itself (D1 to D8 tests), with its control lines; the row
  says that the configuration change is manual.
- A new `open` row: a leaked master key together with an older copy of the database still gives
  every merchant key, since merchant keys and cards are not re-encrypted (the design section above,
  cited through `docs/tokenization.md`).
- T23 stays `open` (a public or placeholder master key in that mode is not detected); its row gains
  that the key can now be rotated, citing the external-mode test.
- Moved `file:line` references corrected.

## Risks

- The service may need configuration that its docs do not state (its README says traffic is
  authorised by mutual TLS; its development configuration has none). Building it adds several
  minutes to its CI job and to a local run. Two failed attempts at
  running it in CI stop that part: back to the last working state, the blocker reported, the
  owner asked before a third approach.
- Every key in the e2e tests is generated by `utils master-key` or at random in the test, never
  printed; the service's own master key is generated the same way for each job.
- The manual configuration step after the command stays the most likely operational failure; it is
  documented and listed `open`.

## Decisions for the owner

- **R1** what happens to the duplicate-check hashes: **A, the same command runs the existing re-hash
  job under the new key once every merchant row is rewritten and checked** (owner, 2026-11-23). No
  migration; the hash step is already tested and resumable; its cost is one decryption per stored
  card, vault stopped. After it, the former master key computes no hash in use, so a later leak of
  it does not make the stored hashes testable. Rejected: B, decision I3's exit path (the current
  hash key frozen and stored encrypted under the new master key): it needs a new table, so a
  migration, and the former master key would still derive the hash key in use.
- **R2** the external key manager mode: **B, the rotation supports it and a test proves it against
  the real service, in this ticket** (owner, 2026-11-23). In that mode the cards are encrypted by
  the service (entity keys, `src/crypto/keymanager/external_keymanager.rs:189-200`); the master key
  still wraps the merchant rows not yet transferred (read by `/key/transfer`,
  `src/storage/db.rs:81-120`) and still keys the duplicate-check hash. The rotation is the same:
  rewrite those merchant rows, then the hash step, which decrypts each card through the service.
  Rejected: A, refuse in that mode and prove it in a later ticket (smaller, fail-closed, recommended
  by the builder, who said so once); C, support it untested. Accepted cost: about twice the work of
  A, a second service to run in CI, and the risk that its configuration blocks; see "Risks".

## Left to the builder

- Exact names, counts printed, test names, the helper that builds the canonical state.
