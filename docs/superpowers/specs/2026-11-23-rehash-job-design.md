# Re-hash job for the duplicate-check hash (R1): design

Date: 2026-11-23. Branch: `feat/rehash-job` (from `main`, `d914a8b`). Status: decisions W1, W2 and W3
taken by the owner; plan in `docs/superpowers/plans/2026-11-23-rehash-job.md`.

## Intent

Since I6 (`docs/superpowers/specs/2026-11-23-merchant-scoped-dedup-design.md`), the duplicate-check
hash is scoped to the merchant and customer (HKDF context `hyperswitch-card-vault/card-dedup/v2`).
Hashes written before it, under the tenant-wide `v1` context, are never matched again (T28, `open`):

- a card stored before I6 and added again by the same merchant and customer is stored a second
  time, without `duplication_check`;
- the old `locker` rows keep a shared `hash_id`, which still links merchants, and customers of one
  merchant, for a database reader.

A change of master key would break every hash in the same way (T22, `open`). Decision S2 of I6 asks
for a reusable job that can be run again without harm, resumes after an interruption, is recorded
in the audit log, is tested against PostgreSQL, and serves both for `v1` to `v2` and after a change
of master key. This ticket writes that job, proves each effect with a test that fails on `main`,
and updates the threat model table. This is a study fork; see `CLAUDE.md` for what may not be
claimed about it.

Research reused: grand-angle report of 2026-11-23 on this ticket, kept outside the repository (ideas
I1 to I3 adopted, I5 to I7 rejected, I4 asked as W2). Comparable products, read on 2026-11-23: the
CipherSweet key rotation guide decides per row whether a row needs work by recomputing it under the
current key (https://ciphersweet.paragonie.com/php/key-rotation); GitLab runs data migrations as
idempotent batches over primary-key ranges with an explicit finalisation step
(https://docs.gitlab.com/development/database/batched_background_migrations/); the AWS Database
Encryption SDK states that changing a beacon key invalidates every beacon and needs a full
migration plan (https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/changing-configuration-and-risks.html).
None of them settles where such a job should run.

## Current state (read in the code on 2026-11-23)

- The only place that computes the hash is `add_card_inner` (`src/routes/data.rs:117-126`):
  `CardDedupHmac::from_master_key(master_key, merchant_id, customer_id)`, then
  `transformers::get_hash`, which hashes the JSON-serialised card number, or the caller's
  `enc_card_data` string (`src/routes/data/transformers.rs:83-104`).
- Each `locker` row holds the encrypted card (`enc_data`, encrypted with the merchant's key, itself
  stored encrypted under the master key) and a `hash_id`. Decrypting it gives a `StoredData`
  (`CardData(card)` or `EncData(string)`, `src/routes/data/types.rs:228-231`), from which the
  hashed bytes can be rebuilt exactly as the add route builds them.
- Constraints: `hash_table.data_hash` is the primary key and `hash_table.hash_id` is unique
  (migrations of 2026-06-30); `locker` has a unique index on `(hash_id, merchant_id, customer_id)`
  (migration of 2026-07-13). There is no foreign key between `locker.hash_id` and `hash_table`.
- Two `v1`-era rows of the same card for the same merchant and customer cannot exist: they would
  share one `hash_id` and break the unique index. A duplicate is therefore always one row written
  before a change (I6, or a key change) and one written after it.
- A delete removes the `locker` row and keeps the `hash_table` row (`src/storage/db.rs:264-307`).
- The storage traits have no way to list `locker` rows, read a hash row by `hash_id`, update a
  `locker.hash_id` or delete a hash row (`src/storage.rs:528-580`).
- The in-memory cache (feature `caching`, on by default) keeps `data_hash` to hash row, never a
  negative result (`src/storage/caching/hash_table.rs`).
- Precedent for a maintenance job in this code base: `/key/transfer`
  (`src/routes/key_migration.rs`), a batch route with a `limit`, recorded in the audit log, mounted
  only when an external key manager is configured.
- With the `kv` feature, `locker` and `hash_table` rows may live in Redis before they are drained to
  PostgreSQL, so a job that reads PostgreSQL alone would miss them.

## Requirements

- **D1** After the job, every `locker` row of the tenant cites a `hash_table` row whose `data_hash`
  is the `v2` hash recomputed from the current master key, the row's merchant and customer and its
  decrypted card (except rows handled by W2).
  Verifiable by: e2e test that writes `v1`-era rows (two merchants, two customers of one merchant,
  the same card), runs the job, and recomputes each expected value with `CardDedupHmac` in the
  test; it fails on `main`, where the job does not exist.
- **D2** After the job, no two `locker` rows of different `(merchant, customer)` pairs share a
  `hash_id`, and no `hash_table` row that no `locker` row cites, older than the run, remains (so no
  `v1` row remains).
  Verifiable by: the same e2e test (distinct hash ids; `legacy` row gone; `hash_table` count).
- **D3** After the job, a new add of a card stored before I6, by the same merchant and customer,
  returns `duplication_check` = `duplicated` and stores no copy.
  Verifiable by: the same e2e test; the duplicate test of D11 first shows that, before the job,
  such an add is missed.
- **D4** Running the job again on a tenant already processed changes no `locker` or `hash_table`
  row (only its own audit row is added).
  Verifiable by: e2e test comparing snapshots of both tables before and after a second run.
- **D5** An interruption then a resume give the same final state as one complete run: state is
  never kept by the job itself, it is recomputed from the rows. Covered interruptions: between two
  batches, after a new hash row is inserted but before the `locker` row is moved, and after the
  move but before the old hash row is deleted.
  Verifiable by: e2e test running the same data set on two databases (one complete run; one with
  the three interrupted states written into the database, then resumed) and comparing a canonical
  state keyed by fixed card references.
- **D6** The job writes `audit_log` rows with metadata only (tenant, operation, merchant, customer,
  card reference, outcome), never a card number, a hash value or a key; one row per changed
  `locker` row, written before the change (it records the attempt), and one row per run (it
  records the result).
  Verifiable by: e2e test reading every `audit_log` row as text and checking that none contains the
  card number, the hex of any hash, the master key or either custodian key.
- **D7** If an audit row cannot be written, the job stops with an error and the row it was about
  to change is unchanged: each row's audit entry is written before any write for that row.
  Verifiable by: e2e test that makes `audit_log` unwritable, runs the job, expects a non-zero exit
  and unchanged `locker` and `hash_table` rows.
- **D8** The job never writes a card number, a hash value or a key to a log, its output or an
  error message. Its output holds counts only.
  Verifiable by: e2e test checking the command's standard output and error for the card number,
  the hash values and the key values; code read: no `logger` call takes decrypted data.
- **D9** The counts balance: rows examined = already current + moved + handled as duplicate; if
  they do not, the batch fails before its final clean-up.
  Verifiable by: unit test on the balance check (the error case required by `CLAUDE.md`).
- **D10** (T22, W3 = A) The same job also converges rows whose hash was written under another master
  key: it only needs the current key, since it compares each cited hash with the recomputed one.
  Verifiable by: e2e test with hash rows computed in the test under the `v2` derivation of another
  random master key.
- **D11** Duplicate of the same card for the same merchant and customer: handled as decided in W2,
  never by deleting a `locker` row.
  Verifiable by: e2e test that creates the duplicate the way it happens (a `v1`-era row, then an add
  after I6) and checks both card references still retrieve the card.
- **D12** No change visible to callers of the existing routes; no migration, no configuration
  change, no new dependency; `cargo test -j 4`, the e2e suite and `make demo` still pass.
  Verifiable by: those commands, and
  `git diff --name-only main -- demo config migrations src/storage/schema.rs Cargo.toml Cargo.lock .github CLAUDE.md .typos.toml LICENSE scripts`
  returning nothing.
- **D13** The threat model table, `docs/tokenization.md` and `README.md` describe the state after
  R1; every moved `file:line` is corrected and reread.
  Verifiable by: `scripts/check-threat-model.sh` exit code 0; rows listed under "Table changes".

## Goals, non-goals, anti-goals

- Goal: after one run, rows written before I6 (or before a key change) behave like rows written
  after it, and no longer link merchants or customers.
- Non-goals: rotating the master key itself (re-encrypting merchant keys under a new master key);
  the fingerprint table; the `kv` storage scheme; a dry-run mode; scheduling the job.
- Anti-goals: hand-written cryptography; deleting a stored card; a lookup that tries `v2` then `v1`
  (rejected in I6: it keeps the link and the timing difference alive, and after a key change it
  would need the old key); a version column or a progress table (both need a migration).

## Design

### How one row is processed (the same step makes the job resumable and idempotent)

For each `locker` row L, in `id` order, from a cursor:

1. Decrypt L with its merchant's key (`crypto_operation::decrypt_data`), rebuild the request data
   from `StoredData`, compute H with `CardDedupHmac` and `get_hash`, exactly as `/data/add` does.
   The decrypted bytes live only in memory, inside `StrongSecret`, for this step.
2. Read the hash row of L's `hash_id`. If it exists and its `data_hash` equals H: L is current;
   nothing is written.
3. Otherwise read the hash row of H (`find_optional_by_data_hash`). If it exists and another
   `locker` row of the same merchant and customer cites it, L is a duplicate, handled as W2
   decides (W2 = A: if L's `hash_id` already has no hash row, L was detached by an earlier run and
   is counted as current, so a second run writes nothing).
4. Write L's audit row, before any write for L. Then, for a move, insert H if it is missing
   (`hash::insert_or_get`, race-safe) and move L: `UPDATE locker SET hash_id = new WHERE` primary
   key `AND hash_id = old` (the second condition makes a concurrent change visible as 0 rows, which
   stops the job).
5. Delete the old hash row only if no `locker` row cites it any more (one statement with
   `NOT EXISTS`), and drop it from the cache.

Every intermediate state is one the next run handles: after the insert of step 4 an unused current
hash row exists and the next run reuses it; after the move the old row is unused and step 5 or the final clean-up
removes it. No progress is stored by the job.

### Final clean-up of the batch that reaches the end

Delete every `hash_table` row that no `locker` row cites and whose `created_at` is earlier than the
start of the run minus 60 seconds. The margin leaves alone a hash row that a concurrent add has
inserted but not yet cited. This removes `v1` rows whose cards were deleted before the job, and
also the current rows of cards their owners deleted (T29): after the job, such a re-add takes the
new-card path until the next delete.

### Where it runs (W1 = B)

A subcommand `utils rehash --tenant <id> [--max-rows <n>]` of the existing `utils` binary
(`src/bin/utils.rs`). It reads the same configuration as the vault (`GlobalConfig::new`, file and
`LOCKER__` environment variables), builds the tenant state with `TenantConfig::from_global_config`
and `TenantAppState::new`, both already public, and calls one public function of
`src/domain/hash.rs`, which holds the job. Under `key_custodian`, the two custodian keys are read
from standard input, one per line, never from the command line (which other users of the machine
can see), and the master key is unlocked by the same function as `/custodian/decrypt`
(`aes_decrypt_custodian_key`, `src/routes/key_custodian.rs:221-240`, made public). Without
`key_custodian`, the master key comes from the configuration, as in the vault.

It prints only counts (`examined`, `current`, `moved`, `duplicates`, `removed hash rows`,
`complete`). Exit code 0 when every row has been processed; 2 when `--max-rows` stopped it before
the end (the interruption used by the tests); 1 on any error, with a message that names the error
kind only. Running the command again resumes. An internal `--batch-size` option (default 100)
lets the tests cross batch boundaries with a few rows. The job runs in the command's own process, so the vault never gains a route that
decrypts every card.

### Running next to a live vault

Recommended operation: stop the vault, run the command, start the vault again. If the vault keeps
running, two effects remain, both described in `docs/tokenization.md`: an add of a card not yet
processed creates the duplicate of W2, which a second run handles; and the vault's in-memory cache
(time-to-idle only, `src/storage/caching.rs:50-64`) may still hold a hash row that the final
clean-up deleted, which matters only for a card deleted before the job and added again before the
vault restarts.

### New storage primitives (`src/storage.rs`, `src/storage/db.rs`, cache layer)

- `LockerInterface`: list a batch of rows after a cursor (`id`, primary key, merchant, customer,
  `hash_id`, encrypted data); update one row's `hash_id` from an expected old value.
- `HashInterface`: read a hash row by `hash_id`; delete a hash row by `hash_id` if unused,
  returning its `data_hash` so the cache entry is dropped; delete unused rows older than a time.
- With the `kv` feature these primitives return an error: the job is refused rather than run on a
  partial view.

### Audit

New operations `rehash_run` (one row per run of the command, its outcome) and `rehash_row` (one row per changed
`locker` row, with merchant, customer and card reference as `resource_id`), through `audit::record`
and `PendingAudit`, so ids are cleaned and card-shaped ids redacted as elsewhere.

### Files

`src/bin/utils.rs` (subcommand), `src/routes/key_custodian.rs` (unlock function made public),
`src/domain/hash.rs` (job), `src/storage.rs`,
`src/storage/db.rs`, `src/storage/caching/hash_table.rs` (and the locker cache file if one forwards
the trait), `src/audit.rs` (operations), `tests/vault_e2e.rs`, `docs/threat-model.md`,
`docs/tokenization.md`, `README.md`, this design and its plan. Outside the owner's
modifiable list, asked before any change: `src/routes/key_custodian.rs` and `src/routes/data.rs`,
one visibility change each (`aes_decrypt_custodian_key` public; `mod transformers` visible inside
the crate, so the job reuses `get_hash` instead of copying how the hashed bytes are built).

## Table changes planned (`docs/threat-model.md`)

- T28: control = the re-hash job; evidence = D1 to D5 tests; status `proven` for tenants on which
  the job has run; the row says the job must be run, and that duplicates follow W2.
- T22: stays `open`; control still `none` for the rotation itself; evidence adds the D10 test and
  the `docs/tokenization.md` lines saying that the re-hash after a key change exists and that the
  rotation does not.
- T29: wording notes that the job's clean-up removes the kept hash rows of deleted cards; stays
  `open` (a delete after the job keeps its hash row again).
- New row (`open`): run next to a live vault, the job can leave a duplicate created during the run
  until a second run, and the vault's cache can keep a deleted hash row until restart (the
  `docs/tokenization.md` lines that describe it).
- T3/T5/T6 evidence may gain the new audit tests; moved `file:line` references corrected.

## Decisions for the owner

- **W1** where the job runs: **B, a `utils rehash` command** (owner, 2026-11-23). Option A, a route
  `POST /custodian/rehash` after unlock, was rejected: it would add, for good, a network entry
  point outside the JWE middleware that decrypts every card of the tenant, for a job run once; its
  cache advantage holds only for a single vault instance. Accepted cost of B: the master key also
  lives, for the run, in the command's process, and the custodians type their keys into it.
- **W2** duplicate of the same card for the same merchant and customer: **A, detach the row that
  cannot take the current hash** (owner, 2026-11-23). It gets a fresh random `hash_id` with no
  `hash_table` row: both card references still retrieve the card, no link to anyone remains, the
  old hash row can be deleted, and later adds find the other copy and return `duplicated`. The two
  stored copies remain, as before the job. Rejected: B, leave it on its old hash and report it
  (keeps the link of T24 and the old row until a manual fix); C, delete it (the merchant may still
  use that reference).
- **W3** T22: **A, the job converges rows whose hash was written under any other master key, and a
  test proves it; master key rotation itself (re-encrypting each merchant key under a new master
  key) stays out of scope** (owner, 2026-11-23). T22 stays `open`, since a master key still cannot
  be changed in this code; its row cites the job and its test as the part that exists. Rejected: B,
  also implement the rotation (about a second ticket, in key management, which would mix two risky
  reviews, as decision S2 of I6 already refused).

## Left to the builder

- Exact names, batch size defaults, test names; the helper that writes `v1`-era rows in the tests.
