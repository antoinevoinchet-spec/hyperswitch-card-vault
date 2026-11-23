# Re-hash job (R1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `utils rehash` command that recomputes every duplicate-check hash of a tenant under the
current master key and `v2` scope, resumable and idempotent, recorded in `audit_log`, proven by
end-to-end tests against PostgreSQL that fail on `main`.

**Architecture:** The job lives in `src/domain/hash.rs` as one public async function over a
`TenantAppState`; it uses new single-query storage primitives (`src/storage.rs`,
`src/storage/db.rs`, forwarded by the cache layer). `src/bin/utils.rs` loads the configuration,
unlocks the master key (custodian keys on standard input), builds the tenant state and prints
counts only. Per-row state is recomputed from the rows, never stored.

**Tech Stack:** Rust 1.100, diesel + async-bb8-diesel, `ring` (through `CardDedupHmac`), argh,
tokio, PostgreSQL 14+.

**Spec:** `docs/superpowers/specs/2026-11-23-rehash-job-design.md` (requirements D1 to D13,
decisions W1 = B, W2 = A, W3 = A).

## Global Constraints

- No hand-written cryptography: hashes only through `CardDedupHmac::from_master_key` and
  `transformers::get_hash`; decryption only through `crypto_operation::decrypt_data`.
- No new dependency, no migration, no change to `config/`, `Cargo.toml`, `Cargo.lock`,
  `src/storage/schema.rs`, `demo/`, `.github/`, `scripts/`, `CLAUDE.md`, `.typos.toml`, `LICENSE`.
- Two files outside the owner's modifiable list, each a one-line visibility change, are touched
  only after the owner's explicit approval (Task 0): `src/routes/key_custodian.rs`
  (`aes_decrypt_custodian_key` becomes `pub`) and `src/routes/data.rs` (`mod transformers` becomes
  `pub(crate) mod transformers`, so the job reuses `get_hash`). Any other file outside the list
  (for example `src/lib.rs`, `src/domain.rs`, `src/routes.rs`, `src/routes/data/types.rs`) means:
  stop and ask. Checked on 2026-11-23: `domain::hash`, `routes::key_custodian`,
  `routes::data::types::StoredData`, `storage::GlobalStore`, `api_client::ApiClient` and
  `runtime_config::RuntimeConfigManager` are already public, so `utils.rs` needs nothing else.
- The decrypted card stays in memory inside `StrongSecret`; no `logger` call, output line or error
  message takes decrypted data, a hash value or a key. Custodian keys are read from standard input,
  never from arguments.
- Timestamps in UTC (`crate::utils::date_time::now()`).
- English everywhere in the repository; nothing that describes the project's standing against a
  standard (see `CLAUDE.md`). The search pattern for the forbidden wording is kept in the session
  scratchpad (`forbidden.txt`, one fixed string per line, the terms `CLAUDE.md` forbids), never in
  the repository.
- Rust commands are prefixed by `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"`
  and use `-j 4`.
- E2e runs use a throwaway TCP-only cluster in the session scratchpad
  (`/opt/homebrew/opt/postgresql@14/bin`): `initdb -D <scratchpad>/pg -U postgres --auth=trust`,
  then `pg_ctl -D <scratchpad>/pg -o "-p 54330 -c unix_socket_directories=''" -l <scratchpad>/pg.log start`.
  E2e command: `VAULT_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:54330/postgres VAULT_TEST_REQUIRE_DB=1 cargo test -j 4 --features key_custodian --test vault_e2e`.
  Cleanup: `pg_ctl -D <scratchpad>/pg stop` and `rm -rf <scratchpad>/pg`, done once no further
  code change is expected (end of Task 8, re-created if a review asks for a fix).
- One commit per task, after `git status`, English message, attribution lines.
- Not available locally, checked only in CI: `typos`, `cargo nextest`, nightly `cargo fmt`. Every
  failing CI check is reported as is, with its step and message.

## Review Focus

1. A tenant with no `locker` row at all: the command must exit 0 with all counts 0 and remove only
   unused hash rows older than the margin. Test: `rehash_on_an_empty_tenant_changes_nothing`.
2. A row stored with `enc_card_data` (not a card): its hash must be the hash of that string, as
   `/data/add` computes it. Test: the `ref-enc` row of `rehash_moves_v1_rows_to_scoped_hashes`.
3. Wrong custodian keys on standard input: non-zero exit, no change, no key printed. Test:
   `rehash_refuses_wrong_custodian_keys`.
4. More rows than one internal batch: the cursor must reach every row exactly once. The e2e helper
   passes `--batch-size 2` (an internal option, default 100) so every data set spans at least two
   batches, and test 1 checks `examined: 4`.
5. A concurrent change of a row between read and update (0 rows updated): the job stops with an
   error rather than count it as moved. Code only (`hash_id = old` condition); not tested, since it
   needs a concurrent writer; listed in the final report. Also listed there as not tested: the
   refusal under `kv` (only compiled with `--all-features`); the path without `key_custodian`
   (master key from the configuration; only compiled with default features); the cache
   invalidation of deleted hash rows (the tests restart the vault around each run, as the design
   recommends); the order "balance check before clean-up".

---

### Task 0: Branch, design and plan in place; approval of the two visibility changes

**Covers:** K1, K2 (owner's completion criteria), the "outside the list" rule

- [ ] **Step 1**: `git branch --show-current` -> `feat/rehash-job`;
  `git merge-base --is-ancestor d914a8b feat/rehash-job; echo $?` -> `0`.
- [ ] **Step 2**: `git status --porcelain` empty and `git log --oneline main..HEAD -- docs/superpowers`
  lists the design and plan commits.
- [ ] **Step 2b**: create `<scratchpad>/forbidden.txt` (the terms `CLAUDE.md` forbids, one fixed
  string per line) and check `test -s` on it; every later search runs
  `grep -i -F -f <scratchpad>/forbidden.txt ...; echo $?` and accepts only exit 1 (no match), exit 2
  being an error.
- [ ] **Step 2c**: record the starting counts: `cargo test -j 4` (expected 41 passed) and the full
  e2e command (expected 8 passed); the thresholds of Tasks 5 and 8 are these plus the new tests.
- [x] **Step 3**: the owner has approved the two one-line visibility changes of Global
  Constraints (stop point 3 of the request): approved on 2026-11-23.

### Task 1: End-to-end tests that fail on `main`

**Covers:** D1, D2, D3, D4, D5, D6, D7, D8, D10, D11 (and Review Focus 1 to 4)

**Files:**
- Modify: `tests/vault_e2e.rs` (helpers after `store_card_as`, tests at the end)

**Interfaces:**
- Consumes (existing): `TestDb::{create, exec, count, locker_hash_ids, audit_rows}`, `Keys`,
  `Vault::{start, post}`, `unlock`, `unlocked_master_key`, `store_card_as`, `CardDedupHmac`.
- Produces (test helpers, used only in this file):
  - `async fn store_card_with_ref(vault: &Vault, merchant: &str, customer: &str, data: serde_json::Value, reference: &str) -> serde_json::Value`
    (`data` is `{"card": {...}}` or `{"enc_card_data": "..."}`, merged into the add body with
    `requestor_card_reference`).
  - `fn run_rehash(db: &TestDb, keys: &Keys, key2: &str, args: &[&str]) -> (i32, String)` runs
    `env!("CARGO_BIN_EXE_utils") rehash --tenant public --batch-size 2 <args>` with the same
    `LOCKER__DATABASE__*` and `LOCKER__TENANT_SECRETS__PUBLIC__MASTER_KEY` variables as
    `Vault::start`, current dir `CARGO_MANIFEST_DIR`, writes `key1\n<key2>\n` to standard input,
    returns the exit code and standard output plus standard error joined. It kills the process and
    panics with "rehash timed out" after 120 s.
  - `fn expected_hash(master_key: &[u8], merchant: &str, customer: &str, hashed: &str) -> Vec<u8>`
    (`CardDedupHmac` over `serde_json::to_vec(hashed)`; `get_hash` serialises both the card number
    and the `enc_card_data` string this way, read in `src/routes/data/transformers.rs:83-104`).
  - `fn seed_v1(db: &TestDb, master_key: &[u8], groups: &[(&str, &str, &[&str])])`: deletes every
    `hash_table` row; for each group `(hash_id, hashed, locker_ids)` inserts
    `(hash_id, <v1 hash of hashed>, created_at '2000-01-01')` and points those `locker` rows at it
    (the v1 value as in `tenant_wide_v1_hash_row_is_not_matched`); then inserts an unused
    `('orphan-v1', <64 random bytes>, created_at '2000-01-01')`.
  - `TestDb::snapshot(&self) -> (Vec<String>, Vec<String>)`: every column of every `locker` row
    (`SELECT t::text FROM locker t ORDER BY locker_id`) and of every `hash_table` row (ordered by
    `hash_id`).
  - `TestDb::hash_of(&self, hash_id: &str) -> Option<Vec<u8>>`.
  - `fn assert_no_secret(text: &str, secrets: &[&str])` (fails naming the kind, never the value).
  - Data set "first" (used by tests 1, 4, 5, 6): card `4111111111111111` for (M1, C1) `ref-m1-c1`,
    (M2, C1) `ref-m2-c1`, (M1, C2) `ref-m1-c2`; `{"enc_card_data": "opaque-test-value"}` for
    (M1, C1) `ref-enc`; then `seed_v1` with `("legacy-v1", card, [three card refs])` and
    `("legacy-enc", "opaque-test-value", ["ref-enc"])`. Secrets checked in outputs and audit rows:
    the card number, `opaque-test-value`, the hex of every stored and expected hash,
    `keys.master_key`, `keys.key1`, `keys.key2`.
  - The vault is dropped before each `run_rehash` and a new one started after (the design's
    recommended operation), so its cache never serves a row the test changed.

- [ ] **Step 1: Write the tests**

  1. `rehash_moves_v1_rows_to_scoped_hashes`: data set "first"; drop the vault; `run_rehash` ->
     exit 0, output has `examined: 4`, `moved: 4`. Assert: each locker row's `hash_of(hash_id)`
     equals `expected_hash(.., merchant, customer, hashed)`; 4 distinct `hash_id`;
     `hash_of("legacy-v1")`, `hash_of("legacy-enc")`, `hash_of("orphan-v1")` are `None`;
     `count("hash_table") == 4`; `assert_no_secret(output, ..)`. Start a vault, unlock, add the
     card again for (M1, C1): `duplication_check == "duplicated"`, `count("locker") == 4`.
  2. `rehash_detaches_the_older_duplicate`: store (M1, C1) `ref-old`; `seed_v1`; restart the vault;
     add the card again for (M1, C1) `ref-new` -> `duplication_check` is null (the T28 symptom
     before the job, D3); drop the vault; `run_rehash` -> exit 0. Assert: `ref-new` cites the
     expected hash; `ref-old`'s `hash_id` differs from `ref-new`'s and `hash_of` it is `None`; no
     `legacy-v1`; restart, unlock: retrieve `ref-old` and `ref-new` both 200 with the card number;
     a third add -> `duplicated`, `count("locker") == 2`.
  3. `rehash_twice_changes_nothing`: the data set of test 2 plus (M2, C1); run once (exit 0); age
     every `hash_table` row (`UPDATE hash_table SET created_at = '2000-01-01'`), so the final
     clean-up of the second run sees cited rows older than its margin; then `snapshot` and
     `audit_rows().len()`; run again (exit 0); `snapshot` equal; exactly one new
     audit row, `("rehash_run", "success", 200)`, and no new `rehash_row`; second output has
     `moved: 0`, `duplicates: 0`, `removed hash rows: 0`.
  4. `rehash_resumed_after_interruption_matches_a_full_run`: two databases, one `Keys`, data set
     "first" in each. Database A: one full run (exit 0). Database B: `--max-rows 1` -> exit 2,
     output `complete: no`, and `hash_of("legacy-v1")` is still `Some` (two rows still cite it);
     then write two crash states by SQL: insert the expected hash row of `ref-m2-c1` unused (crash
     after insert, before move), and move `ref-enc` to a new row holding its expected hash, leaving
     `legacy-enc` uncited (crash after move, before delete); then a full run -> exit 0,
     `complete: yes`. Assert: for every `locker_id`, `hash_of(hash_id)` is equal in A and B, and
     `count("hash_table")` is equal.
  5. `rehash_audit_rows_hold_no_card_or_key`: after a run on data set "first", `audit_rows()`
     contains exactly 4 `("rehash_row", "success", 200)` and 1 `("rehash_run", "success", 200)`;
     `assert_no_secret` on every row's text.
  6. `rehash_stops_when_audit_table_is_unwritable`: data set "first", drop the vault, `snapshot`,
     rename `audit_log`, `run_rehash` -> exit 1; rename back; `snapshot` equal (nothing written,
     since each row's audit entry is written before any change of that row);
     `assert_no_secret(output, ..)`.
  7. `rehash_converges_rows_hashed_under_another_master_key`: store (M1, C1) and (M2, C1); rewrite
     each row's `data_hash` to `expected_hash(<32 random bytes>, merchant, customer, card)`; drop
     the vault; run -> exit 0; each row cites the expected hash under the real key;
     `count("hash_table") == 2`; restart, add (M1, C1) again -> `duplicated`.
  8. `rehash_on_an_empty_tenant_changes_nothing`: unlock once, drop the vault, insert `orphan-v1`
     (old) and an unused row `fresh` with `created_at = now()`; run -> exit 0, `examined: 0`;
     `orphan-v1` gone, `fresh` kept.
  9. `rehash_refuses_wrong_custodian_keys`: data set "first", drop the vault, `snapshot`;
     `run_rehash` with a wrong `key2` (right shape) -> exit 1, `snapshot` equal,
     `assert_no_secret(output, ..)` including the wrong key.

- [ ] **Step 2: Run them on the current code and keep the failure output for the report**

Run: the e2e command of Global Constraints with the filter `rehash`, output kept in
`<scratchpad>/rehash-red.txt`.
Expected: 9 failed, each on the first `run_rehash` exit-code assertion (unknown subcommand); the
8 existing e2e tests pass when run without the filter.

- [ ] **Step 3: Commit** `test: add end-to-end tests for the re-hash job (failing: no command yet)`.

### Task 2: Audit operations and the count balance

**Covers:** D6, D9

**Files:**
- Modify: `src/audit.rs` (enum, `as_str`, two constructors, unit test)
- Modify: `src/domain/hash.rs` (report type, balance check, unit tests)

**Interfaces:**
- Produces:
  - `AuditOperation::RehashRow` -> `"rehash_row"`, `AuditOperation::RehashRun` -> `"rehash_run"`.
  - `pub fn rehash_row_audit(tenant_id: &str, merchant_id: &str, customer_id: &str, locker_id: &str) -> PendingAudit`
    (merchant, customer, resource) and `pub fn rehash_run_audit(tenant_id: &str) -> PendingAudit`.
  - In `src/domain/hash.rs`:
    `#[derive(Debug, Default, Clone, PartialEq, Eq)] pub struct RehashReport { pub examined: u64, pub current: u64, pub moved: u64, pub duplicates: u64, pub removed_hash_rows: u64, pub complete: bool }`
    and `pub(crate) fn check_balance(&self) -> Result<(), ContainerError<error::ApiError>>`,
    `Err(ApiError::DatabaseError)` when `examined != current + moved + duplicates`.

- [ ] **Step 1: Write failing unit tests**: `rehash_row_entry_has_ids_only` (a card-shaped
  `locker_id` is redacted; operation `rehash_row`; JSON holds merchant and customer),
  `report_balance_accepts_matching_counts`, `report_balance_rejects_mismatched_counts`
  (`examined: 3, current: 1, moved: 1` -> `Err`).
- [ ] **Step 2: Run** `cargo test -j 4 --lib rehash_row_entry report_balance` -> compile error.
- [ ] **Step 3: Implement** the items above.
- [ ] **Step 4: Run** the same command -> 3 passed.
- [ ] **Step 5: Commit** `feat: add re-hash audit operations and the count balance check`.

### Task 3: Storage primitives

**Covers:** D1, D2, D4, D5 (prerequisites)

**Files:**
- Modify: `src/storage.rs:528-580` (trait methods)
- Modify: `src/storage/db.rs` (PostgreSQL implementations; under `kv` each returns an error)
- Modify: `src/storage/caching/hash_table.rs` (forward, invalidate deleted keys). There is no
  locker cache file: `Caching<T>` reaches `LockerInterface` through `Deref`
  (`src/storage/caching.rs`), so the two locker methods need no forwarding; check it compiles.

**Interfaces:**
- Produces (`pub(crate)` traits):
  - `LockerInterface::find_locker_batch(&self, after_id: i32, limit: i64) -> Result<Vec<(i32, types::Locker)>, ContainerError<Self::Error>>`
    (`select((locker::id, locker::all_columns))`, `id > after_id`, ordered by `id`, loaded as
    `(i32, LockerInner)`; no change to `types.rs`).
  - `LockerInterface::update_locker_hash_id(&self, locker_id: Secret<String>, merchant_id: &str, customer_id: &str, old_hash_id: &str, new_hash_id: &str) -> Result<usize, ContainerError<Self::Error>>`
    (primary key and `hash_id = old_hash_id` in the filter).
  - `HashInterface::find_optional_by_hash_id(&self, hash_id: &str) -> Result<Option<types::HashTable>, ContainerError<Self::Error>>`.
  - `HashInterface::delete_hash_if_unused(&self, hash_id: &str) -> Result<Option<Secret<Vec<u8>>>, ContainerError<Self::Error>>`
    (`DELETE ... WHERE hash_id = $1 AND NOT EXISTS (SELECT 1 FROM locker WHERE locker.hash_id = hash_table.hash_id) RETURNING data_hash`).
  - `HashInterface::delete_unused_hashes_before(&self, before: time::PrimitiveDateTime) -> Result<Vec<Secret<Vec<u8>>>, ContainerError<Self::Error>>`
    (same `NOT EXISTS`, `created_at < before`, `RETURNING data_hash`).
  - The cache layer forwards the three hash methods and calls `invalidate` on the `hash_table`
    cache for every returned `data_hash`.
  - Under `feature = "kv"`: each returns `Err` with the table's existing "DB error" variant.

- [ ] **Step 1: Implement** the five methods (exercised by Task 1's tests once Tasks 4 and 5 land).
- [ ] **Step 2: Run** `cargo build -j 4 --features key_custodian` and
  `cargo clippy -j 4 --all-features --all-targets` -> exit 0; the only new warnings allowed are
  dead-code warnings for the five methods, which Task 4 uses (none may remain after Task 4).
- [ ] **Step 3: Commit** `feat: add storage primitives for the re-hash job`.

### Task 4: The job

**Covers:** D1, D2, D4, D5, D6, D7, D8, D9, D10, D11

**Files:**
- Modify: `src/domain/hash.rs`
- Modify: `src/routes/data.rs:2` (`pub(crate) mod transformers;`, after Task 0 step 3)

**Interfaces:**
- Consumes: Task 2 (`RehashReport`, `check_balance`, `rehash_row_audit`, `rehash_run_audit`),
  Task 3 (primitives), `transformers::get_hash`, `CardDedupHmac::from_master_key`,
  `crypto_operation::decrypt_data`, `keymanager::get_dek_manager(..).find_by_entity_id`,
  `hash::insert_or_get`, `audit::record`, `storage::utils::generate_uuid`.
- Produces: `pub async fn rehash(state: &TenantAppState, batch_size: i64, max_rows: Option<u64>) -> Result<RehashReport, ContainerError<error::ApiError>>`.

- [ ] **Step 1: Implement `rehash`**, per row in this order (the audit entry comes before any
  write for that row, so a failed audit write leaves the database unchanged):
  - run start `t0 = now()`; cursor `0`; loop `find_locker_batch(cursor, batch_size)`; stop when a
    batch is empty (`complete = true`), or when `examined` reaches `max_rows` (`complete = false`).
  - decrypt; `serde_json::from_slice::<StoredData>`; map `CardData(card)` to `Data::Card { card }`
    and `EncData(s)` to `Data::EncData { enc_card_data: s }`;
    `H = get_hash(&data, CardDedupHmac::from_master_key(master_key, merchant, customer)?)`.
  - cited = `find_optional_by_hash_id(L.hash_id)`; target = `find_optional_by_data_hash(H)`.
  - current: `cited` exists and its `data_hash` equals `H` (compared through `PeekInterface`)
    -> `current += 1`, nothing written.
  - duplicate: `target` exists and
    `find_optional_by_hash_id_merchant_id_customer_id(target.hash_id, merchant, customer)` returns
    a row with another `locker_id`. If `cited` does not exist, the row was detached earlier:
    `current += 1`, nothing written. Otherwise:
    `audit::record(&state.db, rehash_row_audit(..), Ok(()))?`, update to `generate_uuid()`,
    `delete_hash_if_unused(old)`, `duplicates += 1`.
  - move: `audit::record(&state.db, rehash_row_audit(..), Ok(()))?`; target = existing row or
    `insert_or_get(H)`; `update_locker_hash_id(.., old, target.hash_id)`; 0 rows -> stop with
    `ApiError::DatabaseError`; `delete_hash_if_unused(old)`; `moved += 1`.
  - when complete: `check_balance()?`, then `delete_unused_hashes_before(t0 - 60 s)`;
    `removed_hash_rows` counts these and the per-row deletions.
  - the whole result goes through `audit::record(&state.db, rehash_run_audit(tenant), result)`,
    so a failed final audit write also returns `Err`.
  - no `logger` call with decrypted data, `H`, or any key; errors carry static strings only.
- [ ] **Step 2: Run** `cargo build -j 4 --features key_custodian` and `cargo build -j 4` (default
  features) -> exit 0.
- [ ] **Step 3: Commit** `feat: add the re-hash job to the hash domain`.

### Task 5: The `utils rehash` command

**Covers:** D6, D7, D8, D12 (and Review Focus 3)

**Files:**
- Modify: `src/bin/utils.rs`
- Modify: `src/routes/key_custodian.rs:221` (`pub async fn aes_decrypt_custodian_key`, after Task 0
  step 3; body unchanged)

**Interfaces:**
- Consumes: Task 4 `rehash`; `GlobalConfig::new`, `validate`, `fetch_raw_secrets`;
  `TenantConfig::from_global_config`; `ApiClient::new`; `RuntimeConfigManager::new`;
  `GlobalStore::new`; `TenantAppState::new` (the same wiring as `GlobalAppState::new` and
  `decrypt_inner`).
- Produces: subcommand `rehash` with `--tenant <id>` (required), `--batch-size <n>` (internal,
  default 100), `--max-rows <n>` (optional).
  - Under `key_custodian`: reads two lines (key 1, key 2) from standard input and unlocks the
    master key with `aes_decrypt_custodian_key` (a wrong key -> exit 1). It never echoes them.
  - Without `key_custodian`: uses `tenant_secrets.master_key` from the configuration, as the vault
    does at start-up (`GlobalAppState::new`).
  - Output, one per line: `examined: N`, `current: N`, `moved: N`, `duplicates: N`,
    `removed hash rows: N`, `complete: yes|no`.
  - Exit codes: 0 when complete; 2 when stopped by `--max-rows` (`complete: no`); 1 on any error,
    after printing `rehash failed: <error kind>` (variant name only, as the audit log keeps it).

- [ ] **Step 1: Implement**; `main` stays synchronous and runs the subcommand in a
  `tokio::runtime::Runtime`; no logger setup.
- [ ] **Step 2: Run** the e2e command with the filter `rehash` -> 9 passed.
- [ ] **Step 3: Run** `cargo test -j 4` (at least 44 passed: 41 + 3) and the full e2e command (at
  least 17 passed, `0 failed`).
- [ ] **Step 4: Run** `git diff main -- src | grep -n -E '^\+.*logger::'` and read every hit: none
  takes decrypted data, a hash or a key.
- [ ] **Step 5: Commit** `feat: add the utils rehash command`.

### Task 6: Deliberate breakages

**Covers:** the owner's main rule (each test seen failing when its control is removed)

**Files:** none committed; each breakage is reverted with `git checkout -- <file>` and checked with
`git diff --quiet`.

- [ ] **Step 1**: for each line, apply the breakage, run the named test, record the failing
  assertion, revert:

| Breakage | Test expected to fail |
|---|---|
| merchant id replaced by `""` in the job's `CardDedupHmac` call | `rehash_moves_v1_rows_to_scoped_hashes` |
| customer id replaced by `""` in the same call | `rehash_moves_v1_rows_to_scoped_hashes` |
| `EncData` rebuilt as an empty `enc_card_data` | `rehash_moves_v1_rows_to_scoped_hashes` (`ref-enc`) |
| no `delete_hash_if_unused` and no final clean-up | `rehash_moves_v1_rows_to_scoped_hashes` |
| `NOT EXISTS` removed from `delete_hash_if_unused` | `rehash_resumed_after_interruption_matches_a_full_run` (`legacy-v1` gone after one row) |
| `NOT EXISTS` removed from `delete_unused_hashes_before` | `rehash_twice_changes_nothing` (aged, cited rows deleted) |
| `id > after_id` replaced by `id >= after_id` | `rehash_moves_v1_rows_to_scoped_hashes` (fails by "rehash timed out" or on `examined: 4`) |
| "detached earlier" check removed | `rehash_twice_changes_nothing` |
| duplicate branch skipped (row left on its old hash) | `rehash_detaches_the_older_duplicate` |
| "current" decided by existence of the cited row only | `rehash_converges_rows_hashed_under_another_master_key` |
| an existing target row ignored, `insert_hash` always called | `rehash_resumed_after_interruption_matches_a_full_run` (crash state 1: duplicate key, exit 1) |
| audit error ignored (`let _ =`) | `rehash_stops_when_audit_table_is_unwritable` |
| row audit written after the move instead of before | `rehash_stops_when_audit_table_is_unwritable` |
| `rehash_row_audit`'s resource set to the decrypted data as text (`opaque-test-value` is not card-shaped, so it is not redacted) | `rehash_audit_rows_hold_no_card_or_key` |
| decrypted card printed in the output | `rehash_moves_v1_rows_to_scoped_hashes` |
| `check_balance` always `Ok` | `report_balance_rejects_mismatched_counts` |
| margin of the final clean-up set to 0 s | `rehash_on_an_empty_tenant_changes_nothing` |
| master key taken without the AES-GCM unlock | `rehash_refuses_wrong_custodian_keys` |

- [ ] **Step 2**: `git status --porcelain` empty after the last revert.

### Task 7: Threat model, tokenization page, README

**Covers:** D13

**Files:**
- Modify: `docs/threat-model.md`, `docs/tokenization.md`, `README.md`

- [ ] **Step 1**: `docs/tokenization.md`: replace the "not converted either" paragraph by what the
  job does, how to run it (stop the vault, run, restart), what stays (two copies of a detached
  duplicate; live-run effects; rotation not implemented); how custodians give their keys (piped
  from a file only they can read, or typed with echo off, never as an argument, so they stay out
  of the screen and the shell history); that a `rehash_row` entry records the attempt, written
  before the change, and `rehash_run` the result; update the T29 paragraph (the clean-up removes
  kept hash rows of deleted cards); correct every moved `file:line`.
- [ ] **Step 2**: `docs/threat-model.md`: T28 `proven` (control: the job's lines in
  `src/domain/hash.rs`; evidence: tests 1 to 6 of Task 1; the row says the job must be run); T22
  stays `open` (evidence adds `rehash_converges_rows_hashed_under_another_master_key` and the
  tokenization lines on the missing rotation); T29 wording; new row T30 `open` (live run:
  duplicate during the run, cached deleted row); "How to check it yourself" e2e list updated;
  every `file:line` reread.
- [ ] **Step 3**: `README.md`: new entry under "Changes from the original" listing every file of
  `git diff --name-only main` except `README.md`; reread the earlier entries (I6 says "older rows
  are not converted") and add, in the new entry, that the re-hash job now converts them.
- [ ] **Step 4: Run** `scripts/check-threat-model.sh` before (today: `OK: 29 rows (13 proven, 6 not tested, 10 open)`)
  and after; expected after: 30 rows, 14 proven (T28 added), 6 not tested, 10 open (T28 removed,
  T30 added); `grep -c -i -E 'GHSA|advisories' docs/threat-model.md README.md docs/tokenization.md`
  -> 0 each.
- [ ] **Step 5: Commit** `docs: describe the re-hash job in the threat model and tokenization page`.

### Task 8: Final checks, reviews, pull request

**Covers:** D12, D13, owner's completion criteria K7 to K18

- [ ] **Step 1**: `cargo fmt --all --check` (stable, exit 0; the nightly check runs only in CI),
  `cargo clippy -j 4 --all-features --all-targets`
  (compared with `main`), `cargo test -j 4`, full e2e, `make demo` with `DEMO_DATABASE_URL` to an
  empty database of the cluster -> `DEMO OK`.
- [ ] **Step 2**: `grep -i -F -f <scratchpad>/forbidden.txt` on the added lines of `git diff main`
  and on `git log main..HEAD --format=%B` -> no match;
  `git diff --name-only main -- demo config migrations src/storage/schema.rs Cargo.toml Cargo.lock .github CLAUDE.md .typos.toml LICENSE scripts`
  -> empty; every file of `git diff --name-only main` named in `README.md`.
- [ ] **Step 3**: `security-review` skill on the branch; a fresh `opus` reviewer and
  `second-avis --reserve 50` in parallel, each given the owner's request verbatim, the diff and the
  table, and asked to check that each added test fails if its control is removed. If a fix
  changes any file: rerun the tests touched, then Steps 1 and 2, `scripts/check-threat-model.sh`
  and the README list check (cluster re-created if removed).
- [ ] **Step 4**: stop, DOING / EXPECT / IF WRONG, ask to push:
  `git push -u origin feat/rehash-job` (`origin` = `antoinevoinchet-spec/hyperswitch-card-vault`,
  checked with `git remote get-url origin`).
- [ ] **Step 5**: write the PR title and body; `grep -i -F -f <scratchpad>/forbidden.txt` on them
  -> no match; stop, show them, ask; then
  `gh pr create -R antoinevoinchet-spec/hyperswitch-card-vault --base main --head feat/rehash-job`.
- [ ] **Step 6**: `gh pr checks <n> -R antoinevoinchet-spec/hyperswitch-card-vault --watch`;
  `gh pr list -R juspay/hyperswitch-card-vault --author antoinevoinchet-spec --state all` -> no row
  (a read, required verbatim by the owner's completion criteria; `CLAUDE.md` forbids writing to
  `juspay/*`, which this does not);
  `git status --porcelain` empty; cluster removed.
