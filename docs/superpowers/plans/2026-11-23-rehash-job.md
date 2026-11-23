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
- Files outside the owner's modifiable list touched by this plan, to be approved with the plan:
  `src/routes/key_custodian.rs` (make `aes_decrypt_custodian_key` public) and `src/routes/data.rs`
  (`mod transformers` becomes `pub(crate) mod transformers`, so the job reuses `get_hash`).
- The decrypted card stays in memory inside `StrongSecret`; no `logger` call, output line or error
  message takes decrypted data, a hash value or a key. Custodian keys are read from standard input,
  never from arguments.
- Timestamps in UTC (`crate::utils::date_time::now()`).
- English everywhere in the repository; no compliance wording (see `CLAUDE.md`).
- Rust commands are prefixed by `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"`
  and use `-j 4`.
- E2e runs use a throwaway TCP-only cluster in the session scratchpad, started before Task 1 step 2
  and removed after Task 8 step 1: `initdb -D <scratchpad>/pg -U postgres --auth=trust`, then
  `pg_ctl -D <scratchpad>/pg -o "-p 54330 -c unix_socket_directories=''" -l <scratchpad>/pg.log start`;
  e2e command: `VAULT_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:54330/postgres VAULT_TEST_REQUIRE_DB=1 cargo test -j 4 --features key_custodian --test vault_e2e`;
  cleanup: `pg_ctl -D <scratchpad>/pg stop` and `rm -rf <scratchpad>/pg`.
- One commit per task, after `git status`, English message, attribution lines.

## Review Focus

1. A tenant with no `locker` row at all: the command must exit 0 with all counts 0 and remove
   only unused hash rows older than the margin. Test: `rehash_on_an_empty_tenant_changes_nothing`
   (Task 1).
2. A row stored with `enc_card_data` (not a card): its hash must be the hash of that string, as
   `/data/add` computes it. Test: covered in `rehash_moves_v1_rows_to_scoped_hashes` by one
   `enc_card_data` row (Task 1).
3. Wrong custodian keys on standard input: the command must exit non-zero, change nothing and print
   no key. Test: `rehash_refuses_wrong_custodian_keys` (Task 1).
4. More rows than one internal batch: the cursor must reach every row. The batch size is an option
   of the command (`--batch-size`, default 100) and the e2e helper passes `--batch-size 2`, so
   every seeded data set (3 or 4 rows) spans at least two batches (Task 1).
5. A concurrent change of a row between read and update (0 rows updated): the job must stop with an
   error rather than count it as moved. Covered by code (update with `hash_id = old` condition and
   an error on 0 rows); no test (would need a concurrent writer); listed in the final report.

---

### Task 1: End-to-end tests that fail on `main`

**Covers:** D1, D2, D3, D4, D5, D6, D7, D8, D10, D11 (and Review Focus 1 to 4)

**Files:**
- Modify: `tests/vault_e2e.rs` (helpers after `store_card_as`, tests at the end)

**Interfaces:**
- Consumes: `TestDb`, `Keys`, `Vault`, `unlock`, `unlocked_master_key`, `store_card_as`,
  `CardDedupHmac` (all existing).
- Produces (test helpers, used only in this file):
  - `async fn store_card_with_ref(vault: &Vault, merchant: &str, customer: &str, data: serde_json::Value, reference: &str) -> serde_json::Value`
    (`data` is `{"card": {...}}` or `{"enc_card_data": "..."}`, merged into the add body with
    `requestor_card_reference`).
  - `fn run_rehash(db: &TestDb, keys: &Keys, args: &[&str]) -> (i32, String)` runs
    `env!("CARGO_BIN_EXE_utils") rehash --tenant public --batch-size 2 <args>` with the same
    `LOCKER__DATABASE__*` and `LOCKER__TENANT_SECRETS__PUBLIC__MASTER_KEY` variables as
    `Vault::start`, current dir `CARGO_MANIFEST_DIR`, writes `key1\nkey2\n` to standard input,
    returns the exit code and standard output plus standard error joined.
  - `fn expected_hash(master_key: &[u8], merchant: &str, customer: &str, hashed: &str) -> Vec<u8>`
    (`CardDedupHmac` over `serde_json::to_vec(hashed)`).
  - `fn seed_v1(db: &TestDb, master_key: &[u8], groups: &[(&str, &str, &[&str])])`: deletes every
    `hash_table` row; for each group `(hash_id, hashed, locker_ids)` inserts
    `(hash_id, <v1 hash of hashed>, created_at '2000-01-01')` and points those `locker` rows at it
    (the v1 value as in `tenant_wide_v1_hash_row_is_not_matched`); then inserts an unused
    `('orphan-v1', <64 random bytes>, created_at '2000-01-01')`.
  - `TestDb::snapshot(&self) -> (Vec<(String, String)>, Vec<(String, Vec<u8>)>)`: `(locker_id,
    hash_id)` ordered by `locker_id`, and `(hash_id, data_hash)` ordered by `hash_id`.
  - `TestDb::hash_of(&self, hash_id: &str) -> Option<Vec<u8>>`.

- [ ] **Step 1: Write the tests** (fixed references `ref-m1-c1`, `ref-m2-c1`, `ref-m1-c2`,
  `ref-enc`; the vault is dropped before each `run_rehash` and a new one started after, as the
  design's recommended operation, so its cache never serves a row the test deleted)

  - `rehash_moves_v1_rows_to_scoped_hashes`: store the card for (M1, C1), (M2, C1), (M1, C2) and
    `{"enc_card_data": "opaque-test-value"}` for (M1, C1) with `ref-enc`; `seed_v1` with groups
    `("legacy-v1", card, [three card refs])` and `("legacy-enc", "opaque-test-value", ["ref-enc"])`;
    drop the vault; `run_rehash` -> exit 0. Assert: each locker row's `hash_of(hash_id)` equals
    `expected_hash(.., merchant, customer, hashed)`; 4 distinct `hash_id`; `hash_of("legacy-v1")`,
    `hash_of("legacy-enc")` and `hash_of("orphan-v1")` are `None`; `count("hash_table") == 4`;
    output contains none of `4111111111111111`, the hex of any stored or expected hash,
    `keys.master_key`, `keys.key1`, `keys.key2`. Start a vault, unlock, add the card again for
    (M1, C1): `duplication_check == "duplicated"` and `count("locker") == 4`.
  - `rehash_detaches_the_older_duplicate`: store (M1, C1) `ref-old`; `seed_v1`; restart the vault;
    add the card again for (M1, C1) `ref-new` -> `duplication_check` is null (T28 symptom, asserted);
    drop the vault; `run_rehash` -> exit 0. Assert: `ref-new` cites the expected hash;
    `ref-old`'s `hash_id` differs from `ref-new`'s and `hash_of` it is `None`; no `legacy-v1`;
    restart, unlock: retrieve `ref-old` and `ref-new` both 200 with the card number; a third add ->
    `duplicated`, `count("locker") == 2`.
  - `rehash_twice_changes_nothing`: the data set of the previous test plus (M2, C1); run once
    (exit 0), `snapshot`, run again (exit 0), `snapshot` equal; the second output reports
    `moved: 0`, `duplicates: 1`, `removed hash rows: 0`.
  - `rehash_resumed_after_interruption_matches_a_full_run`: two databases, one `Keys`, the same
    data set as `rehash_moves_v1_rows_to_scoped_hashes`. Database A: one full run. Database B:
    `--max-rows 1` (exit 0, output `complete: no`); then write the two crash states by SQL: insert
    the expected hash row of `ref-m2-c1` unused (crash after insert), and move `ref-m1-c2` to a
    new hash row holding its expected hash while `legacy-v1` stays (crash after move); then a full
    run (exit 0, `complete: yes`). Assert: for every `locker_id`, `hash_of(hash_id)` is equal in A
    and B, and `count("hash_table")` is equal.
  - `rehash_audit_rows_hold_no_card_or_key`: after a run on the first data set, `audit_rows()`
    contains 4 `("rehash_row", "success", 200)` and 1 `("rehash_run", "success", 200)`; no row text
    contains the card number, `opaque-test-value`, the hex of any hash, or any key value.
  - `rehash_stops_when_audit_table_is_unwritable`: seed, drop the vault, rename `audit_log`,
    `run_rehash` -> exit non-zero; rename back; `snapshot` equals the one taken before the run.
  - `rehash_converges_rows_hashed_under_another_master_key`: store (M1, C1) and (M2, C1); rewrite
    each row's `data_hash` to `expected_hash(<32 random bytes>, merchant, customer, card)`; drop the
    vault; run -> exit 0; each row cites the expected hash under the real key;
    `count("hash_table") == 2`; restart, add (M1, C1) again -> `duplicated`.
  - `rehash_on_an_empty_tenant_changes_nothing`: unlock once (creates no locker row), insert
    `orphan-v1` old and a fresh unused row `fresh` with `created_at = now()`; run -> exit 0, output
    `examined: 0`; `orphan-v1` gone, `fresh` kept.
  - `rehash_refuses_wrong_custodian_keys`: seed; `run_rehash` with a wrong `key2` -> exit non-zero,
    `snapshot` unchanged, output contains no key value.

- [ ] **Step 2: Run them on the current code and keep the failure output for the report**

Run: the e2e command of Global Constraints with the filter `rehash`, output kept in
`<scratchpad>/rehash-red.txt`.
Expected: 9 failed, each on the `run_rehash` exit-code assertion (argh: unrecognized `rehash`);
the 8 existing e2e tests still pass when run without the filter.

- [ ] **Step 3: Commit**

```bash
git add tests/vault_e2e.rs
git commit -m "test: add end-to-end tests for the re-hash job (failing: no command yet)"
```

### Task 2: Audit operations and the count balance

**Covers:** D6, D9

**Files:**
- Modify: `src/audit.rs` (enum, `as_str`, two constructors, unit tests)
- Modify: `src/domain/hash.rs` (report type and its unit tests)

**Interfaces:**
- Produces:
  - `AuditOperation::RehashRow` -> `"rehash_row"`, `AuditOperation::RehashRun` -> `"rehash_run"`.
  - `pub fn rehash_row_audit(tenant_id: &str, merchant_id: &str, customer_id: &str, locker_id: &str) -> PendingAudit`
    (merchant, customer, resource), `pub fn rehash_run_audit(tenant_id: &str) -> PendingAudit`.
  - In `src/domain/hash.rs`: `#[derive(Debug, Default, Clone, PartialEq, Eq)] pub struct RehashReport { pub examined: u64, pub current: u64, pub moved: u64, pub duplicates: u64, pub removed_hash_rows: u64, pub complete: bool }`
    and `pub(crate) fn check_balance(&self) -> Result<(), ContainerError<error::ApiError>>`,
    which returns `ApiError::DatabaseError` when `examined != current + moved + duplicates`.

- [ ] **Step 1: Write failing unit tests**: `rehash_row_entry_has_ids_only` (card-shaped locker id
  is redacted; operation `rehash_row`; JSON has merchant and customer), `report_balance_accepts_matching_counts`,
  `report_balance_rejects_mismatched_counts` (`examined: 3, current: 1, moved: 1` -> `Err`).
- [ ] **Step 2: Run** `cargo test -j 4 --lib rehash report_balance` -> compile errors (types absent).
- [ ] **Step 3: Implement** the items above.
- [ ] **Step 4: Run** the same command -> 3 passed.
- [ ] **Step 5: Commit** `feat: add re-hash audit operations and the count balance check`.

### Task 3: Storage primitives

**Covers:** D1, D2, D4, D5 (prerequisites)

**Files:**
- Modify: `src/storage.rs:528-580` (trait methods)
- Modify: `src/storage/db.rs` (PostgreSQL implementations; under `kv` each returns an error)
- Modify: `src/storage/caching/hash_table.rs` (forward, invalidate deleted keys)

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
  - The cache layer forwards each and calls `invalidate` on the `hash_table` cache for every
    returned `data_hash`.
  - Under `feature = "kv"`: each returns `Err` with the table's existing "DB error" variant, so the
    job refuses to run on a partial view.

- [ ] **Step 1: Implement** the five methods (no unit test possible without a database; they are
  exercised by Task 1's tests once Task 4 and 5 land).
- [ ] **Step 2: Run** `cargo build -j 4 --features key_custodian` and
  `cargo clippy -j 4 --all-features --all-targets` -> exit 0, no new warning compared with `main`
  (the `kv` branch compiles under `--all-features`).
- [ ] **Step 3: Commit** `feat: add storage primitives for the re-hash job`.

### Task 4: The job

**Covers:** D1, D2, D4, D5, D8, D9, D10, D11

**Files:**
- Modify: `src/domain/hash.rs`
- Modify: `src/routes/data.rs:2` (`pub(crate) mod transformers;`, approved with the plan)

**Interfaces:**
- Consumes: Task 2 (`RehashReport`, audit constructors), Task 3 (primitives),
  `transformers::get_hash`, `CardDedupHmac::from_master_key`, `crypto_operation::decrypt_data`,
  `keymanager::get_dek_manager(..).find_by_entity_id`, `hash::insert_or_get`, `audit::record`,
  `storage::utils::generate_uuid`.
- Produces: `pub async fn rehash(state: &TenantAppState, batch_size: i64, max_rows: Option<u64>) -> Result<RehashReport, ContainerError<error::ApiError>>`.

- [ ] **Step 1: Implement `rehash`** following the design's "How one row is processed" exactly:
  - run start `t0 = now()`; cursor `0`; loop `find_locker_batch(cursor, batch_size)`; stop when a
    batch is empty, or when `examined` reaches `max_rows` (then `complete = false`).
  - per row: decrypt; `serde_json::from_slice::<StoredData>`; map `CardData(card)` to
    `Data::Card { card }` and `EncData(s)` to `Data::EncData { enc_card_data: s }`; `H = get_hash(&data, CardDedupHmac::from_master_key(master_key, merchant, customer)?)`.
  - current: cited row exists and its `data_hash` equals `H` (compare with `PeekInterface`, no
    printing) -> `current += 1`.
  - target row = `find_optional_by_data_hash(H)`; if it exists and
    `find_optional_by_hash_id_merchant_id_customer_id(target.hash_id, merchant, customer)` returns
    a row with another `locker_id` -> duplicate: if the cited row does not exist, `duplicates += 1`
    and nothing is written (already detached); else write `rehash_row` audit, update to
    `generate_uuid()`, `delete_hash_if_unused(old)`, `duplicates += 1`.
  - otherwise target = existing row or `insert_or_get(H)`; write `rehash_row` audit (fail-closed:
    an `Err` stops the job); `update_locker_hash_id(.., old, target.hash_id)`; 0 rows -> stop with
    an error; `delete_hash_if_unused(old)`; `moved += 1`.
  - when complete: `check_balance()?`, then `delete_unused_hashes_before(t0 - 60 s)`, add to
    `removed_hash_rows` (also add the per-row deletions).
  - the whole result goes through `audit::record(&state.db, rehash_run_audit(tenant), result)`.
  - no `logger` call with decrypted data, `H`, or any key; errors carry static strings only.
- [ ] **Step 2: Run** `cargo build -j 4 --features key_custodian` -> exit 0.
- [ ] **Step 3: Commit** `feat: add the re-hash job to the hash domain`.

### Task 5: The `utils rehash` command

**Covers:** D7, D8, D12 (and Review Focus 3)

**Files:**
- Modify: `src/bin/utils.rs`
- Modify: `src/routes/key_custodian.rs:221` (`pub async fn aes_decrypt_custodian_key`, approved
  with the plan; body unchanged)

**Interfaces:**
- Consumes: Task 4 `rehash`; `GlobalConfig::new`, `validate`, `fetch_raw_secrets`;
  `TenantConfig::from_global_config`; `ApiClient::new`; `RuntimeConfigManager::new`;
  `GlobalStore::new`; `TenantAppState::new` (the same wiring as `GlobalAppState::new` and
  `decrypt_inner`).
- Produces: subcommand `rehash` with `--tenant <id>` (required), `--batch-size <n>` (default 100),
  `--max-rows <n>` (optional). Under `key_custodian`: reads two lines (key 1, key 2) from standard
  input and unlocks the master key with `aes_decrypt_custodian_key`. Output, one per line:
  `examined: N`, `current: N`, `moved: N`, `duplicates: N`, `removed hash rows: N`,
  `complete: yes|no`. Exit 0 on success; on error prints `rehash failed` and the error kind
  (variant name only, as the audit log does) and exits 1.

- [ ] **Step 1: Implement**; `main` stays synchronous and runs the subcommand in a
  `tokio::runtime::Runtime`; no logger setup.
- [ ] **Step 2: Run the Task 1 tests** (Task 6 command, filter `rehash`) -> 9 passed.
- [ ] **Step 3: Run the whole suite**: `cargo test -j 4` (at least 44 passed: 41 + Task 2's 3) and the
  full e2e command (at least 17 passed, `0 failed`).
- [ ] **Step 4: Commit** `feat: add the utils rehash command`.

### Task 6: Deliberate breakages

**Covers:** the owner's main rule (each test seen failing when its control is removed)

**Files:** none committed (each breakage is reverted with `git checkout -- <file>` and the revert
checked with `git diff --quiet`).

- [ ] **Step 1**: for each line, apply the breakage (on the cluster of Global Constraints), run the named test(s), record the failing
  assertion, revert:

| Breakage | Test expected to fail |
|---|---|
| merchant id replaced by `""` in the job's `CardDedupHmac` call | `rehash_moves_v1_rows_to_scoped_hashes` |
| no `delete_hash_if_unused` and no final clean-up | `rehash_moves_v1_rows_to_scoped_hashes` (legacy and orphan rows remain) |
| "already detached" check removed | `rehash_twice_changes_nothing` |
| duplicate branch skipped (row left on its old hash) | `rehash_detaches_the_older_duplicate` |
| "current" decided by existence of the cited row only (no `data_hash` comparison) | `rehash_converges_rows_hashed_under_another_master_key` |
| `insert_or_get` replaced by `insert_hash` | `rehash_resumed_after_interruption_matches_a_full_run` |
| audit error ignored (`let _ =`) | `rehash_stops_when_audit_table_is_unwritable` |
| decrypted card printed in the output | `rehash_moves_v1_rows_to_scoped_hashes` (output check) |
| `check_balance` always `Ok` | `report_balance_rejects_mismatched_counts` |
| margin of the final clean-up set to 0 s (the `fresh` row is then deleted) | `rehash_on_an_empty_tenant_changes_nothing` |
| custodian keys accepted without the AES-GCM check (master key taken as given) | `rehash_refuses_wrong_custodian_keys` |

- [ ] **Step 2**: `git status --porcelain` empty after the last revert.

### Task 7: Threat model, tokenization page, README

**Covers:** D13

**Files:**
- Modify: `docs/threat-model.md`, `docs/tokenization.md`, `README.md`

- [ ] **Step 1**: `docs/tokenization.md`: replace the "not converted either" paragraph by what the
  job does, how to run it (stop the vault, run, restart), what stays (two copies of a detached
  duplicate; live-run effects; rotation not implemented); update the T29 paragraph (the clean-up
  removes kept hash rows of deleted cards); correct every moved `file:line`.
- [ ] **Step 2**: `docs/threat-model.md`: T28 `proven` (control: the job's lines in
  `src/domain/hash.rs`; evidence: the D1 to D5 and D11 tests; the row says the job must be run);
  T22 stays `open` (evidence adds `rehash_converges_rows_hashed_under_another_master_key` and the
  tokenization lines on the missing rotation); T29 wording; new row T30 `open` (live run:
  duplicate during the run, cached deleted row); T3 or T5 evidence gains the two audit tests if
  they prove the row; "How to check it yourself" list of e2e rows updated; every `file:line`
  reread.
- [ ] **Step 3**: `README.md`: new entry under "Changes from the original" listing every file of
  `git diff --name-only main`.
- [ ] **Step 4: Run** `scripts/check-threat-model.sh` -> `OK: 30 rows (14 proven, 6 not tested, 10 open)`;
  `grep -c -i -E 'GHSA|advisories' docs/threat-model.md README.md docs/tokenization.md` -> 0 each.
- [ ] **Step 5: Commit** `docs: describe the re-hash job in the threat model and tokenization page`.

### Task 8: Final checks, reviews, pull request

**Covers:** D12, completion criteria

- [ ] **Step 1**: `cargo fmt --all --check`, `cargo clippy -j 4 --all-features --all-targets`
  (compare with `main`), `cargo test -j 4`, full e2e, `make demo` with `DEMO_DATABASE_URL` -> `DEMO OK`.
- [ ] **Step 2**: forbidden-wording search (pattern in the scratchpad) on added lines of
  `git diff main`, on `git log main..HEAD --format=%B`; locked-paths diff empty; README lists every
  changed file.
- [ ] **Step 3**: `security-review` skill on the branch; fresh `opus` reviewer and
  `second-avis --reserve 50` in parallel, each given the owner's request verbatim, the diff and the
  table, and asked to check that each added test fails if its control is removed.
- [ ] **Step 4**: stop: DOING / EXPECT / IF WRONG, ask to push `feat/rehash-job`; then show the PR
  title and body, ask to open it on `antoinevoinchet-spec/hyperswitch-card-vault` (base `main`);
  `gh pr checks <n> -R antoinevoinchet-spec/hyperswitch-card-vault`.
