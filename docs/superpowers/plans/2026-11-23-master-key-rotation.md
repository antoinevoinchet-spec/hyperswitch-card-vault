# Master key rotation (T22) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `utils rotate-master-key` re-encrypts every merchant key of a tenant under a new master key,
then recomputes every duplicate-check hash under it, resumably and with an audit trail, proven by
end-to-end tests in every mode, the external key manager mode included.

**Architecture:** An offline `utils` subcommand (vault stopped) reads both keys from standard input,
builds the tenant state with the new master key, and calls `domain::master_key::rotate`. That
function checks every merchant row in read-only mode, rewrites each row still wrapped by the former
key (audit entry first, conditional update), checks that every row opens under the new key only,
then calls the existing `domain::hash::rehash`. The AES-GCM tag tells which key wraps a row, so no
progress is stored.

**Tech Stack:** Rust, diesel/async-bb8-diesel on PostgreSQL, `ring` through `GcmAes256` and
`CardDedupHmac`, argh, the existing e2e harness (`tests/vault_e2e.rs`), GitHub Actions; for the
external mode, Juspay's Hyperswitch Encryption Service (`cripta`) v0.1.14 built from source.

**Spec:** `docs/superpowers/specs/2026-11-23-master-key-rotation-design.md`

## Global Constraints

- No hand-written cryptography: `GcmAes256`, `CardDedupHmac` and `ring` only. No new dependency;
  `Cargo.toml` and `Cargo.lock` unchanged.
- No change to `migrations/`, `config/`, `demo/`, `deny.toml`, `CLAUDE.md`, `.typos.toml`, `LICENSE`,
  `scripts/`; no change to existing HTTP routes or existing CI jobs (jobs are only added).
- Keys arrive on standard input only. No key, key part, merchant key, hash or derived value in any
  output, log line, error message, audit row or commit. Test keys come from `utils master-key` or
  `ring` randomness and are never printed.
- Exit codes: 0 done, 2 stopped by `--max-rows`, 1 error; errors print `rotation failed: <ApiError
  variant>` only.
- English everywhere in the repository; no compliance wording (see `CLAUDE.md`); `GHSA` and
  `advisories` never in `docs/threat-model.md`, `README.md`, `docs/tokenization.md`.
- Every `cargo` command is prefixed with
  `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"` and uses `-j 4`.
- Commit after each verified step, on `feat/master-key-rotation`; `git status` before each commit.

## Review Focus

- Fewer than five lines on standard input (a custodian pressed Enter too early): refused like a wrong
  key, no row changed. Pinned in Task 1, test 5 (case "four lines").
- A tenant with no merchant row: exit 0, the hash step still runs. Pinned in Task 1, test 10.
- A merchant created by `POST /entity` that never stored a card: its row is rotated too. Pinned in
  Task 1, test 1 (third merchant) and test 2 (all rows checked).
- Without custodians, a new master key of the wrong length: refused with `ValidationError`, no row
  changed. Pinned in Task 1, test 6 (second case).
- The command run again after a complete rotation, same keys: exit 0, nothing changes. Pinned in
  Task 1, test 4 (third run on the full database).

## Error kinds (decided here, asserted by the tests)

| Situation | Printed kind |
|---|---|
| Former or new custodian keys do not open their encrypted master key; fewer than five lines | `DecryptingKeysFailed` |
| New master key equal to the former; raw new key not 32 bytes; batch size below 1 | `ValidationError` |
| A merchant row opens under neither key (pre-check), or the final check fails | `MerchantKeyError` |
| Conditional update changed 0 rows | `DatabaseError` |
| Under `kv` (the locker read of the pre-check) | `RetrieveDataFailed` |

## Output (counts only, one per line)

`merchant rows: <n>`, `rewritten: <n>`, `already under the new key: <n>`, then, once the hash step has
run, the `utils rehash` lines prefixed `hash ` (`hash examined`, `hash current`, `hash moved`,
`hash duplicates`, `hash removed hash rows`), then `complete: yes|no`.

---

### Task 1: End-to-end tests that fail on the current code

**Covers:** D1, D2, D3, D4, D5, D6, D7, D8, D9, D10, D13

**Files:**
- Modify: `tests/vault_e2e.rs` (new helpers and tests appended after the re-hash tests; existing
  helpers and tests unchanged)

**Interfaces:**
- Produces (test helpers, new):
  - `fn run_rotation(db: &TestDb, former: &Keys, stdin: &str, args: &[&str]) -> (i32, String)`:
    spawns `utils rotate-master-key --tenant public --batch-size 2 <args>` with the former master key
    in `LOCKER__TENANT_SECRETS__PUBLIC__MASTER_KEY`, writes `stdin`, 120 s deadline, returns exit code
    and joined stdout/stderr (same shape as `run_rehash`, which stays untouched). Passes
    `LOCKER__EXTERNAL_KEY_MANAGER__MODE`/`URL` through when `VAULT_TEST_KEY_MANAGER_URL` is set.
  - `fn rotation_input(former: &Keys, new: &Keys) -> String`: with `key_custodian`
    `"{former.key1}\n{former.key2}\n{new.master_key}\n{new.key1}\n{new.key2}\n"`; without it
    `"{new.master_key}\n"` (raw hex, as `Keys::generate` gives it in that mode).
  - `fn merchant_rows(db: &TestDb) -> Vec<(String, Vec<u8>)>`: `(merchant_id, enc_key)` ordered by
    `merchant_id`.
  - `fn merchant_snapshot(db: &TestDb) -> Vec<String>`: `SELECT t::text … FROM merchant t ORDER BY merchant_id`.
  - `fn opens(key: &[u8], blob: &[u8]) -> Option<Vec<u8>>`: `GcmAes256::new(key).decrypt(blob).ok()`.
  - `fn rotation_secrets(db, former, new, deks) -> Vec<String>`: `secrets(...)` of both key sets
    plus hex of each raw master key, each merchant key, each `enc_key` before and after, every hash.
- Consumes: `TestDb`, `Keys`, `Vault`, `unlock`, `store_card_with_ref`, `store_card_as`,
  `card_request`, `unlocked_master_key`, `expected_hash`, `snapshot`, `assert_no_secret`,
  `random_bytes`, `insert_hash_row`.

Tests (names exact; gating in brackets; each starts with `let Some(admin) = admin_url() else { return };`):

- [ ] **Step 1: Write the tests**

  Writing rule: no assertion may print a key on failure. Key bytes are compared with
  `assert!(a == b, "<merchant_id> …")` or turned into booleans first, never with `assert_eq!`; the
  failure lines copied into the report in Task 6 are reread before they are pasted.

  1. `rotation_cards_read_back_for_two_merchants` — store the test card for `MERCHANT` (`ref-m1`) and
     `MERCHANT_2` (`ref-m2`), `POST /entity` for `merchant-no-card`; record each merchant key
     (`opens(former_raw, enc_key)`); stop the vault; `run_rotation` → `code == 0`,
     `output.contains("rewritten: 3")`. Start the vault with `new.master_key`, `unlock(&vault, &new)`;
     each reference: status 200 and body contains `CARD_NUMBER`. Every row:
     `opens(new_raw, enc_key) == Some(dek_before)`.
  2. `rotation_former_key_opens_no_merchant_row` — same seed; after the run, every row:
     `opens(former_raw, enc_key).is_none()` and `opens(new_raw, enc_key).is_some()`.
  3. `rotation_keeps_duplicate_detection` — seed one card for `MERCHANT`; rotate; new vault; the same
     add returns `duplication_check == "duplicated"` and `db.count("locker") == 1`; every `locker` row
     cites `expected_hash(new_raw, …)`. Then, vault stopped, `run_rehash(&db, &new, &new.key2, &[])` →
     `code == 0` and `moved: 0` (the check the docs give the operator after the configuration change).
  4. `rotation_resumed_after_interruption_matches_a_full_run` — two databases, same data set (three
     merchants, one card each, plus `ref-m1-c2` for `MERCHANT`/`CUSTOMER_2`). Full: one run. Resumed:
     run with `--max-rows 1` → `code == 2`, `rewritten: 1`, `complete: no` (stopped between rows, hash
     step not run); a second run with `--max-rows 1`, started from that mixed state with no help →
     `code == 2`, `rewritten: 1`, `already under the new key: 1` (it progresses); then the test itself
     rewraps the last merchant row under the new key (a run killed after its last row, before the
     hash step); then a run that completes. Compare
     `canonical(db)`: per merchant `(merchant_id, opens new, opens former, merchant key unchanged)`;
     per `locker` row `(locker_id, enc_data equal to before, cited hash == expected_hash(new_raw, …))`;
     `count("hash_table")`. Then a third run on the full database: `code == 0`,
     `already under the new key: 3`, `(snapshot(), merchant_snapshot())` unchanged.
  5. `rotation_refuses_wrong_custodian_keys` [`key_custodian`] — cases: wrong former key 2; wrong new
     key 2; new encrypted master key of another `Keys::generate()`; only four lines. Each: `code == 1`,
     `output.contains("rotation failed: DecryptingKeysFailed")`, `(snapshot(), merchant_snapshot())`
     unchanged, one more `master_key_rotation_run` audit row with outcome `failure`,
     `assert_no_secret`.
  6. `rotation_refuses_the_same_master_key` — new keys = former keys (custodian: same parts and same
     encrypted key; without: the same raw key) → `rotation failed: ValidationError`, snapshots
     unchanged. Second case, without `key_custodian` only: a raw new key of 31 bytes →
     `ValidationError`, snapshots unchanged. Third case, with `key_custodian` only: the former raw
     master key encrypted in the test under the parts of another `Keys::generate()` (a change of
     custodian keys only, which is out of scope) → `ValidationError`, snapshots unchanged.
  7. `rotation_refuses_a_row_under_a_third_key` — seed two merchants through the vault, then insert a
     merchant `merchant-third` (highest `id`) whose `enc_key` is `GcmAes256(random_bytes(32))` of a
     random key → `rotation failed: MerchantKeyError`, snapshots unchanged.
  8. `rotation_audit_and_output_hold_no_key` — seed as test 1; run; audit rows filtered on
     `master_key_rotation_`: three `("master_key_rotation_row", "success", 200)` then one
     `("master_key_rotation_run", "success", 200)`; `assert_no_secret` on every audit row and on the
     output with `rotation_secrets`.
  9. `rotation_stops_when_audit_table_is_unwritable` — seed; rename `audit_log`; run → `code == 1`,
     `output.contains("rotation failed")`, snapshots unchanged; rename back.
  10. `rotation_on_an_empty_tenant_succeeds` — no merchant, no card → `code == 0`,
      `merchant rows: 0`, `hash examined: 0`, `complete: yes`.
  13. `rotation_refuses_a_batch_size_of_zero` — seed one card; `--batch-size 0` →
      `rotation failed: ValidationError`, snapshots unchanged.
  11. `rotation_refuses_to_run_with_kv` [`kv`] — no vault; insert one merchant row by SQL under the
      former raw key → `rotation failed: RetrieveDataFailed`, snapshots unchanged, audit
      `master_key_rotation_run` `failure`.
  12. `rotation_with_external_key_manager` [`external_key_manager`; when `VAULT_TEST_KEY_MANAGER_URL` is
      unset it panics if `VAULT_TEST_REQUIRE_DB` is set, and otherwise returns early printing
      "skipped"] — vault started with
      `LOCKER__EXTERNAL_KEY_MANAGER__MODE=enabled` and `__URL`; store the card for `MERCHANT` and
      `MERCHANT_2`; insert `legacy-merchant` (merchant row, `enc_key` = `GcmAes256(former_raw)` of a
      random 32-byte key, no `entity` row); stop; rotate → `code == 0`; new vault: both references
      read back, a second add for `MERCHANT` returns `duplicated`; `legacy-merchant` opens under the
      new key only; `POST /key/transfer` `{"limit": 10}` → 200 and `total_transferred == 1`.
  Existing helpers are unchanged except one: `Vault::start` keeps its signature and calls a new
  `Vault::start_with_env(db, master_key, extra: &[(&str, &str)])` with `&[]`; the external test passes
  the two key manager variables through it.

- [ ] **Step 2: Start the throwaway PostgreSQL (TCP only, port 54330) and run them**

Run: `VAULT_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:54330/postgres VAULT_TEST_REQUIRE_DB=1 cargo test -j 4 --features key_custodian --test vault_e2e rotation_`
Expected: 11 tests FAIL (the subcommand does not exist: `utils` exits 1 with argh's "Unrecognized
argument"); the 20 earlier tests still pass when run without the filter. Then
`… --features key_custodian,kv --test vault_e2e rotation_refuses_to_run_with_kv -- --exact` → FAIL.
Test 12 needs the service and is first seen failing in Task 7, Step 4. Keep the outputs.

- [ ] **Step 3: Commit**

```bash
git add tests/vault_e2e.rs
git commit -m "test: add failing end-to-end tests for master key rotation"
```

### Task 2: Audit operations

**Covers:** D8

**Files:**
- Modify: `src/audit.rs` (enum, `as_str`, two builders, one unit test)

**Interfaces:**
- Produces: `AuditOperation::MasterKeyRotationRow` (`"master_key_rotation_row"`),
  `AuditOperation::MasterKeyRotationRun` (`"master_key_rotation_run"`);
  `pub fn master_key_rotation_row_audit(tenant_id: &str, merchant_id: &str) -> PendingAudit`
  (merchant only); `pub fn master_key_rotation_run_audit(tenant_id: &str) -> PendingAudit`.

- [ ] **Step 1: Unit test `master_key_rotation_entries_have_ids_only`**: row entry has
  `operation == "master_key_rotation_row"`, `merchant_id == Some("merchant_abc")`, `customer_id`,
  `resource_id`, `request_id` all `None`; run entry `operation == "master_key_rotation_run"`,
  `merchant_id == None`.
- [ ] **Step 2:** `cargo test -j 4 --lib master_key_rotation_entries` → FAIL (unknown function).
- [ ] **Step 3:** Implement as above.
- [ ] **Step 4:** Same command → PASS. Breakage B17: also set `resource_id` to the merchant id →
  FAIL; revert.
- [ ] **Step 5:** Commit `feat: add audit operations for master key rotation`.

### Task 3: Storage primitives for merchant rows

**Covers:** D1, D3, D5, D7

**Files:**
- Modify: `src/storage.rs` (`MerchantInterface`), `src/storage/types.rs` (one struct),
  `src/storage/db.rs` (implementation), `src/storage/caching/merchant.rs` (forwarding)

**Interfaces:**
- Produces:
  - `pub struct EncryptedMerchant { pub id: i32, pub merchant_id: String, pub enc_key: Secret<Vec<u8>> }`
    in `types.rs`.
  - `async fn find_merchant_batch(&self, after_id: i32, limit: i64) -> Result<Vec<EncryptedMerchant>, ContainerError<Self::Error>>`
    — `id > after_id ORDER BY id LIMIT limit`, primary connection (not the replica).
  - `async fn update_merchant_enc_key(&self, merchant_id: &str, expected: Secret<Vec<u8>>, new: Secret<Vec<u8>>) -> Result<usize, ContainerError<Self::Error>>`
    — `UPDATE merchant SET enc_key = $new WHERE merchant_id = $id AND enc_key = $expected`, diesel
    DSL (bound parameters).
  - The cache forwards both without caching. No merchant is cached in the command's process before
    its update (the pre-check reads batches, not `find_by_merchant_id`), so no invalidation is added.
- Both run on PostgreSQL in every mode (the `merchant` table is never in KV).

- [ ] **Step 1:** Implement; `cargo build -j 4 --features key_custodian` and
  `cargo build -j 4 --all-features` → exit 0. Tests 1 to 9 exercise both primitives end to end. The
  `AND enc_key = expected` guard (a writer changing the row between the read and the update) cannot be
  reached from the tests without a concurrent writer: written "read in the code, not tested" in the
  docs, as for the re-hash job's own guard.
- [ ] **Step 2:** Commit `feat: add merchant batch read and conditional key update`.

### Task 4: Rotation job

**Covers:** D1, D3, D4, D5, D7, D8, D10

**Files:**
- Create: `src/domain/master_key.rs`
- Modify: `src/domain.rs` (`pub mod master_key;`)

**Interfaces:**
- Consumes: Task 2 builders, Task 3 primitives, `domain::hash::{rehash, RehashReport}`.
- Produces:
  - `pub enum WrappedBy { New, Former, Neither }` and
    `pub(crate) fn wrapped_by(blob: &[u8], new: &GcmAes256, former: &GcmAes256) -> WrappedBy`
    (tries the new key first).
  - `pub(crate) fn final_check(rows: &[EncryptedMerchant], new: &GcmAes256, former: &GcmAes256) -> Result<(), ContainerError<ApiError>>`
    — `MerchantKeyError` if any row is not `New` or also opens under the former key.
  - `pub struct RotationReport { pub merchants: u64, pub rewritten: u64, pub already_new: u64, pub hashes: Option<RehashReport>, pub complete: bool }`.
  - `pub async fn rotate(state: &TenantAppState, former_master_key: &Secret<Vec<u8>>, batch_size: i64, max_rows: Option<u64>) -> Result<RotationReport, ContainerError<ApiError>>`
    — `state.config.tenant_secrets.master_key` is the new key. Order: refuse `batch_size < 1` and
    equal keys (`ValidationError`); pre-check: `state.db.find_locker_batch(0, 1)` (refusal under
    `kv` before any write), then every merchant batch, any `Neither` → `MerchantKeyError`; rewrite
    rows `Former` in `id` order (decrypt under former, `GcmAes256::encrypt` under new,
    `master_key_rotation_row_audit` recorded first, update returning 0 → `DatabaseError`); `max_rows`
    counts rewritten rows: once that many are rewritten and another `Former` row remains, stop with
    `complete = false`; when complete, `final_check` over every row read again, then
    `hash::rehash(state, batch_size, None)`. The whole result goes through
    `audit::record(&state.db, master_key_rotation_run_audit(..), result)`. Decrypted merchant keys
    live in `Secret`/`StrongSecret` and are dropped after each row.

- [ ] **Step 1: Unit tests** `wrapped_by_tells_the_key_apart` (blob from `GcmAes256` under key A:
  `New` with A as new; `Former` with A as former; `Neither` with two other keys),
  `wrapped_by_prefers_the_new_key` (same key passed as both → `New`),
  `final_check_accepts_rows_under_the_new_key_only`, `final_check_refuses_a_row_still_under_the_former_key`,
  `final_check_refuses_a_row_under_neither_key`.
- [ ] **Step 2:** `cargo test -j 4 --lib master_key` → FAIL; implement; → PASS (5 tests).
- [ ] **Step 3:** Commit `feat: add the master key rotation job`.

### Task 5: `utils rotate-master-key`

**Covers:** D6, D9, D10, D13

**Files:**
- Modify: `src/bin/utils.rs`

**Interfaces:**
- Consumes: `domain::master_key::{rotate, RotationReport}`, `routes::key_custodian::aes_decrypt_custodian_key`, `error_kind`.
- Produces: subcommand `rotate-master-key` with `--tenant` (required), `--batch-size` (default 100),
  `--max-rows` (optional); no key option.
- Flow: load and validate the configuration as `run_rehash` does; read five lines (custodian) or one
  (without); former key: `aes_decrypt_custodian_key` on the configured value (custodian) or the
  configured key; new key: hex-decode line 3 into a clone of the tenant config and call
  `aes_decrypt_custodian_key` with lines 4 and 5 (custodian), or hex-decode line 1 and require 32
  bytes (without). On an unlock or input failure: build the tenant state from the configuration as
  is, record `master_key_rotation_run` with the error, print the kind, exit 1. Otherwise build the
  state with the new key and call `rotate`. Print the output lines above; exit 0, 2 or 1.

- [ ] **Step 1:** Implement; `cargo build -j 4` in default, `key_custodian`, and `--all-features`.
  `utils rotate-master-key --help` lists only `--tenant`, `--batch-size`, `--max-rows` (D9).
- [ ] **Step 2:** Run Task 1's tests with `key_custodian` → 11 passed (tests 11 and 12 not compiled),
  then the full e2e file → 0 failed, 31 passed.
- [ ] **Step 3:** Without `key_custodian`: `cargo test -j 4 --test vault_e2e rotation_` → 10 passed
  (tests 5, 11, 12 not compiled); with `--features key_custodian,kv … rotation_refuses_to_run_with_kv -- --exact` → 1 passed.
- [ ] **Step 4:** Commit `feat: add the rotate-master-key command to utils`.

### Task 6: Deliberate breakages (each seen failing, then reverted with `git checkout -- <file>`)

**Covers:** the owner's main rule, D1–D10

Each line: the breakage, the test that must fail, the line of failure to copy into the report.

- [ ] B1 skip the update of rewritten rows → tests 1, 2, 8 fail (exit 1: final check); B1b also skip
  the final check → test 1 fails on the retrieve status.
- [ ] B2 write the row re-encrypted under the former key, final check removed → test 2 fails on
  "opens under the former key".
- [ ] B3 remove the `hash::rehash` call → test 3 fails on `duplicated`.
- [ ] B4 treat a row already under the new key as `Neither` → test 4 fails (second run exit 1).
- [ ] B5a accept the new encrypted key without decrypting it (use the bytes as given) and skip the
  pre-check → test 5 ("wrong new key 2") fails on the snapshot.
- [ ] B5b when the former key does not unlock, go on with the configured bytes → test 5 ("wrong
  former key 2") fails on the printed kind (`MerchantKeyError`).
- [ ] B5c accept four lines (missing fifth read as empty, unlock skipped) → test 5 ("four lines")
  fails.
- [ ] B6 remove the pre-check → test 7 fails on the snapshot (the third-key row has the highest id).
- [ ] B7 put the decrypted merchant key, as hex, in the row entry's `resource_id` → test 8 fails.
- [ ] B8 record the row entry after the update → test 9 fails on the snapshot.
- [ ] B9 remove the pre-check's locker read → test 11 fails on the snapshot.
- [ ] B10 remove the equality refusal → test 6 fails on the printed kind (first and third cases).
- [ ] B11 make `final_check` always return `Ok` → the three `final_check_` unit tests fail.
- [ ] B12 remove the 32-byte check of the raw new key → test 6 (second case) fails (without
  `key_custodian`).
- [ ] B13 print the new master key's hex in the output → test 8 fails on the output.
- [ ] B14 skip the hash step when the tenant has no merchant → test 10 fails on `hash examined: 0`.
- [ ] B15 try the former key before the new one in `wrapped_by` → `wrapped_by_prefers_the_new_key`
  fails.
- [ ] B16 return `Former` instead of `Neither` → `wrapped_by_tells_the_key_apart` fails.
- [ ] B18 remove the batch size refusal → test 13 fails.
- [ ] Revert all; `git diff` empty on `src/`.

### Task 7: External key manager mode, locally

**Covers:** D13

**Approval needed before Step 1** (owner's point 3: third-party code built and run on the Mac).

- [ ] **Step 1:** Clone `juspay/hyperswitch-encryption-service` at commit
  `18423c5864676604a226e18ea3fff433224b3010` (tag `v0.1.14`) into the session's scratchpad; `cargo
  build -j 4 --release --locked` with no feature (AES-256 key, plain HTTP).
- [ ] **Step 2:** On the throwaway cluster: `CREATE DATABASE encryption_db`; apply its six
  `migrations/*/up.sql` in order; start `cripta` with `CRIPTA__DATABASE__*`,
  `CRIPTA__SERVER__PORT=5000`, `CRIPTA__SECRETS__MASTER_KEY` from `openssl rand -hex 32` held in a
  shell variable, never echoed; wait for its health route.
- [ ] **Step 3:** `VAULT_TEST_KEY_MANAGER_URL=http://127.0.0.1:5000 … cargo test -j 4 --features key_custodian,external_key_manager --test vault_e2e rotation_with_external_key_manager -- --exact` → 1 passed.
- [ ] **Step 4:** Breakages: B3 (hash step) → fails on `duplicated`; B1b (rewrite) → fails on the
  legacy row or `/key/transfer`. Revert.
- [ ] **Step 5:** Stop `cripta`, drop `encryption_db`; commit any test fix found here.

Two failed attempts at getting `cripta` to serve requests stop this task: report, then ask.

### Task 8: CI jobs (added only)

**Covers:** D10, D13

**Files:**
- Modify: `.github/workflows/CI-pr.yml` (three jobs appended; pinned actions as in `rehash-kv`)

- [ ] Read beforehand (done on 2026-11-23): `integration-db` runs every e2e test with
  `key_custodian` and counts nothing, so it runs the 11 new tests unchanged; `rehash-without-custodian`
  counts `rehash_` tests (11), which no new name contains. If a run shows otherwise, stop and ask.
- [ ] Job `rotation-without-custodian` ("Master key rotation without the key_custodian feature"):
  PostgreSQL service; `cargo test --test vault_e2e rotation_`; fails unless `test result: ok. 10 passed`.
- [ ] Job `rotation-kv` ("Master key rotation refusal with the kv feature"):
  `cargo test --features key_custodian,kv --test vault_e2e rotation_refuses_to_run_with_kv -- --exact`;
  fails unless `ok. 1 passed`.
- [ ] Job `rotation-external-key-manager` ("Master key rotation with an external key manager"):
  second checkout of `juspay/hyperswitch-encryption-service` at the commit above
  (`persist-credentials: false`, `path: cripta`), its build (cached), its migrations by `psql`, its
  master key from `openssl rand -hex 32` masked with `::add-mask::` before use, the service started
  in the background and its health route awaited, then the test of Task 7 with
  `--features key_custodian,external_key_manager`, `VAULT_TEST_DATABASE_URL`,
  `VAULT_TEST_REQUIRE_DB=1`, `VAULT_TEST_KEY_MANAGER_URL=http://127.0.0.1:5000`,
  `-- --exact --nocapture`; fails unless `ok. 1 passed` and the output has no `skipped`.
- [ ] Two failed CI attempts on the same job: back to the last working state, the blocker reported,
  the owner asked before a third approach.
- [ ] `ruby -ryaml -e 'YAML.load_file(".github/workflows/CI-pr.yml")'` → exit 0; existing jobs
  byte-identical (`git diff main -- .github/workflows/CI-pr.yml` shows additions only).
- [ ] Commit `ci: add the master key rotation jobs`.

### Task 9: Threat model table, tokenization page, README

**Covers:** D12

**Files:**
- Modify: `docs/threat-model.md`, `docs/tokenization.md`, `README.md`

- [ ] `docs/tokenization.md`: replace the paragraph on key rotation (lines 201-206) with: the command,
  how to run it (stop, back up, `utils master-key`, the command, configuration, start, `utils rehash`
  as the check), what it covers and what it does not (merchant keys and cards unchanged: a leaked
  former key with an older copy of the database still reads cards; keep the former key until older
  backups expire), the external mode, the modes tested and the CI jobs.
- [ ] `docs/threat-model.md`: T22 → `proven` for the rotation itself, its row saying that the
  configuration change after the command is manual (see T36); control citing `src/domain/master_key.rs` (pre-check,
  rewrite, final check, hash step) and `src/bin/utils.rs`, evidence tests 1–12; T23 evidence gains
  `rotation_with_external_key_manager`, stays `open`; new `open` rows T35 (former key plus an older
  database copy still give every merchant key) and T36 (between the command and the configuration
  change, or if the vault is started mid-rotation, cards do not read back), each citing the new
  `docs/tokenization.md` lines; "How to check it yourself" gains the three CI jobs; every moved
  `file:line` in `docs/threat-model.md`, `docs/tokenization.md` and `README.md` corrected and reread
  (begin and end of each block).
- [ ] `README.md`: new entry under "Changes from the original" naming every file of
  `git diff --name-only main` except `README.md`; checked by
  `for f in $(git diff --name-only main); do [ "$f" = README.md ] || grep -q -F "$f" README.md || echo "MISSING $f"; done`
  (no output), run again at the end of Task 10. `grep -n -i 'rotation' README.md` shows no sentence
  left saying that rotation is not implemented.
- [ ] The docs list the modes not covered: `kv` (refused), concurrent writers (read in the code, not
  tested), a public or placeholder master key with an external key manager (T23).
- [ ] `scripts/check-threat-model.sh` → `OK: 36 rows (15 proven, 7 not tested, 14 open)`;
  `grep -c -i -E 'GHSA|advisories' docs/threat-model.md README.md docs/tokenization.md` → 0 each.
- [ ] Commit `docs: describe master key rotation in the threat model and tokenization pages`.

### Task 10: Whole-branch checks, reviews, PR

**Covers:** D11, D12, the owner's completion criteria

- [ ] `cargo fmt --all --check` (stable; `cargo +nightly fmt` and `typos` are not installed: "not
  run" in the report); `RUSTFLAGS="-D warnings" cargo clippy -j 4 --all-features --all-targets`
  compared with `main`; `cargo test -j 4` (≥ 77 passed: 61 + 6 unit tests + 10 e2e tests that report passed without a
  database); full e2e with `key_custodian` (0 failed,
  31 passed); `make demo` with `DEMO_DATABASE_URL` → `DEMO OK`.
- [ ] Locked-paths check: `git diff --name-only main -- migrations config demo Cargo.toml Cargo.lock deny.toml CLAUDE.md .typos.toml LICENSE scripts` → empty.
- [ ] Compliance-wording search (pattern kept in the scratchpad) on added lines of `git diff main`,
  on `git log main..HEAD --format=%B` and on the PR text → 0.
- [ ] `security-review` skill on the branch; fresh `opus` subagent review and `second-avis --reserve 50`
  in parallel, each given the owner's request verbatim, the diff and the table, and asked to check
  that every added test fails when its control is removed. Fix what changes the result.
- [ ] Owner's approval (DOING / EXPECT / IF WRONG), then `git push -u origin feat/master-key-rotation`
  (never `upstream`) and `gh pr create -R antoinevoinchet-spec/hyperswitch-card-vault`;
  `gh pr checks <n> -R antoinevoinchet-spec/hyperswitch-card-vault` until every job passes or the
  failure is reported as is.
