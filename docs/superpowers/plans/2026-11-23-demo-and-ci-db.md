# Replayable demo, PostgreSQL CI tests and custodian audit rows: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the vault demonstrable in one command and proven against a real PostgreSQL in CI, and
record custodian steps in `audit_log` (limit D8).

**Architecture:** Integration tests start the real `locker` and `utils` binaries against a throwaway
database and talk HTTP. Custodian handlers get a per-tenant audit-only `Storage`, created lazily on
the first custodian call, and write their row before keeping a key. A bash script plays the same
journey for humans; a new CI job runs both.

**Tech Stack:** Rust (axum 0.7, diesel 2 with `postgres`, reqwest 0.12, tokio), bash, `psql`/`initdb`/`pg_ctl`,
`jq`, `curl`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-23-demo-and-ci-db-design.md` (requirements E1 to E13).

## Global Constraints

- Every `cargo` command is preceded by `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"` and uses `-j 4`.
- No change to `Cargo.toml`, `Cargo.lock`, `config/`, `migrations/`, `.env`, `.typos.toml`, `CLAUDE.md`, `LICENSE`, other workflows.
- Debug builds only for the demo and the tests (`Env::current_env` picks `config/development.toml` only with `debug_assertions`).
- Test card number: `4111111111111111`. Tenant `public`. Merchant `demo-merchant`, customer `demo-customer`.
- Custodian keys and master keys are generated per run by `utils master-key` and never printed, logged or written to a tracked file.
- Repository text in English; no forbidden compliance phrase from the "No compliance claim" rule of `CLAUDE.md`.
- Timestamps UTC. No hand-written cryptography.
- One logical change per commit; `git status` before each commit; message in English ending with the attribution lines of the session.
- Database URLs written in the repository carry no password: local cluster and CI service use `trust` authentication (the commit hook's secret scanner blocks `user:password@` URLs). The vault's `LOCKER__DATABASE__PASSWORD` is then any placeholder, ignored by the server; helpers take the password from the URL when present, else use an empty string.
- Local PostgreSQL for the e2e tests: throwaway cluster in the session scratchpad, TCP `127.0.0.1`, port **54339**, removed in Task 6. The demo's own default port stays 54329, so both never collide.
- Work only on branch `feat/demo-and-ci-db`; every `gh pr`/`gh issue` command carries `-R antoinevoinchet-spec/hyperswitch-card-vault`; never write to `juspay/*`.
- Baseline measured on 2026-11-23 before any change: `cargo test -j 4` → 27 unit + 2 other tests passed (29).
- Crate features confirmed in `Cargo.toml`: `tokio` has `macros` and `rt-multi-thread`, `uuid` has `v7`, `reqwest` has `json`, `diesel` has `postgres`.

## Review Focus

1. A wrong custodian key that is valid hex of 16 bytes reaches the handler; a non-hex or wrong-length key is rejected by JSON validation before the handler and leaves no row. The demo's wrong key must be 32 hex characters. Pinned in Task 2 (`custodian_steps_write_audit_rows`).
2. Leftover state when a test panics: the database must still be dropped and the child process killed. Pinned in Task 1 by `Drop` on the helpers.
3. Port collision between parallel tests: each test binds port 0 to pick a free port. Pinned in Task 1 (tests run in parallel by default).
4. Demo interrupted (Ctrl-C) or failing mid-way: the cluster and the `locker` process are stopped by `trap`. Pinned in Task 3 step 4.
5. A second `/custodian/key1` before decrypt: both submissions get a row and the last key wins. Pinned in Task 2 (`custodian_steps_write_audit_rows` sends key1 twice).

---

### Task 1: Integration test harness and card-path tests

**Couvre:** E6 (tests 1 and 2), E9 (M5), E13

**Files:**
- Create: `tests/vault_e2e.rs`

**Interfaces:**
- Produces (in `tests/vault_e2e.rs`, private helpers reused by Task 2):
  - `fn admin_url() -> Option<String>`: reads `VAULT_TEST_DATABASE_URL`; `None` makes the test print `skipped: VAULT_TEST_DATABASE_URL not set` and return.
  - `struct TestDb { name: String, url: String, admin: String }` with `fn create(admin: &str) -> TestDb` (creates database `vault_test_<uuid v7 simple>`, applies every `migrations/*/up.sql` in directory-name order with `diesel::connection::SimpleConnection::batch_execute`), `fn audit_rows(&self) -> Vec<AuditRow>` (`AuditRow { operation: String, outcome: String, status_code: i16, text: String }`, ordered by `created_at, audit_id`, `text` being the whole row cast with `audit_log::text`) and `fn exec(&self, sql: &str)`. `Drop` runs `DROP DATABASE … WITH (FORCE)` on the admin connection.
  - `struct Keys { master_key: String, key1: String, key2: String }` with `fn generate() -> Keys`, parsing the `master key: `, `key 1: `, `key 2: ` lines of `env!("CARGO_BIN_EXE_utils") master-key`.
  - `struct Vault { child: std::process::Child, base: String }` with `async fn start(db: &TestDb, master_key: &str) -> Vault` (free port from binding `127.0.0.1:0`; `current_dir(env!("CARGO_MANIFEST_DIR"))`; env `LOCKER__SERVER__PORT`, `LOCKER__DATABASE__HOST/PORT/USERNAME/PASSWORD/DBNAME` parsed from the db URL, `LOCKER__TENANT_SECRETS__PUBLIC__MASTER_KEY`; stdout and stderr to `Stdio::null()`; polls `GET /health` until 200, 60 s timeout) and `async fn post(&self, path: &str, body: serde_json::Value) -> (u16, String)` (header `x-tenant-id: public`). `Drop` kills the child.
  - `async fn unlock(vault: &Vault, keys: &Keys)`: key1, key2, decrypt, each asserting 200.
- File starts with `#![cfg(feature = "key_custodian")]` and `#![allow(clippy::unwrap_used, clippy::expect_used)]`.

- [ ] **Step 1: Start the local throwaway PostgreSQL**

Run (scratchpad dir `$S`): `/opt/homebrew/opt/postgresql@14/bin/initdb -D "$S/pg" -U vault --auth=trust -E UTF8 >/dev/null && /opt/homebrew/opt/postgresql@14/bin/pg_ctl -D "$S/pg" -o "-p 54339 -k '' -c listen_addresses=127.0.0.1" -l "$S/pg.log" start`
Expected: `server started`. Use `VAULT_TEST_DATABASE_URL=postgres://vault@127.0.0.1:54339/postgres`.

- [ ] **Step 2: Write the two card-path tests**

```rust
#[tokio::test]
async fn audit_row_is_written_for_each_card_step() {
    // unlock, add, retrieve, delete
    // rows (operation, outcome, status_code), in created_at order, for card operations:
    // [("locker_add","success",200), ("locker_retrieve","success",200), ("locker_delete","success",200)]
    // no row's text contains "4111111111111111"
}

#[tokio::test]
async fn retrieve_fails_closed_when_audit_table_is_unwritable() {
    // unlock, add -> card_reference
    // db.exec("ALTER TABLE audit_log RENAME TO audit_log_blocked")
    // retrieve -> status 500, body does not contain "4111111111111111"
    // db.exec("ALTER TABLE audit_log_blocked RENAME TO audit_log")
}
```
Add request body: `{"merchant_id":"demo-merchant","merchant_customer_id":"demo-customer","card":{"card_number":"4111111111111111"}}`; reference at `payload.card_reference`.

- [ ] **Step 3: Run without the variable, then with it**

Run: `cargo test -j 4 --features key_custodian --test vault_e2e`
Expected: 2 passed, each printing the skip line.
Run: `VAULT_TEST_DATABASE_URL=… cargo test -j 4 --features key_custodian --test vault_e2e`
Expected: 2 passed. These tests describe existing behaviour, so they pass at once; to prove they can fail, temporarily remove the `/retrieve` route from `routes::data::serve`, see both tests fail, revert.

- [ ] **Step 4: Check that `cargo test -j 4` (default features) still passes 29 tests and clippy is clean on the file**

Run: `cargo test -j 4` → 29 passed. `cargo clippy --features key_custodian --all-targets -j 4` → no warning in `tests/vault_e2e.rs`.

- [ ] **Step 5: Commit** `test: add end-to-end tests against a real PostgreSQL`

### Task 2: Custodian steps write audit rows (D8)

**Couvre:** E4, E5, E6 (tests 3 and 4), E9 (M4)

**Files:**
- Modify: `src/tenant.rs` (new field and method, `key_custodian` only)
- Modify: `src/routes/key_custodian.rs` (`key1`, `key2`, `decrypt`)
- Modify: `src/audit.rs` (remove `emit_audit_event`)
- Test: `tests/vault_e2e.rs`

**Interfaces:**
- Consumes: Task 1 helpers; `audit::record`, `audit::PendingAudit::new`, `AuditOperation::{CustodianKey1, CustodianKey2, CustodianDecrypt}`.
- Produces:
  - `GlobalAppState.tenants_audit_store: RwLock<FxHashMap<String, Arc<crate::storage::Storage>>>` (`#[cfg(feature = "key_custodian")]`).
  - `pub async fn custodian_audit_store(&self, tenant_id: &str) -> Result<Arc<crate::storage::Storage>, ContainerError<ApiError>>` on `GlobalAppState`: returns the cached store or builds one with `storage::Storage::new(&global_config.database, None, &<tenant schema>, runtime_config_manager.clone(), storage_global_store.clone(), #[cfg(feature = "redis")] None)`; a build error maps to `ApiError::DatabaseInsertFailed("audit_log")`.
  - `key1` and `key2` return `Result<Json<CustodianRespPayload>, ContainerError<ApiError>>`.

- [ ] **Step 1: Write the two custodian tests**

```rust
#[tokio::test]
async fn custodian_steps_write_audit_rows() {
    // key1, key1 again, wrong key2 (32 random hex chars), decrypt -> not 200,
    // right key2, decrypt -> 200
    // custodian rows in order: key1 success 200, key1 success 200, key2 success 200,
    // decrypt failure (status != 200), key2 success 200, decrypt success 200
    // no row text contains keys.key1, keys.key2 or keys.master_key
}

#[tokio::test]
async fn custodian_key_is_refused_when_audit_table_is_unwritable() {
    // rename audit_log -> audit_log_blocked; key1 -> 500
    // rename back; key2 -> 200; decrypt -> not 200 (key1 was not kept)
    // rows: key2 success, decrypt failure; no key1 row
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `VAULT_TEST_DATABASE_URL=… cargo test -j 4 --features key_custodian --test vault_e2e custodian`
Expected: both FAIL (no custodian rows except decrypt success; key1 returns 200 while the table is blocked).

- [ ] **Step 3: Implement `custodian_audit_store` in `src/tenant.rs`**

Read lock first; on miss, take the write lock, check again, build, insert. Tenant schema from `global_config.tenant_secrets` for `tenant_id`; a tenant missing there returns `ApiError::TenantError("Invalid x-tenant-id")` (the `TenantId` extractor already rejects unknown tenants, so this is a guard). Error messages of the test helpers (`Keys::generate`, `unlock`) never include the `utils` output or a key.

- [ ] **Step 4: Rewrite `key1`, `key2` and the failure path of `decrypt` in `src/routes/key_custodian.rs`**

`key1`/`key2`: get the audit store (error → return it, key not kept), `audit::record(&*store, PendingAudit::new(&tenant_id, request_id, CustodianKeyN), Ok(())).await?`, then take the `tenants_key_state` lock and keep the key. `decrypt`: on `Err` from `decrypt_inner`, get the audit store and return `audit::record(&*store, PendingAudit::new(…, CustodianDecrypt), result).await` (records `failure` with the error kind; if the store is unavailable, return the store error). Success path unchanged. Remove `audit::emit_audit_event` from `src/audit.rs` and its imports.

- [ ] **Step 5: Run the four e2e tests, the default tests, clippy and per-feature check**

Run: `VAULT_TEST_DATABASE_URL=… cargo test -j 4 --features key_custodian --test vault_e2e` → 4 passed.
Run: `cargo test -j 4` → 29 passed. `cargo clippy --features key_custodian --all-targets -j 4` → no warning in changed files.
Run: `cargo check -j 4 --all-targets --no-default-features --features key_custodian` and `cargo check -j 4 --all-targets --no-default-features` → exit 0.
Run: `grep -rn emit_audit_event src` → no output. M4 is closed by removing the function; no format test is written for a function that no longer exists.

- [ ] **Step 6: Commit** `feat(audit): record custodian steps in audit_log, fail-closed`

### Task 3: One-command demo

**Couvre:** E1, E2, E3, E13

**Files:**
- Create: `demo/run.sh` (executable), `demo/README.md`
- Modify: `Makefile` (add `demo` target only), `README.md` (short "Demo" section)

**Interfaces:**
- Consumes: Task 2 behaviour (custodian rows). Environment: `DEMO_DATABASE_URL` (optional, empty database), `DEMO_PG_PORT` (default 54329), `PG_BIN` (default: directory of `pg_ctl` on `PATH`, else `/opt/homebrew/opt/postgresql@14/bin`).
- Produces: `make demo` → `./demo/run.sh`; exit 0 only when every step returns its expected status, the audit check and the locker-bytes check are 0, and at least one `locker` row exists after step 6.

- [ ] **Step 1: Write `demo/run.sh` (`set -euo pipefail`)**

Order: build `cargo build -j 4 --features key_custodian --bin locker --bin utils`; temp dir via `mktemp -d`; database (own cluster or `DEMO_DATABASE_URL`); `psql -v ON_ERROR_STOP=1 -q -f` each `migrations/*/up.sql`; keys from `target/debug/utils master-key` into variables; wrong key2 from `openssl rand -hex 16`; start `target/debug/locker` with the env overrides of Task 1, log to `$tmp/locker.log`, wait for `/health`; play the 10 steps of E1 with a helper `step <n> <expected-status> <title> <explanation> <path> <json> [shown-json]` that prints the explanation, the shown request (custodian keys replaced by `"<hidden>"`), the status and the response through `jq`, and fails the run on an unexpected status (for step 3 and step 10, expected is "not 200"); after step 6, run the locker-bytes check with `psql` (`count(*)` of `locker` and of rows where `position(convert_to('4111111111111111','UTF8') in enc_data) > 0`, column name checked in `src/storage/schema.rs`); after step 10, print the audit rows (E1.6) with `psql` and the three checks (E1.7). `trap` on EXIT stops `locker` and the cluster and removes the temp dir. Never `echo` a key variable; never `set -x`.

- [ ] **Step 2: Add the `demo` target to `Makefile`** (`.PHONY: demo`, recipe `./demo/run.sh`).

- [ ] **Step 3: Run it and check exit code, rows and exposure**

Run: `make demo > $S/demo.out 2>&1; echo $?` → `0`.
Run: `grep -c 4111111111111111 $S/demo.out` → at most 3; `grep -n 4111111111111111 $S/demo.out` shows only the add request, the retrieve response and the fingerprint request.
Run: count of audit rows printed → 10.
The four E1.7 check lines: audit rows containing the card (`psql` count on `audit_log::text`, must be 0); after step 6, `locker` rows (≥ 1) and rows whose `enc_data` contains the card bytes (0); lines of `$tmp/locker.log` containing the card (printed as measured); generated key values found in the script's own output copied to `$tmp/out` (`grep -cF` per key, must be 0).
Run: `grep -c 'CustodianLocked\|CustodianUnlocked\|rate limit' demo/README.md` → at least 3 after Step 5.
In `DEMO_DATABASE_URL` mode, the script passes the URL as is to `psql` and splits it with bash parameter expansion (`user:password@host:port/db`) for the `LOCKER__DATABASE__*` variables.

- [ ] **Step 4a: Check that a wrong status fails the run**

Temporarily change step 9's expected status to 500 in `demo/run.sh`; run `make demo; echo $?` → non-zero, the failing step is named, and nothing is left running (`pgrep -fl target/debug/locker` empty, temp dir removed). Revert.

- [ ] **Step 4: Check cleanup on failure**

Run: `DEMO_PG_PORT=54330 make demo` and press Ctrl-C during the build or after start; then `pgrep -fl 'target/debug/locker'` and `pg_ctl status` on the temp dir → nothing left running.

- [ ] **Step 5: Write `demo/README.md` and the `README.md` "Demo" section**

One paragraph per step: what is sent, what is encrypted and with which key (custodian keys → master key → merchant key → card, as in `docs/imgs/locker-key-hierarchy.png`), what the audit row records and never records; what the `middleware` JWE envelope would add (link `docs/guides/testing.md`); the abridged real output of Step 3; prerequisites (Rust, PostgreSQL 14+, `jq`, `curl`, `openssl`); the full "Known limits" list of the design, copied (requests rejected before the handler, including `CustodianLocked`, `CustodianUnlocked` and the `/delete` rate limit; the `middleware` response step; add or delete already applied when the audit write fails; halves; wrong key kept after a failed decrypt; second key1 replaces the first), plus the E5 point that the audit connection uses the vault's database credentials before unlock.

- [ ] **Step 6: Commit** `feat(demo): add a one-command demo of the card journey and its audit rows` (script, Makefile) then `docs(demo): explain each demo step` (READMEs).

### Task 4: CI job with PostgreSQL

**Couvre:** E7, E10

**Files:**
- Modify: `.github/workflows/CI-pr.yml` (append one job, nothing else)

**Interfaces:**
- Consumes: `tests/vault_e2e.rs`, `make demo` with `DEMO_DATABASE_URL`.

- [ ] **Step 1: Append job `integration-db`**

`runs-on: ubuntu-latest`; `services.postgres` copied from `migration-check.yml` (`postgres:alpine`, user `postgres`, db `locker`, health check, port 5432, plus `POSTGRES_HOST_AUTH_METHOD: trust` so that no URL in the repository carries a password; the existing `POSTGRES_PASSWORD` line is not copied); steps: checkout (`actions/checkout@v7`), mold (`rui314/setup-mold@v1`), Rust `stable 2 weeks ago` (`dtolnay/rust-toolchain@master`), `Swatinem/rust-cache@v2.9.1`; then
`cargo test --features key_custodian --test vault_e2e` with `VAULT_TEST_DATABASE_URL: postgres://postgres@localhost:5432/postgres`;
`psql postgres://postgres@localhost:5432/postgres -c 'CREATE DATABASE demo'`;
`make demo` with `DEMO_DATABASE_URL: postgres://postgres@localhost:5432/demo`, then `make demo` output saved and `grep -c 4111111111111111` asserted `<= 3`.

- [ ] **Step 2: Validate the YAML and the diff**

Run: `python3 -I -c "import yaml,sys;yaml.safe_load(open('.github/workflows/CI-pr.yml'))"` → no error (if PyYAML is missing, `ruby -ryaml -e 'YAML.load_file(ARGV[0])' .github/workflows/CI-pr.yml`). `git diff main -- .github/workflows/CI-pr.yml | grep '^-[^-]'` → empty.

- [ ] **Step 3: Commit** `ci: run end-to-end tests and the demo against PostgreSQL`

### Task 5: Tokenization page

**Couvre:** E8, E9 (M1 mention), E12

**Files:**
- Create: `docs/tokenization.md`

- [ ] **Step 1: Read the PCI SSC information supplement on tokenization (2011)** and note its definitions; in the page, name it only as "PCI SSC information supplement on tokenization (2011)" with its URL (token, tokenization, de-tokenization, card data vault, reversible and irreversible tokens, cryptographic and non-cryptographic tokens). Record the URL and date read. If it cannot be read, say so in the page and in the report.

- [ ] **Step 2: Write the page**, title "What the vault already does for tokenization". For each concept: the matching behaviour and a citation (`file:line` checked on the branch, or a test name from `src/audit.rs`, `src/crypto/...` tests or `tests/vault_e2e.rs`): `card_reference` as a random reference returned by `/data/add`; the `locker` table as the mapping to encrypted data; retrieval as de-tokenization; the fingerprint as a keyed, non-reversible value; what is encrypted with which key. A "What it does not do" list (no format-preserving token, the token is not derived from the card number, M1 redaction side effect, the audit connection holds full database credentials before unlock with an `INSERT`-only role as a next step). No sentence claims anything about the project's standing against a standard.

- [ ] **Step 3: Check every citation exists**

Run: for each `path:line` in the page, `sed -n '<line>p' <path>` shows the cited code; for each test name, `grep -rn 'fn <name>' src tests` finds it.

- [ ] **Step 4: Commit** `docs: describe the vault's existing tokenization behaviour`

### Task 6: README notice, gates and review

**Couvre:** E9, E10, E11, E12, E13

**Files:**
- Modify: `README.md` ("Changes from the original")

- [ ] **Step 1: List every file of `git diff --name-only main` (except `README.md`) in "Changes from the original"**, under a new bullet "Demo, end-to-end tests and custodian audit rows".

- [ ] **Step 2: Run the gates**

`cargo build -j 4` → 0. `cargo test -j 4` → ≥ 29 passed. `cargo clippy --all-features --all-targets -j 4` → no warning in changed files (pre-existing ones listed as such). `cargo fmt --all --check` → 0. `typos` if installed (else report "not run"). E2E with local DB → 4 passed. `make demo` → 0. Forbidden-phrase search on added lines: run the search script kept in the session scratchpad (built from the "No compliance claim" rule of `CLAUDE.md`, never written in the repository) on `git diff main | grep '^+'` (all added files, `docs/superpowers/` included) → 0; any hit is read and reworded. `typos` is not installed locally: report "not run locally, checked by CI" unless the owner approves installing it. `git diff --name-only main -- config .env Cargo.toml Cargo.lock migrations` → empty.

- [ ] **Step 3: Commit** `docs: list this phase's changes in the README`

- [ ] **Step 4: Review before the PR** — fresh opus subagent (owner's request verbatim, the diff, criteria E1 to E13) and `second-avis --reserve 50` in parallel; fix what changes the result; then stop and ask the owner before push and PR.

- [ ] **Step 4b: After review fixes, redo the checks they can break**: citation check of Task 5 step 3, README list against `git diff --name-only main`, the gates of Step 2.

- [ ] **Step 5: Remove the local throwaway cluster** (`pg_ctl stop`, delete `$S/pg`).

- [ ] **Step 6 (after the owner's yes): push, open the PR on the fork, then `gh pr checks <n> -R antoinevoinchet-spec/hyperswitch-card-vault`** and report each job as is.
