# Replayable demo, PostgreSQL in CI, custodian audit rows: design

Date: 2026-11-23. Branch: `feat/demo-and-ci-db` (from `main`, `e7aeb13`). Status: draft, awaiting owner
approval.

## Intent

This fork is a study project. A reader of the fork should understand the vault in about ten minutes,
and the owner, who does not read Rust, should be able to check that what the docs announce is true by
running one command or by reading a green CI check. This phase adds no new business feature: it makes
the existing vault demonstrable and proven, and closes one known gap in the audit log (limit D8 of the
2026-11-20 design).

## Current state (read in the code on 2026-11-23)

- The router is assembled inside `app::server_builder`, which also binds the socket. There is no
  function that returns the router alone, so in-process HTTP tests would need a change to `src/`.
- The `locker` binary reads `config/development.toml`, then environment variables prefixed `LOCKER`
  with `__` as separator (`src/config.rs`, `new_with_config_path`).
- Under `key_custodian`, `GlobalAppState::new` builds no tenant state. A tenant's `TenantAppState`
  (and its database pool) only exists after a successful `/custodian/decrypt`. `key1` and `key2` only
  emit a WARN log event (`audit::emit_audit_event`); a failed decrypt does the same.
- The database password is not protected by the custodian keys: only the tenant `master_key` is
  (`aes_decrypt_custodian_key` in `src/routes/key_custodian.rs`). The vault can therefore open a
  database connection before it is unlocked. Data rows stay encrypted under keys the vault cannot
  derive until the master key is decrypted.
- `cargo run --bin utils -- master-key` prints an encrypted master key and the two custodian keys
  (`src/bin/utils.rs`, `master_key_generator`).
- PR CI has no PostgreSQL in the test job. `migration-check.yml` already runs a `postgres:alpine`
  service container.
- No `tests/` directory exists. `cargo test -j 4` passes 27 unit tests and 2 integration tests,
  without a database.

## Decisions taken by the owner (2026-11-23)

1. **Plain HTTP in the demo**: requests and responses are shown as readable JSON; the JWE envelope
   (`middleware` feature) is explained in the README, not played.
2. **The demo includes the two custodians** (`key_custodian` feature): key 1, key 2, unlock.
3. **Limit D8 is resolved**: `/custodian/key1`, `/custodian/key2` and a failed `/custodian/decrypt`
   write a row to `audit_log`, fail-closed.
4. **The demo uses the local PostgreSQL**, not Docker.
5. Ideas from the research reports not needed for this phase stay for later.

## Approaches considered

- Proof against a real database: in-process tests with a router extracted from `server_builder`
  (rejected: a refactor of `src/app.rs` for tests only) versus tests that start the real `locker`
  binary against a throwaway database and talk to it over HTTP (chosen: no change to the server code,
  and it tests the route wiring end to end, which closes review note M5).
- Fail-closed proof: stopping the whole database (rejected: the card read fails before the audit
  write, so a 500 would prove nothing about the audit) versus making only `audit_log` unwritable while
  the card stays readable (chosen).
- Custodian audit rows: replaying a log file into the table after a successful unlock (rejected:
  nothing reaches the table if the unlock never succeeds, and it is not fail-closed) versus an audit
  connection per tenant opened at startup and written before the custodian key is kept (chosen).
- Demo database: Docker Compose (rejected by the owner: heavy on an 8 GB machine, long container
  build) versus a throwaway local PostgreSQL cluster (chosen).

Reference point found during research: HashiCorp Vault and OpenBao do not record unseal key
submissions in their audit devices (https://developer.hashicorp.com/vault/docs/audit and
https://openbao.org/docs/audit/, read on 2026-11-23). This fork goes further for study purposes.

## Requirements

- **E1. One-command demo.** `make demo` runs `demo/run.sh`. On a machine with Rust and PostgreSQL 14
  or later, it:
  1. builds `locker` and `utils` with `--features key_custodian` (`-j 4`);
  2. creates a throwaway PostgreSQL cluster in a temporary directory, listening on TCP `127.0.0.1`
     (port from `DEMO_PG_PORT`, default 54329), applies every `migrations/*/up.sql` in order with
     `psql`, and removes the cluster on exit, success or failure (`trap`). When `DEMO_DATABASE_URL`
     is set (CI), it points to an existing empty database: the script applies the migrations to it
     and creates no cluster. The CI job creates that empty database just before;
  3. generates a throwaway encrypted master key and its two custodian keys with `utils master-key`,
     kept in shell variables and never printed;
  4. starts `locker` with environment overrides only (database, port, tenant `public` master key),
     its own log going to a file in the temporary directory;
  5. plays the journey below, printing for each step: a one-line explanation, the request (custodian
     keys shown as `<hidden>`), the HTTP status and the response;
  6. prints the `audit_log` rows written by the journey (columns `created_at`, `operation`,
     `merchant_id`, `customer_id`, `resource_id`, `outcome`, `status_code`, `error_type`);
  7. prints three checks: the number of `audit_log` rows containing the test card number (expected
     0); right after step 6, while the card is stored, the number of `locker` rows (expected at
     least 1) and the number of those whose stored bytes contain the number (expected 0); and the
     number of server log lines containing it (reported as measured).
  Exit code 0 only if every step returns its expected status and the first two checks are 0.

  Journey (tenant `public`, merchant `demo-merchant`, customer `demo-customer`, card
  `4111111111111111`, a public test number):

  | # | Step | Expected | `audit_log` row |
  |---|---|---|---|
  | 1 | `/custodian/key1` | 200 | `custodian_key1`, success |
  | 2 | `/custodian/key2` with a wrong key | 200 | `custodian_key2`, success |
  | 3 | `/custodian/decrypt` | error | `custodian_decrypt`, failure |
  | 4 | `/custodian/key2` with the right key | 200 | `custodian_key2`, success |
  | 5 | `/custodian/decrypt` | 200 | `custodian_decrypt`, success |
  | 6 | `/data/add` (store the card) | 200, returns `card_reference` | `locker_add`, success |
  | 7 | `/data/retrieve` | 200, returns the card | `locker_retrieve`, success |
  | 8 | `/cards/fingerprint` | 200, returns a fingerprint id | `fingerprint`, success |
  | 9 | `/data/delete` | 200 | `locker_delete`, success |
  | 10 | `/data/retrieve` after delete | error | `locker_retrieve`, failure |

  Existing behaviour, kept as is: a decrypt that fails on a wrong key returns early
  (`aes_decrypt_custodian_key(...).await?` in `decrypt_inner`) and skips the reset of the stored
  keys, which only runs when a key is missing. Key 1 therefore stays stored after step 3, and step 4
  only replaces key 2. This is listed under "Known limits"; changing it is out of scope.

  Build and run: debug profile (`cargo build`), because `Env::current_env` picks
  `config/development.toml` only in debug builds; the binaries are started from the repository root.
  Verifiable by: `make demo; echo $?` prints 0 on a fresh machine state, and its output holds one
  audit row per journey step (10 rows).

- **E2. Card number exposure in the demo output.** The test card number appears at most **3 times** in
  `make demo` output: the `/data/add` request (step 6), the `/data/retrieve` response (step 7) and the
  `/cards/fingerprint` request (step 8). None of these is an audit row. The check lines of E1.7 print
  counts, not the number.
  Verifiable by: `make demo 2>&1 | grep -c 4111111111111111` returns at most 3.

- **E3. Demo README.** `demo/README.md` explains each step for a non-developer: what is encrypted, with
  which key (custodian keys decrypt the master key; the master key encrypts each merchant's key; the
  merchant key encrypts the card), what the audit row records and what it never records. It explains
  what the `middleware` JWE envelope would add and points to `docs/guides/testing.md` for the `utils`
  tool. It shows an abridged expected output. The root `README.md` gains a short "Demo" section
  linking to it.
  Verifiable by: the files exist; each of the 10 journey steps has a paragraph in `demo/README.md`.

- **E4. Custodian audit rows (resolves D8).** Under `key_custodian`, `GlobalAppState` holds, for each
  known tenant, an audit-only `Storage` built at startup from the database configuration and the
  tenant schema, before any unlock. Then:
  - `/custodian/key1` and `/custodian/key2` write their row through `audit::record` **before** storing
    the key. If the write fails, the response is `DatabaseInsertFailed("audit_log")` (HTTP 500) and
    the key is not kept.
  - A failed `/custodian/decrypt` writes a `custodian_decrypt` failure row with the error kind and
    status. A successful one keeps its current behaviour (row written before the tenant is published).
  - Rejections in the custodian routes that happen before the handler (unknown tenant, malformed
    JSON) stay unrecorded, as for other routes.
  - The custodian keys never reach the row: `PendingAudit` for these operations takes no request.
  - `audit::emit_audit_event` loses its last callers and is removed.
  Verifiable by: the integration tests of E6.

- **E5. Audit connection opened before unlock: what it can do.** The audit `Storage` uses the same
  database credentials as the rest of the vault. Before unlock, the vault therefore has full database
  rights, but cannot read any card: rows are encrypted under keys derived from the master key, which
  is still encrypted. A PostgreSQL role restricted to `INSERT` on `audit_log` is listed as a next step.
  Startup is unchanged: the audit-only `Storage` of a tenant is created on its first custodian call
  and kept for the next ones. If it cannot be created (database unreachable), that call is refused
  with HTTP 500 and the key is not kept, like any other failed audit write.
  Verifiable by: this paragraph in `demo/README.md` and in the tokenization page limits.

- **E6. Integration tests against a real PostgreSQL.** A new file `tests/vault_e2e.rs`, compiled only
  with `key_custodian` (`#![cfg(feature = "key_custodian")]`). Each test creates its own database
  from `VAULT_TEST_DATABASE_URL` (an admin connection URL), applies `migrations/*/up.sql`, starts the
  `locker` binary (`CARGO_BIN_EXE_locker`) on a free port with environment overrides, generates
  custodian keys with `CARGO_BIN_EXE_utils`, and drops its database at the end. When
  `VAULT_TEST_DATABASE_URL` is unset, each test returns early and prints that it was skipped, so
  `cargo test` keeps passing without a database. Tests:
  - `audit_row_is_written_for_each_card_step`: unlock, store, retrieve, delete; reads `audit_log` and
    finds one row per step with the expected `operation`, `outcome` and `status_code`, and no row
    containing the card number.
  - `retrieve_fails_closed_when_audit_table_is_unwritable`: unlock, store a card, rename `audit_log`
    so inserts fail, retrieve; expects HTTP 500 and a body that does not contain the card number.
  - `custodian_steps_write_audit_rows`: key1, wrong key2, decrypt (failure), then the right keys and
    decrypt; finds the five custodian rows with their outcomes.
  - `custodian_key_is_refused_when_audit_table_is_unwritable`: rename `audit_log`, send key1; expects
    HTTP 500; restore the table, send key2 and decrypt; expects the decrypt to fail because key1 was
    not kept.
  Tests use only crates already in `Cargo.toml` (`reqwest`, `tokio`, `diesel` with `postgres`,
  `uuid`, `serde_json`). No dependency is added.
  Verifiable by: the four tests pass in the `integration-db` CI job; `git diff main -- Cargo.toml`
  is empty.

- **E7. CI job.** `.github/workflows/CI-pr.yml` gains one job, `integration-db`, with a PostgreSQL
  service container copied from `migration-check.yml`. It runs
  `cargo test --features key_custodian --test vault_e2e` with `VAULT_TEST_DATABASE_URL` set, then
  `make demo` with `DEMO_DATABASE_URL` set. Existing jobs and steps are unchanged. The existing
  `test` job (`--all-features`) compiles the new tests and skips them (no database there).
  Verifiable by: `git diff main -- .github/workflows/CI-pr.yml` only adds lines; the job is green
  on the PR.

- **E8. Tokenization page.** `docs/tokenization.md`, titled "What the vault already does for
  tokenization", describes the existing behaviour with the PCI SSC tokenization vocabulary (token,
  reversible token, card data vault, mapping, de-tokenization, and the non-reversible fingerprint),
  taken from the PCI SSC Information Supplement on tokenization, read before writing. Every statement
  about the vault cites a test name or a `file:line`. It states what the vault does not do (for
  example format-preserving tokens) without proposing to build it.
  Verifiable by: every paragraph about current behaviour in `docs/tokenization.md` ends with a test
  name or a `file:line` reference that exists on the branch.

- **E9. Review notes M1 to M6.**

  | Note | Brought up by the demo or CI? | Handling |
  |---|---|---|
  | M1: card-shaped id redaction also hits ~1 in 10 numeric ids of 13 to 19 digits | No: demo ids are not numeric | Does not block the demo. Left for a later phase; mentioned in the tokenization page limits. |
  | M2: the D8 limits list omits rate-limited `/delete` and locked-custodian rejections | Yes: the demo runs with `key_custodian`, where data calls before unlock are rejected before the handler | Fixed in this document: see "Known limits" below. Documentation only, no test. |
  | M3: `decrypt` holds the `tenants_key_state` lock while writing the audit row | No: the demo and tests send one request at a time | Does not block the demo. Unchanged. |
  | M4: `emit_audit_event` prints `request_id` in Debug format | Yes, indirectly: E4 replaces the function | Fixed by removal (E4); the custodian tests of E6 fail before E4 and pass after. |
  | M5: no end-to-end test of route wiring | Yes: the CI job is that test | Fixed by E6. |
  | M6: `#[tracing::instrument]` on v2 inner functions, not v1 | No | Does not block the demo. Unchanged. |

  Verifiable by: this table; for M4 and M5, the E6 tests in the CI job.

- **E10. Quality gates.** `cargo build -j 4` exits 0. `cargo test -j 4` exits 0 with at least 29
  tests passing (E6 tests are not compiled without `key_custodian`; the baseline is measured before
  the first change). `cargo clippy --all-features --all-targets -j 4` reports no warning in changed
  files. `cargo fmt --all --check` (stable, locally) exits 0; the nightly check runs in CI. CI on the
  PR passes, including `integration-db`.
  Verifiable by: the command outputs and `gh pr checks`.

- **E11. License notice.** `README.md`, section "Changes from the original", names every file listed
  by `git diff --name-only main` except `README.md`.
  Verifiable by: comparing that list with the section.

- **E12. No compliance claim.** No added line contains any of the forbidden phrases of the "No
  compliance claim" rule in `CLAUDE.md`. This document refers to them without quoting them.
  Verifiable by: the owner's search command on the added lines of `git diff main` returns 0.

- **E13. Secrets.** The demo and the tests generate throwaway custodian keys and never print them.
  No `.env` file is read. The `master_key` of `config/development.toml` is never printed (it is
  overridden by the throwaway one when `key_custodian` is on). No file under `config/` changes.
  Verifiable by: `git diff --name-only main -- config .env` is empty; E1.7 and E6 checks; reading
  `demo/run.sh`, where no key variable is echoed.

## Known limits (updated list, replaces the one in D8)

Recorded in `audit_log` after this phase: every vault and custodian operation that reaches its
handler. Not recorded:

- Requests rejected before the handler: unknown tenant, JWE decryption failure, malformed JSON,
  data or vault calls while the custodian is locked (`CustodianLocked`), custodian calls after unlock
  (`CustodianUnlocked`), and `/delete` calls rejected by the rate limit (`limit` feature, HTTP 429).
- With `middleware`, a failure while encrypting the response happens after the row says `success`.
- For an add or a delete, the database change has already happened when the audit write fails.
- Custodian keys are two halves concatenated: each custodian knows half of the key bits.
- A decrypt that fails on a wrong key keeps both stored keys (see E1); a second `key1` before
  decrypt replaces the first. Both submissions are recorded.

## Non-goals

- No new business feature: no proxy, no per-caller access rules, no key rotation (later phase).
- No refusal of a second `key1` before decrypt, no key check value in the row, no full-length XOR
  key components, no `INSERT`-only database role (listed as next steps).
- No Docker path for the demo; the existing `Makefile` Docker targets stay as they are.
- No new migration, no change to `Cargo.toml` or `config/`.

## Anti-goals

- A custodian key, the master key or a card number in an audit row, a demo check line or a test
  output.
- A custodian key kept in memory while its audit row was not written.
- A demo that passes while a step returned an unexpected status.

## Left to the builder

- Shell details of `demo/run.sh` (functions, colours, how JSON is pretty-printed with `jq`).
- Where the audit-only storage lives in `GlobalAppState` and how it is typed.
- Helper functions shared by the integration tests.
- Exact wording of the tokenization page, within E8.
