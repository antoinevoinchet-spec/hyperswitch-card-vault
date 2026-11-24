# Per-caller read control (T19): plan

Design: `docs/superpowers/specs/2026-11-24-per-caller-read-control-design.md` (decision R1: option
A). Branch: `feat/per-caller-read-control`. Status: approved by the owner on 2026-11-24; executed on the branch (see the execution notes).

## Files this plan may change

- `src/config.rs`: `CallerConfig` struct and optional `callers` map in `TenantSecrets`.
- `src/storage/consts.rs`: header name `X_VAULT_CALLER_KEY = "x-vault-caller-key"`.
- `src/custom_extractors.rs`: `OptionalCallerKey` extractor and the check function
  `authorize_read`, with its unit tests.
- `src/error.rs`: `ApiError::CallerKeyMissingOrUnknown` (401) and `ApiError::CallerNotAllowed`
  (403), both `code` `TE_00`.
- `src/routes/data.rs` and `src/routes/routes_v2/data.rs`: one extra extractor in each retrieve
  handler, one call to `authorize_read` as the first statement of each retrieve inner function.
- `tests/vault_e2e.rs`, `docs/threat-model.md`, `docs/tokenization.md`, `README.md`, this plan.

Nothing in `config/`, `migrations/`, `demo/`, `scripts/`, `Cargo.toml`, `Cargo.lock`.

## Shape of the control

```rust
// src/config.rs
#[derive(serde::Deserialize, Debug, Clone)]
pub struct CallerConfig {
    /// Lower-case hex SHA-256 of the caller's key. The key itself is never configured.
    pub key_hash: String,
    /// Comma-separated merchant ids (v1) or entity ids (v2) this caller may read.
    pub merchants: String,
}
// in TenantSecrets:
#[serde(default)]
pub callers: std::collections::HashMap<String, CallerConfig>,
```

`authorize_read(callers, caller_key, merchant_id) -> Result<(), ApiError>`:
1. `callers` empty: `Ok(())` (default: unchanged behaviour, design "Default").
2. no key: `Err(CallerKeyMissingOrUnknown)`.
3. SHA-256 of the key bytes with `ring::digest::digest(&ring::digest::SHA256, …)`, hex-encoded;
   no caller whose `key_hash` equals it exactly: `Err(CallerKeyMissingOrUnknown)`.
4. the matched caller's `merchants`, split on `,`, contains
   `merchant_id` exactly: `Ok(())`; otherwise `Err(CallerNotAllowed)`.

The digest is hex-encoded with the `hex` crate (already a dependency) and compared as a string.
`ring::constant_time::verify_slices_are_equal` is deprecated in `ring` 0.17.14 (read in
`src/deprecated_constant_time.rs` of the crate), so it would fail clippy with `-D warnings`; the
compared value is the SHA-256 of a random 32-byte key, so the time of the comparison can reveal at
most a prefix of that hash, from which the key cannot be recovered. The key is held in
`hyperswitch_masking::Secret<String>`, whose `Debug` prints a mask, and is never logged. Configured by environment variables in tests:
`LOCKER__TENANT_SECRETS__PUBLIC__CALLERS__<NAME>__KEY_HASH` and `…__MERCHANTS`.

## Tasks

### Task 1: end-to-end tests first, red on the current code
**Covers:** D1, D2, D4, D5, D6, D9

- Read first: the environment source options (`src/config.rs:227-231`): only
  `redis.cluster_urls` is split on commas, so a `merchants` value with commas stays one string.
- Before writing the expected JSON, check the error body shape on a real response: an existing
  error (for example the 404 of a missing card) is serialized from the same `ApiErrorResponse`
  (`src/error.rs:429-434`); the run of Task 1 shows it if `"data":null` is wrong.
- Assertion messages never print a response body; each run is piped with `tee` to a file in the
  session scratchpad, and each file is scanned (card numbers and 64-character hex strings, count 0),
  red runs included.
- Add to `tests/vault_e2e.rs`: a helper that generates a random 32-byte key (hex) and its SHA-256
  hex, never printed; a start helper built on the existing `Vault::start_with_env(db, master_key,
  extra)` (`tests/vault_e2e.rs:313`) that passes `LOCKER__TENANT_SECRETS__PUBLIC__CALLERS__READER__KEY_HASH`
  and `…__MERCHANTS`; `Vault::post_with_key(path, body, Option<&str>)`; constants for the two
  messages (`Caller is not allowed to read this merchant's data`, 403;
  `Caller key missing or unknown`, 401; both `code` `TE_00`).
- `caller_reads_only_its_merchants_cards`: vault started with one caller allowed for `MERCHANT`;
  cards stored for `MERCHANT` and `MERCHANT_2` with different card numbers; read of `MERCHANT`'s card
  with the key: 200 and exact number; read of `MERCHANT_2`'s card with its correct reference and
  customer: status 403 and body equal to
  `{"code":"TE_00","message":"Caller is not allowed to read this merchant's data","data":null}`, no
  card number; a read of `MERCHANT_2` with a reference that does not exist gets the same exact 403,
  not a 404 (the check runs before any lookup, D3); audit rows for the first two retrieves are `("locker_retrieve","success",200)` then
  `("locker_retrieve","failure",403)`, and no audit row holds a card number. The same two reads are
  repeated on `/cards/retrieve` (the same handler mounted a second time): 200, then the exact 403.
- `caller_without_a_valid_key_is_refused`: same vault; no header, then a random unknown key: 401 and
  body `{"code":"TE_00","message":"Caller key missing or unknown","data":null}` each time; the
  audit rows of these two reads are `("locker_retrieve","failure",401)` twice; a read with no key
  for a merchant that does not exist also gets the exact 401.
- `caller_reads_only_its_entities_through_v2`: v2 add for two entities, v2 retrieve: allowed entity
  200 and stored data; other entity 403 and the exact body; its audit row is
  `("vault_retrieve","failure",403)`.
- Run them on the branch before any `src/` change, with and without `key_custodian` (test names
  written literally, count of tests run checked): expect each to fail at the 403 or 401 assertion
  (status 200 today). A failure counts only if it is the assertion on the refusal's status or
  body: a failure at start-up, on the add or on the positive read means the test is wrong, not the
  control. Record the failure lines below.
- Commit the tests, then the execution notes: `test: add end-to-end tests for the per-caller read
  control`, `docs: record the red-run lines before the control`.

### Task 2: configuration, errors and check function, unit tests first
**Covers:** D3, D8, D9

- Checked on 2026-11-24 (read only): `ring`, `hex` and `hyperswitch_masking` are in `Cargo.toml`
  (lines 73-75); nothing is added.
- Write the unit tests first, with `authorize_read` as a stub returning `Ok(())`: run
  `cargo test -j 4 --lib authorize_read`, record the red lines, then implement and run green.
- Add `CallerConfig`, `callers`, the header constant, `OptionalCallerKey` (wrapping
  `Secret<String>`), `authorize_read`, and the two `ApiError` variants:
  `CallerKeyMissingOrUnknown`, `#[error("Caller key missing or unknown")]`, 401;
  `CallerNotAllowed`, `#[error("Caller is not allowed to read this merchant's data")]`, 403; both
  answered with `code` `TE_00` and the error's text as message. The audit row takes its status from
  the response of the error (`src/audit.rs:182-193`), so it records 401 or 403 with no change there.
- Unit tests in `src/custom_extractors.rs`: no callers allows; missing key refused (401 kind);
  unknown key refused; matching key and listed merchant allowed; matching key and unlisted
  merchant refused (403 kind); list parsing with spaces and an empty item; an empty list refuses
  every merchant; `format!("{:?}")` of an
  `OptionalCallerKey` does not contain the key.
- Read the request tracing and logging layers (`src/app.rs`, `src/logger/`) to confirm that no
  request header is written to the logs; note what was read in the execution notes. If a header is
  logged, stop and report to the owner before going on.
- `cargo test -j 4 --lib` green. Commit: `feat: add per-caller keys and the read check`.

### Task 3: wire the check into both retrieve routes
**Covers:** D1, D2, D3, D4, D5, D6, D7

- Add `OptionalCallerKey(caller_key)` to `retrieve_card` and `retrieve_data`, pass it to the inner
  functions, call `authorize_read(&tenant_app_state.config.tenant_secrets.callers, …, &merchant_id)`
  first (v2: `entity_id`).
- Run the three new tests (with and without `key_custodian`): green. Then the whole e2e file with
  `key_custodian` (at least 34 passed, expected 36) and the new tests without it.
- Commit: `feat: check the caller's merchants before a card is read`.

### Task 4: deliberate breakage
**Covers:** D9

- Replace the body of `authorize_read` with `Ok(())` (no commit); run the three new e2e tests and
  the unit tests of `authorize_read`: each e2e test must fail at the same assertion as in Task 1
  (the refusal's status), not elsewhere. Record the lines in a scratchpad file, restore
  `src/custom_extractors.rs` with `git checkout --`, check that `git status` shows no change
  outside the plan, then copy the lines into the execution notes and commit them
  (`docs: record the red-run lines with the check removed`).

### Task 5: table, docs, README
**Covers:** D10

- T19: control cites the check and the two call sites; evidence cites the three tests and the unit
  tests; not covered as in the design; status `proven`.
- Read `scripts/check-threat-model.sh` first: statuses accepted (`proven`), snake_case words in
  Evidence must be test names, cited lines must exist and not be blank.
- Fix T19's stale reference `docs/tokenization.md:207-208` (now about rotation); update
  `docs/tokenization.md` "/data/retrieve is de-tokenization" and the "No per-caller access rules"
  line; in `README.md`, under "Changes from the original", list each changed file: the six `src/`
  files, `tests/vault_e2e.rs`, the two docs and the two superpowers documents.
- `scripts/check-threat-model.sh` exit 0; counts of `GHSA` and `advisories` in the three files 0.
- Commit: `docs: mark T19 proven by the per-caller read control`.

### Task 6: full checks and reviews

- `cargo fmt --all --check` (stable; the CI's `cargo +nightly fmt` is not installed here, so it is
  reported as not run, and the CI job is what checks it); `RUSTFLAGS="-D warnings" cargo clippy -j 4 --all-features --all-targets`;
  `cargo test -j 4` (at least 79 passed); e2e with `key_custodian` (at least 34, the owner's
  threshold; expected 33 + 3 = 36) and the new tests without it; `make demo` shows `DEMO OK`.
- Scan the kept outputs for card numbers and 64-character hex strings: count 0.
- Reviews in parallel: a fresh `opus` subagent and `second-avis --reserve 50`, each with the brief
  verbatim, the diff without context lines, and checkable criteria; then `security-review`.

### Task 7: push, PR, CI, note (each after the owner's yes)

- Push the branch; show the PR title and text; open it with
  `-R antoinevoinchet-spec/hyperswitch-card-vault`; watch CI; tick T2 in the Obsidian note with a
  dated log line.

## Known limits of the test set-up

- `try_parsing(true)` in the environment source (`src/config.rs:229`) would turn a `key_hash` made
  of digits only into a number; the chance for a random SHA-256 is about 1 in 10^13.

## Execution notes

(filled during execution)

Task 1 runs (2026-11-24): `src/` identical to `main` (`git diff main --stat -- src` empty), PostgreSQL 14 on port 54330; outputs scanned for card numbers and 64-character hex strings: 0 in each. The failing line is `tests/vault_e2e.rs:2625` in that run and `:2631` after `cargo fmt` moved it (same `assert_eq!` in `assert_refusal`).

Task 3 (2026-11-24): the three new tests pass with and without `key_custodian` (3 passed each); the whole e2e file with `key_custodian`: 36 passed, 0 failed.

Task 2 (read on 2026-11-24): the request span records only `x-tenant-id` and `x-request-id` (`src/utils.rs:102-124`, used by the trace layer in `src/app.rs:281-283`); no other request header is logged.

| Run | Test | Failure line (assertion and values) |
|---|---|---|
| Task 1, before any `src/` change | `caller_reads_only_its_merchants_cards` | `tests/vault_e2e.rs:2625` (`assert_refusal`; the same `assert_eq!` is at `:2631` after `cargo fmt`, which is the line of the Task 4 runs): `assertion left == right failed: /data/retrieve: status`, left 200, right 403; the read of the caller's own card passed first. Same with and without `key_custodian` (3 run, 0 passed, 3 failed). |
| Task 1, before any `src/` change | `caller_without_a_valid_key_is_refused` | `tests/vault_e2e.rs:2625`: `no key: status`, left 200, right 401; both modes. |
| Task 1, before any `src/` change | `caller_reads_only_its_entities_through_v2` | `tests/vault_e2e.rs:2625`: `v2 other entity: status`, left 200, right 403; the two v2 adds and the allowed v2 read passed first; both modes. |
| Task 4, check removed | `caller_reads_only_its_merchants_cards` | `authorize_read` made to return `Ok(())` always (not committed): `tests/vault_e2e.rs:2631`, `/data/retrieve: status`, left 200, right 403 (3 run, 0 passed, 3 failed, with `key_custodian`). |
| Task 4, check removed | `caller_without_a_valid_key_is_refused` | `tests/vault_e2e.rs:2631`, `no key: status`, left 200, right 401. |
| Task 4, check removed | `caller_reads_only_its_entities_through_v2` | `tests/vault_e2e.rs:2631`, `v2 other entity: status`, left 200, right 403. |
| Task 2, stub before the check | unit tests of `authorize_read` | stub returning `Ok(())`, `cargo test -j 4 --lib --features key_custodian caller_tests`: 3 passed, 5 failed (`authorize_read_refuses_a_missing_key` at `src/custom_extractors.rs:190`, `authorize_read_refuses_an_unknown_key` at `:198`, `authorize_read_refuses_an_unlisted_merchant` at `:211`, `authorize_read_with_an_empty_list_refuses_every_merchant` at `:224`, `authorize_read_needs_the_exact_key_hash` at `:238`); the three that passed test allowed reads and the masked `Debug`. With the check: 8 passed, with and without `key_custodian`. |
| Task 4, check removed | unit tests of `authorize_read` | 3 passed, 5 failed: the same five refusal tests as with the stub (`src/custom_extractors.rs:212`, `:220`, `:233`, `:246`, `:260`, lines moved by the implementation). Restored with `git checkout -- src/custom_extractors.rs`; the three e2e tests pass again (3 passed). |

Reviews (2026-11-24):
- `security-review`: no finding.
- Second opinion (gpt-6.2-sol, through `second-avis`, 0.0435 USD): two remarks. Confirmed: two
  callers sharing one key gave a decision that depended on the map's order. Rejected: "the tests
  pass without a database"; every run set `VAULT_TEST_REQUIRE_DB=1`, which fails a test when the
  database is missing (`tests/vault_e2e.rs:39-42`).
- Fresh `opus` subagent: one important deviation, confirmed: `key_hash` was a plain `String` and the
  start-up configuration dump (`src/app.rs:316`, level `DEBUG` in `config/development.toml`) would
  print it; plus the two minor points fixed here (this status line, the line moved by `cargo fmt`)
  and the shared key above. A list written with spaces (`m1, m2`) refuses the merchant after the
  space: it fails closed and the field's comment now says "with no spaces".
- Fix, test first: `authorize_read_with_two_callers_sharing_a_key_uses_both_lists` failed at
  `src/custom_extractors.rs:278` and `caller_config_debug_hides_the_key_hash` at `:286` (8 passed,
  2 failed); after the fix 10 passed with and without `key_custodian`; e2e 36 passed with
  `key_custodian`, 32 without; `cargo test -j 4` 92 passed; `make demo` DEMO OK; clippy and fmt 0.
