# Per-caller write control (T37) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a caller may read, add or delete a card only for a merchant (v2: entity) on its list and
only with the matching right; a tenant with no caller refuses every data call.

**Architecture:** the T2 check `authorize_read` becomes `authorize_caller(callers, key, merchant,
right)`; each caller gains a `rights` field (absent = `read`); the check is the first statement of
the six retrieve, add and delete inner functions (v1 and v2). The e2e harness declares a default
caller; the demo generates its own caller key at each run.

**Tech Stack:** Rust, axum, diesel/PostgreSQL, `ring` (SHA-256), `hex`, `hyperswitch_masking`.

**Spec:** `docs/superpowers/specs/2026-11-24-per-caller-write-control-design.md` (D-A: option A;
D-B: option B; requirements D1 to D12).

Branch: `feat/per-caller-write-control`. Status: written 2026-11-24, awaiting the owner's approval
(including `src/config.rs`).

## Global Constraints

- No new dependency; no hand-written cryptography; `Cargo.toml`, `Cargo.lock`, `migrations/`,
  `scripts/`, `.github/` unchanged.
- Refusal bodies, exactly: 401 `{"code":"TE_00","message":"Caller key missing or unknown","data":null}`;
  403 `{"code":"TE_00","message":"Caller is not allowed to read this merchant's data","data":null}`.
- New test names avoid the `rehash_` and `rotation_` prefixes.
- Caller keys: `hex::encode` of 32 random bytes, generated in the test or the demo, never printed;
  only the lower-case hex SHA-256 is configured. Every kept output is piped with `tee` to the
  session scratchpad and scanned for card numbers and 64-character hex strings (count 0).
- Before `cargo`: `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"`.
- E2e command (`E2E` below): `VAULT_TEST_DATABASE_URL=<local admin URL> VAULT_TEST_REQUIRE_DB=1
  cargo test -j 4 [--features key_custodian] --test vault_e2e <names> -- --exact`; every run is
  done with and without `--features key_custodian`, and the count of tests run is checked.
- Never run a project script with `--help` unless its code handles it.
- `git status` before each commit; one logical change per commit.
- Every `gh pr …` / `gh issue …` / `gh run …` command carries `-R antoinevoinchet-spec/hyperswitch-card-vault`.
- No `.env*` file is read; the local admin database URL is the one of the local PostgreSQL started
  for the tests (as in T2: port 54330), never taken from a file.
- No compliance, certification or audit claim in any added line (checked in Task 6 and Task 7).

## Review Focus

1. A `rights` value with a space (`read, add`): the word after the space is unknown, so it grants
   nothing (fail closed). Pinned in Task 2 (`authorize_caller_ignores_unknown_rights`).
2. Two callers sharing a key, one with `add` for M1, the other with `delete` for M2: `add` on M2
   must be refused (a right of one caller must not combine with a merchant of another). Pinned in
   Task 2 (`authorize_caller_does_not_mix_two_callers_rights`).
3. A refused add must not create the `merchant` row and its key (`find_or_create_entity`): the
   `merchant` count is asserted in Task 1 (`caller_adds_only_for_its_merchants`).
4. A refused delete of a reference that does not exist must answer the same 403 as an existing
   one (no existence oracle): Task 1 (`caller_deletes_only_its_merchants_cards`).
5. `/cards/add` and `/cards/delete` exist: `src/app.rs:192-205` mounts the same v1 router under
   `/data` and `/cards`. The v1 tests of Task 1 refuse an add and a delete on `/cards/…` too.
   No other route writes `locker`, `hash_table` or `vault` rows on a caller's request (read on
   2026-11-24: the rest of the table is `/entity`, `/key/transfer` and the fingerprint routes).

---

### Task 1: end-to-end tests first, red on the current code
**Couvre:** D2, D3, D4, D5, D6, D7, D8, D9, D10, D11

**Files:**
- Modify: `tests/vault_e2e.rs` (harness near `:307-375`, caller helpers near `:2580-2660`, new tests
  at the end)

**Interfaces:**
- Produces: `DEFAULT_CALLER_KEY: std::sync::LazyLock<(String, String)>` (key, SHA-256), declared
  by `Vault::start_with_env` as caller `HARNESS` with rights `read,add,delete` and merchants
  `MERCHANT,MERCHANT_2,MERCHANT_3,MERCHANT_NO_CARD` plus every other merchant or entity id found by
  reading the file (list them in the execution notes), always, beside any caller in `extra` (its
  key differs from theirs, so the T19 tests still read with their own key and store through
  `post` with the harness key); `Vault::start_without_callers(db,
  master_key)`; `Vault::post` sends `x-vault-caller-key` = the default key when the vault declared
  it, `post_with_key` sends only the key it is given; `start_with_callers(db, keys,
  &[(name, key_hash, merchants, Option<rights>)])`; `fn row_counts(db) -> (i64, i64, i64, i64)`
  for `locker`, `hash_table`, `vault`, `merchant`.

- [ ] **Step 1:** add the harness pieces above. Run the whole e2e file with `key_custodian`:
  expected 36 passed (the T19 tests keep their own caller, the others use the default one).
- [ ] **Step 2:** write the seven tests of the design, asserting with `assert_refusal` and
  `audit_of`:
  - `caller_adds_only_for_its_merchants` (D2): callers `writer` (M1, `add`) and `other` (M2, all
    rights); add for M1 by `writer` 200; counts before; add for M2 by `writer`: exact 403; counts
    after equal (all four); audit `("locker_add","failure",403)` last; the same refused add on
    `/cards/add`: exact 403, counts equal; an add for a merchant that never existed and is not
    listed, with a body that `request.validate()` refuses (read the `Validation` impl of
    `StoreCardRequest` to pick one): exact 403, not the validation error, and the `merchant` count
    unchanged (D8: the check runs before validation and before `find_or_create_entity`).
  - `caller_deletes_only_its_merchants_cards` (D3): `other` stores a card for M2; `writer` (M1,
    `delete`) deletes it: exact 403; counts equal; `other` reads it back 200 with the exact number;
    `writer` deletes a random reference of M2: same exact 403; `writer` deletes a reference of a
    merchant that never existed and is not listed: same exact 403 (D8: the check runs before the
    merchant's key is looked up, so an unknown merchant answers like a refused one); audit
    `("locker_delete","failure",403)`; the same refused delete on `/cards/delete`: exact 403; a third caller `owner` (M1, all rights) stores a card for M1;
    `writer` deletes it 200, then `owner` reads it and gets 404.
  - `caller_without_a_valid_key_cannot_add_or_delete` (D4): add and delete with no key, then with
    a random key: exact 401 each, counts equal, four audit rows at 401.
  - `caller_adds_and_deletes_only_its_entities_through_v2` (D5): as D2 and D3 on
    `/api/v2/vault/add` and `/api/v2/vault/delete` with `entity_id`, counts equal, audit
    `vault_add` / `vault_delete` at 403; a v2 delete for an entity that never existed: same exact
    403; a v2 add with `?mode=upsert` on the existing `vault_id` of an unlisted entity: exact 403,
    and the entry read back by its owner unchanged, counts equal; a v2 add for an entity that never existed and is not
    listed, with a body `validate()` refuses: exact 403, `merchant` count unchanged (D8).
  - `caller_without_a_valid_key_cannot_add_or_delete_through_v2` (D5): as D4 on v2.
  - `caller_needs_the_right_for_each_operation` (D6): callers `reader` (M1, no `rights` variable),
    `adder` (M1, `add`), `deleter` (M1, `delete`); on v1 then v2: each allowed operation 200 and
    each other one exact 403, counts equal after each refusal; the audit row of the first refusal
    (`reader` adding) is `("locker_add","failure",403)`.
  - `tenant_without_callers_refuses_every_data_call` (D7): `start_without_callers`; read, add,
    delete on v1 and v2 (six calls, with a key and without): exact 401, counts equal; audit rows of
    the v1 add and the v2 delete at 401.
- [ ] **Step 3:** run the seven tests (names literal, `-- --exact`), with and without
  `key_custodian`. Expected: each fails at a refusal assertion (`status`, left 200), never at
  start-up, at an add meant to pass, or at a count. Record the lines in the execution notes.
- [ ] **Step 4:** commit `test: add end-to-end tests for the per-caller write control`, then
  `docs: record the red-run lines before the write control`.

### Task 2: rights and the check function, unit tests first
**Couvre:** D1, D7

**Files:**
- Modify: `src/config.rs:154-167` (needs the owner's approval), `src/custom_extractors.rs:139-299`,
  `src/routes/data.rs:17-20,257-261` and `src/routes/routes_v2/data.rs:13,80-84` (the two read call
  sites move to `authorize_caller(…, CallerRight::Read)` here, so the crate still compiles)

**Interfaces:**
- Produces: `CallerConfig.rights: String` with `#[serde(default = "default_caller_rights")]`
  returning `"read"`; `pub enum CallerRight { Read, Add, Delete }` (words `read`, `add`,
  `delete`); `pub fn authorize_caller(callers: &HashMap<String, CallerConfig>, caller_key:
  Option<&Secret<String>>, merchant_id: &str, right: CallerRight) -> Result<(), ApiError>`;
  `authorize_read` removed.

- [ ] **Step 0:** stop unless the owner has said yes to changing `src/config.rs`.
- [ ] **Step 1:** rename the existing unit tests' calls to `authorize_caller(…, CallerRight::Read)`
  (names kept), replace `authorize_read_allows_any_read_without_callers` with
  `authorize_caller_refuses_every_call_without_callers` (each right, `None` and a key:
  `CallerKeyMissingOrUnknown`), and add: `authorize_caller_allows_only_the_listed_rights` (for
  each of `read`, `add`, `delete` alone: that right Ok for a listed merchant and `CallerNotAllowed`
  for an unlisted one, the two other rights `CallerNotAllowed`; `rights = ""`: every right
  refused), `authorize_caller_reads_by_default` (rights
  absent from a TOML-deserialized `CallerConfig`: Read Ok, Add and Delete refused),
  `authorize_caller_ignores_unknown_rights` (`write`, `read, add`: only what is spelled exactly is
  granted), `authorize_caller_does_not_mix_two_callers_rights` (Review Focus 2). Stub
  `authorize_caller` returning `Ok(())`; run `cargo test -j 4 --lib caller_tests` with and without
  `key_custodian`; record the red lines.
- [ ] **Step 2:** implement. Empty `callers` → `CallerKeyMissingOrUnknown`. Otherwise as T2, and a
  matching caller allows only if its merchant list holds `merchant_id` **and** its `rights` list
  holds the right's word (both on the same caller).
- [ ] **Step 3:** rewire the two retrieve call sites to `authorize_caller(…, CallerRight::Read)`;
  `cargo build -j 4` and `cargo test -j 4 --lib` green, both modes. Commit
  `feat: add per-caller rights and refuse tenants without callers`.

### Task 3: wire the check into the six routes
**Couvre:** D2, D3, D4, D5, D6, D7, D8, D9

**Files:**
- Modify: `src/routes/data.rs` (`add_card` `:95-116`, `delete_card` `:202-219`, `retrieve_card`
  `:240-261`), `src/routes/routes_v2/data.rs` (`delete_data` `:23-41`, `retrieve_data` `:62-84`,
  `add_data` `:140-157`)

**Interfaces:**
- Consumes: `OptionalCallerKey`, `authorize_caller`, `CallerRight` (Task 2).

- [ ] **Step 1:** add `OptionalCallerKey(caller_key)` to the four write handlers, pass it to the
  inner functions, and call `authorize_caller(&tenant_app_state.config.tenant_secrets.callers,
  caller_key.as_ref(), &request.merchant_id /* v2: entity_id */, CallerRight::Add|Delete)?` as the
  first statement (before `request.validate()`).
- [ ] **Step 2:** `E2E` on the seven new tests (7 passed) and the whole file (expected 43 passed
  with `key_custodian`), both modes for the new tests. Commit
  `feat: check the caller's rights before a card is added or deleted`.

### Task 4: demo and example configuration
**Couvre:** D-A, D9, D10

**Files:**
- Modify: `demo/run.sh` (keys block `:100-108`, start `:111-118`, `step` `:130-145`),
  `demo/README.md`, `config/config.example.toml`

- [ ] **Step 0:** search `/data/`, `/cards/`, `/api/v2/vault/` in `.github/workflows`, `Makefile`,
  `scripts/`, `README.md`, `docs/` (read on 2026-11-24: in CI only `make demo` and the e2e tests
  call these routes; `docs/openapi*` and the Postman collection describe them, reported only).
  An example call in `README.md` or `docs/tokenization.md` is updated to send
  `x-vault-caller-key`; a caller outside the allowed files that would break: stop and ask the owner.
- [ ] **Step 1:** `demo/run.sh`: `CALLER_KEY=$(openssl rand -hex 32)`, its hash with
  `printf '%s' "$CALLER_KEY" | openssl dgst -sha256 -r | cut -d' ' -f1`; pass
  `LOCKER__TENANT_SECRETS__PUBLIC__CALLERS__DEMO__KEY_HASH`, `…__MERCHANTS` (every merchant and
  entity id the demo uses, read from the script) and `…__RIGHTS=read,add,delete`; write the header
  line to a `chmod 600` file in `$TMP` and give it to curl with `-H @file`, so the key stays out of
  the process list and the output. Echo "Generated a caller key (not shown)".
- [ ] **Step 2:** `demo/README.md`: one sentence on the caller key; `config/config.example.toml`:
  a commented `[tenant_secrets.public.callers.<name>]` example with `key_hash`, `merchants`,
  `rights` and a comment that a tenant without callers refuses every data call.
- [ ] **Step 3:** `make demo | tee <scratchpad>/demo.txt`: last line `DEMO OK`; scan the file.
  Commit `feat: give the demo its own caller key`.

### Task 5: deliberate breakage
**Couvre:** D6, D7, D11

- [ ] **Step 1:** four runs, each with one write call of `authorize_caller` removed (v1 add, v1
  delete, v2 add, v2 delete; no commit): run the six write tests, both modes, and record which test
  fails at which line in each run; every run must turn at least one test red at a refusal
  assertion of that route. Restore with `git checkout --` after each run.
- [ ] **Step 2:** make the empty-`callers` branch return `Ok(())` (no commit); run
  `tenant_without_callers_refuses_every_data_call` and the unit tests, both modes: fail at the
  401. Restore; `git status` clean in `src/`; the seven tests pass again.
- [ ] **Step 3:** make `authorize_caller` ignore `rights` (merchant list only; no commit); run
  `caller_needs_the_right_for_each_operation` and the rights unit tests, both modes: fail at the
  first refused right. Restore.
- [ ] **Step 4:** record the lines in the execution notes; commit
  `docs: record the red-run lines with the write control removed`.

### Task 6: threat table, tokenization doc, README
**Couvre:** D12

**Files:**
- Modify: `docs/threat-model.md` (T19 `:68`, T37 `:86`, "How to check" list `:19`),
  `docs/tokenization.md` (`:62-86`, `:274-276`), `README.md` ("Changes from the original")

- [ ] **Step 1:** T37: control cites `authorize_caller` and the four write call sites with their
  new lines, evidence the seven tests and the new unit tests, "Not covered" as in the design,
  status `proven`. T19: drop add, delete and tenants without callers from "Not covered", replace
  `authorize_read_allows_any_read_without_callers` by
  `authorize_caller_refuses_every_call_without_callers`, shift every moved line reference.
  Add T37 to the list of rows cited by the e2e command. Then re-read every `path:N` of the whole
  table that points into a file this branch changed (`tests/vault_e2e.rs`, `src/routes/…`,
  `src/custom_extractors.rs`, `src/config.rs`, `demo/run.sh`, `config/config.example.toml`,
  `docs/tokenization.md`) and fix each one that moved: the script checks that a line exists, not
  that it is the right one.
- [ ] **Step 2:** `docs/tokenization.md`: the de-tokenization section and the "No masking…"
  paragraph describe rights, the mandatory check and what stays open. `README.md`: every changed
  file listed (`src/config.rs`, `src/custom_extractors.rs`, `src/routes/data.rs`,
  `src/routes/routes_v2/data.rs`, `tests/vault_e2e.rs`, `demo/run.sh`, `demo/README.md`,
  `config/config.example.toml`, the two docs, the design and this plan).
- [ ] **Step 3:** `scripts/check-threat-model.sh`: exit 0 and `38 rows (18 proven, 6 not tested,
  14 open)`; `grep -c` of `GHSA` and `advisories` in the three files: 0; the added lines of the
  three files re-read for any compliance, certification or audit claim (patterns kept in the
  scratchpad, not in the repository); the e2e command of "How to check it yourself" run as written,
  with `VAULT_TEST_REQUIRE_DB=1`, with and without `--features key_custodian`: exit 0. Commit
  `docs: mark T37 proven by the per-caller write control`.

### Task 7: full checks and reviews

- [ ] `cargo fmt --all --check`; `RUSTFLAGS="-D warnings" cargo clippy -j 4 --all-features
  --all-targets`; `cargo test -j 4`; `E2E` whole file both modes; `make demo`; scans of every kept
  output; `git diff main -U0 | grep '^+' | grep -cE '[0-9a-f]{64}'` gives 0 (count only, never
  printed); `git diff main --name-only` against the allowed lists and against the README list.
  `typos`, `cargo nextest` and `cargo +nightly fmt` are not installed: reported "not run", nothing
  installed; the CI checks them.
- [ ] `security-review` on the branch; then, in parallel, a fresh `opus` subagent and
  `second-avis --reserve 50`, each with the owner's brief verbatim, the diff without context
  lines (`custodian_key1` / `custodian_key2` lines removed) and the Completion criteria.
- [ ] Fix what is confirmed (test first), record the verdicts in the execution notes.

### Task 8: push, PR, CI, note (each after the owner's yes)

- [ ] Push; show the PR title and text; open it with `-R antoinevoinchet-spec/hyperswitch-card-vault`;
  watch CI; a red job caused by this branch is fixed on the branch and pushed again only after the
  owner's yes; a red job caused by the original code is reported and fixed only after the owner's
  yes; tick T12 in the Obsidian note, update D-A and D-B under "Décisions", add a dated log line.

## Execution notes

Task 1 (2026-11-24): local PostgreSQL 14 on port 54330 (throwaway, in the session scratchpad).
Harness merchants read in the file: `demo-merchant`, `demo-merchant-2`, `demo-merchant-3`,
`merchant-no-card`, `legacy-merchant`, `no-such-merchant`. Step 1, whole e2e file with the harness
caller on the code of `main` (`key_custodian`): 36 passed, 0 failed. Outputs scanned for card
numbers and 64-character hex strings: 0 in each.

| Run | Test | Failure line (assertion and values) |
|---|---|---|
| Task 1, before any `src/` change, with and without `key_custodian` (7 run, 0 passed, 7 failed each) | `caller_adds_only_for_its_merchants` | `tests/vault_e2e.rs:2665` (`assert_refusal`): `/data/add: status`, left 200, right 403; the caller's own add passed first. |
| same | `caller_deletes_only_its_merchants_cards` | `:2665`: `/data/delete: status`, left 200, right 403; the two adds passed first. |
| same | `caller_without_a_valid_key_cannot_add_or_delete` | `:2665`: `add, no key: status`, left 200, right 401. |
| same | `caller_adds_and_deletes_only_its_entities_through_v2` | `:2665`: `v2 add for another entity: status`, left 200, right 403; the two v2 adds passed first. |
| same | `caller_without_a_valid_key_cannot_add_or_delete_through_v2` | `:2665`: `v2 add, no key: status`, left 200, right 401. |
| same | `caller_needs_the_right_for_each_operation` | `:2665`: `reader adds: status`, left 200, right 403. |
| same | `tenant_without_callers_refuses_every_data_call` | `:2665`: `/data/add, no key: status`, left 200, right 401. |
| Task 5, v1 add call removed, with and without `key_custodian` (6 run, 3 passed, 3 failed each) | `caller_adds_only_for_its_merchants`, `caller_needs_the_right_for_each_operation`, `caller_without_a_valid_key_cannot_add_or_delete` | `tests/vault_e2e.rs:2665`: `/data/add: status`, `reader adds: status` (left 200, right 403), `add, no key: status` (left 200, right 401). |
| Task 5, v1 delete call removed, both modes (3 passed, 3 failed) | `caller_deletes_only_its_merchants_cards`, `caller_needs_the_right_for_each_operation`, `caller_without_a_valid_key_cannot_add_or_delete` | `:2665`: `/data/delete: status`, `reader deletes: status` (403 expected, 200 got), `delete, no key: status` (401 expected, 200 got). |
| Task 5, v2 add call removed, both modes (3 passed, 3 failed) | `caller_adds_and_deletes_only_its_entities_through_v2`, `caller_needs_the_right_for_each_operation`, `caller_without_a_valid_key_cannot_add_or_delete_through_v2` | `:2665`: `v2 add for another entity: status`, `reader adds through v2: status` (403 expected, 200 got), `v2 add, no key: status` (401 expected, 200 got). |
| Task 5, v2 delete call removed, both modes (3 passed, 3 failed) | `caller_adds_and_deletes_only_its_entities_through_v2`, `caller_needs_the_right_for_each_operation`, `caller_without_a_valid_key_cannot_add_or_delete_through_v2` | `:2665`: `v2 delete of another entity's entry: status`, `reader deletes through v2: status` (403 expected, 200 got), `v2 delete, no key: status` (401 expected, 200 got). |
| Task 5, empty `callers` allowed again, both modes | `tenant_without_callers_refuses_every_data_call` and the unit tests | e2e `:2665`: `/data/add, no key: status`, left 200, right 401 (0 passed, 1 failed); unit: `authorize_caller_refuses_every_call_without_callers` at `src/custom_extractors.rs:246` (13 passed, 1 failed). |
| Task 5, `rights` ignored (merchant list only), both modes | `caller_needs_the_right_for_each_operation` and the unit tests | e2e `:2665`: `reader adds: status`, left 200, right 403; unit: 10 passed, 4 failed (`authorize_caller_allows_only_the_listed_rights` `:260`, `authorize_caller_reads_by_default` `:287`, `authorize_caller_ignores_unknown_rights` `:298`, `authorize_caller_does_not_mix_two_callers_rights` `:324`, lines of the mutated file). |

Task 2 (2026-11-24): stub `authorize_caller` returning `Ok(())`, `cargo test -j 4 --lib caller_tests`, both modes: 4 passed, 10 failed (every refusal test); with the check, `cargo test -j 4 --lib`: 62 passed, both modes. Task 3: whole e2e file 43 passed with `key_custodian`, 39 without. Task 4: `make demo` ends with `DEMO OK`. Task 5: each mutation restored with `git checkout --`; `git status` clean; the seven tests pass again (7 passed, `key_custodian`). Every output above scanned for card numbers and 64-character hex strings: 0.
