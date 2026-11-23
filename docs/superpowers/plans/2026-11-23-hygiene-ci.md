# CI hygiene (ticket H1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Check the Rust dependencies and run OpenSSF Scorecard in CI, and prove in CI the two re-hash
paths that are only compiled today (refusal under `kv`, run without `key_custodian`).

**Architecture:** Two new workflows (`dependencies.yml`, `scorecard.yml`) and two new jobs in
`CI-pr.yml`; `deny.toml` at the root; `tests/vault_e2e.rs` made to compile with and without
`key_custodian`, plus one `kv` test. No change to `src/`, `Cargo.toml` or `Cargo.lock`.

**Tech Stack:** GitHub Actions, cargo-deny 0.22.0, ossf/scorecard-action v2.5.0, Rust tests with
diesel against a throwaway PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-11-23-hygiene-ci-design.md`

## Global Constraints

- Allowed files: `.github/workflows/` (new jobs or files; existing jobs unchanged), `deny.toml`,
  `tests/`, `docs/threat-model.md`, `docs/tokenization.md`, `README.md`, `docs/superpowers/`.
- Every `cargo` command is prefixed by `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"` and uses `-j 4`.
- Repository text in English; no word that `typos` reads as a misspelling; none of the words forbidden by
  the project `CLAUDE.md`; `docs/threat-model.md`, `docs/tokenization.md` and `README.md` never contain
  `GHSA` or `advisories` (write "known vulnerabilities", "RustSec database").
- No `.env*` file, key value or `master_key` is read, printed or committed.
- Every action added is pinned by full SHA with its tag in a comment:
  - `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`
  - `actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2`
  - `ossf/scorecard-action@fa7117db83c52d787ae5a89f350999701505d78e # v2.5.0`
  - `dtolnay/rust-toolchain@df2a88e9fe4098bad09cb42c3dec7187f15861fc # master on 2026-11-15`
  - `Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1`
  - `rui314/setup-mold@339e96b4ff1f3bd865856ba4cbbe8818a7acb038 # v1`
  - `taiki-e/install-action@fe3acb53a98b62c772db35de75ce0e4595e7ca8c # v2.90.8` (first version that
    knows cargo-deny 0.22.0; 0.21.0 or later is needed for `expiry`)
- Exceptions for known vulnerabilities of the original code expire on `2027-02-21` (owner's Q1 = A).
- Stops for the owner's yes: installing a tool, editing a file outside the allowed list (the breakage
  branch's `Cargo.toml`/`Cargo.lock` included), each push, each PR, each merge or branch deletion.
- Local PostgreSQL: throwaway cluster, TCP only, port 54330 (see Task 1, step 1); stopped and deleted
  at the end of each task that starts it.

## Review Focus

- A test filter that matches no test makes a green job: each new CI job checks the number of tests run.
- A refusal test that passes for another reason (bad configuration, database unreachable): the `kv`
  test checks the error kind and the audit row `rehash_run` = `failure`.
- Dead code without `key_custodian` breaks `RUSTFLAGS="-D warnings"`: compile the tests with default
  features and with `kv` alone (Task 1 step 5, Task 2 step 5).
- An exception given as a duration (`P90D`) counts from each entry's publication, so old entries would
  already be expired: the date is absolute (Task 4).
- The Scorecard action may refuse a fork: Task 5 has a fallback.

---

### Task 1: End-to-end tests compile and run without `key_custodian`

**Couvre:** D4, D7

**Files:**
- Modify: `tests/vault_e2e.rs` (line 7 file-level `cfg`; `Keys` lines 224-252; `unlock` 366-379;
  `send_key` 481-489; `custodian_rows` 491-497; the three custodian-only tests; lines 756-761 of
  `stored_card_hash_is_not_a_plain_sha512`; `unlocked_master_key` 682-688)

**Interfaces:**
- Produces: `Keys { master_key: String, key1: String, key2: String }` where `master_key` is the value
  given to the vault and `utils` (encrypted hex with `key_custodian`, raw hex without);
  `unlocked_master_key(&Keys) -> Vec<u8>` returns the raw key in both modes; `unlock(&Vault, &Keys)` is a
  no-op without `key_custodian`.

- [ ] **Step 1: Start a throwaway PostgreSQL and record the baseline.**
  `PG=/opt/homebrew/opt/postgresql@14/bin; P=$SCRATCH/pg; $PG/initdb -D $P -U postgres -A trust >/dev/null && $PG/pg_ctl -D $P -o "-p 54330 -c unix_socket_directories='' -c listen_addresses=127.0.0.1" -l $P.log start`.
  Run `VAULT_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:54330/postgres VAULT_TEST_REQUIRE_DB=1 cargo test -j 4 --test vault_e2e rehash_`
  (no feature). Expected: `running 0 tests` (the file is compiled out today: the run without custodians
  proves nothing yet).

- [ ] **Step 2: Make the file compile in both modes.**
  - Remove `#![cfg(feature = "key_custodian")]`.
  - `Keys::generate`: still runs `utils master-key`; with `key_custodian`, unchanged; without it,
    decrypts the master key in memory (key 1 + key 2, `GcmAes256`) and stores `hex::encode(raw)` in
    `master_key`, as an operator without custodians would configure it.
  - `unlocked_master_key`: with `key_custodian`, unchanged; without it, `hex::decode(&keys.master_key)`.
  - `unlock`: body under `#[cfg(feature = "key_custodian")]`, otherwise `let _ = (vault, keys);`.
  - `#[cfg(feature = "key_custodian")]` on `send_key`, `custodian_rows`,
    `custodian_steps_write_audit_rows`, `custodian_key_is_refused_when_audit_table_is_unwritable`,
    `rehash_refuses_wrong_custodian_keys`.
  - `stored_card_hash_is_not_a_plain_sha512`: replace its own decryption (lines 756-761) by
    `let master_key = unlocked_master_key(&keys);`.

- [ ] **Step 3: Run the re-hash tests without `key_custodian`.**
  Same command as step 1. Expected: `test result: ok. 11 passed; 0 failed` (12 re-hash tests minus
  `rehash_refuses_wrong_custodian_keys`).

- [ ] **Step 4: Deliberate breakage, then revert.**
  In `src/bin/utils.rs`, comment out the `fetch_raw_secrets` call (lines 217-220), so the master key is
  used as its hex text instead of its bytes. Run
  `... cargo test -j 4 --test vault_e2e rehash_moves_v1_rows_to_scoped_hashes`.
  Expected: FAIL, message `does not cite its v2 hash` (keep the output for the report). Then
  `git checkout -- src/bin/utils.rs` and `git diff --name-only -- src` prints nothing.

- [ ] **Step 5: No regression and no dead code.**
  - With custodians: `... cargo test -j 4 --features key_custodian --test vault_e2e`. Expected:
    `20 passed; 0 failed`.
  - `RUSTFLAGS="-D warnings" cargo clippy -j 4 --all-targets` (default features) and
    `cargo clippy -j 4 --all-features --all-targets`: no new warning compared with `main` (only the
    known `digest`, `gethostname` and `num-bigint-dig` notices).
  - `cargo fmt --all --check`: exit 0.
  - Stop and delete the cluster: `$PG/pg_ctl -D $P stop && rm -rf $P $P.log`.

- [ ] **Step 6: Commit** `tests/vault_e2e.rs`: `test: run the end-to-end tests with and without key_custodian`.

### Task 2: Refusal of `utils rehash` under `kv`

**Couvre:** D3

**Files:**
- Modify: `tests/vault_e2e.rs` (new test after `rehash_refuses_a_batch_size_of_zero`)

**Interfaces:**
- Consumes: `TestDb`, `Keys`, `run_rehash`, `insert_hash_row`, `random_bytes`, `snapshot`,
  `audit_rows` from Task 1.

- [ ] **Step 1: Write the test** `#[cfg(feature = "kv")] #[tokio::test] async fn rehash_refuses_to_run_with_kv()`:
  no vault started (it would need Redis); `insert_hash_row(&db, "orphan-v1", &random_bytes(64), "'2000-01-01'")`;
  `before = db.snapshot()`; `run_rehash(&db, &keys, &keys.key2, &[])`. Assertions:
  - `code == 1` ("rehash must refuse to run under kv");
  - `output.contains("rehash failed: RetrieveDataFailed")` (the first refused call, `find_locker_batch`,
    maps to `RetrieveDataFailed`; adjust to the observed kind once, in step 2, and say so);
  - `db.snapshot() == before` ("a row changed under kv");
  - the `rehash_` audit rows are exactly `[("rehash_run", "failure")]` (the job itself ran and refused;
    no clean-up entry).

- [ ] **Step 2: Run it** with a throwaway cluster (Task 1 step 1):
  `... cargo test -j 4 --features key_custodian,kv --test vault_e2e rehash_refuses_to_run_with_kv`.
  Expected: `1 passed`.

- [ ] **Step 3: Deliberate breakage, then revert.** In `src/storage/db.rs`, run the PostgreSQL code under
  `kv` too for the six re-hash primitives and `DeletedHash`: in lines 309-614, replace each refusal's
  `#[cfg(feature = "kv")]` by `#[cfg(any())]` and the following `#[cfg(not(feature = "kv"))]` by
  `#[cfg(all())]`. Run step 2 again. Expected: FAIL on `rehash must refuse to run under kv` (exit code
  0, the orphan row deleted). Revert with `git checkout -- src/storage/db.rs`; `git diff --name-only -- src`
  prints nothing.

- [ ] **Step 4: Run the full suites again**: Task 1 step 5 commands, plus
  `RUSTFLAGS="-D warnings" cargo clippy -j 4 --features kv --all-targets` (`kv` without `key_custodian`).

- [ ] **Step 5: Commit** `tests/vault_e2e.rs`: `test: prove that utils rehash refuses to run with the kv feature`.

### Task 3: CI jobs for the two re-hash paths

**Couvre:** D3, D4, D5

**Files:**
- Modify: `.github/workflows/CI-pr.yml` (append two jobs after `integration-db`; existing jobs untouched)

- [ ] **Step 1: Add job `rehash-without-custodian`**, name "Re-hash without the key_custodian feature":
  `permissions: contents: read`; same PostgreSQL service block as `integration-db`; steps checkout,
  setup-mold, rust-toolchain (`stable 2 weeks ago`), rust-cache, all pinned as in Global Constraints;
  run (bash) `cargo test --test vault_e2e rehash_ 2>&1 | tee test-output.txt`, then fail unless the
  output has `test result: ok. 11 passed`, with env `VAULT_TEST_DATABASE_URL: postgres://postgres@localhost:5432/postgres`
  and `VAULT_TEST_REQUIRE_DB: "1"`.

- [ ] **Step 2: Add job `rehash-kv`**, name "Re-hash refusal with the kv feature": same shape, run
  `cargo test --features key_custodian,kv --test vault_e2e rehash_refuses_to_run_with_kv -- --exact`,
  fail unless `test result: ok. 1 passed`.

- [ ] **Step 3: Check the file**: `git diff main -- .github/workflows/CI-pr.yml` shows only added lines
  after the last existing job; `python3 -I -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' .github/workflows/CI-pr.yml` exits 0.

- [ ] **Step 4: Commit**: `ci: run the re-hash tests without key_custodian and with kv`.

### Task 4: Dependency check

**Couvre:** D1, D5

**Files:**
- Create: `deny.toml`, `.github/workflows/dependencies.yml`

- [ ] **Step 1: Write `deny.toml`**:
  - `[graph] all-features = true`.
  - `[advisories]`: `unmaintained = "workspace"`, `unsound = "workspace"`, `yanked = "warn"`,
    `ignore-expiry = "2027-02-21"`, `ignore = []` for now; a comment explains the exception policy
    (owner's decision of 2026-11-23, expiry date).
  - `[licenses]`: `allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "Unicode-3.0", "ISC",
    "BSD-2-Clause", "BSD-3-Clause", "Zlib", "CC0-1.0", "MPL-2.0", "OpenSSL"]`,
    `confidence-threshold = 0.93`.
  - `[sources]`: `unknown-registry = "deny"`, `unknown-git = "deny"`, `required-git-spec = "tag"`,
    `allow-registry = ["https://github.com/rust-lang/crates.io-index"]`,
    `allow-git = ["https://github.com/juspay/hyperswitch", "https://github.com/juspay/framework-libs-rs"]`.
  - `bans` not configured and not run.

- [ ] **Step 2: Write `.github/workflows/dependencies.yml`**, name "Dependencies": triggers
  `pull_request`, `push` on `main`, `schedule` weekly (`cron: "17 5 * * 1"`), `workflow_dispatch`;
  top-level `permissions: contents: read`; one job "Known vulnerabilities, licenses and sources":
  checkout, rust-toolchain stable, install-action `tool: cargo-deny@0.22.0` with `checksum: true`, run
  `cargo deny --locked check advisories licenses sources`.

- [ ] **Step 3: See it fail on the current code (CI).** After the owner's yes for the push and the draft
  PR (Task 7 step 1), the job runs with `ignore = []`. Expected: FAIL with `vulnerability` diagnostics
  for crates of the original code. Keep the run link and the identifiers it lists.

- [ ] **Step 4: Add the exceptions** from that output only: one `{ id = "...", reason = "present in the
  original code at a8ee711, not fixed by this fork" }` per identifier. If the license check reports the
  root crate as unlicensed, add a `[[licenses.clarify]]` for `hyperswitch_card_vault` with expression
  `Apache-2.0` and the `LICENSE` hash the tool prints. Push (covered by the yes of Task 7). Expected: PASS.
  If the absolute `ignore-expiry` date is refused by the parser, use a per-entry `expiry` date and say so.

- [ ] **Step 5: Commit** each of steps 1-2 and step 4 separately: `ci: check dependencies with cargo-deny`,
  `ci: record the known vulnerabilities of the original code until 2027-02-21`.

### Task 5: Scorecard

**Couvre:** D2, D5

**Files:**
- Create: `.github/workflows/scorecard.yml`

- [ ] **Step 1: Write the workflow**, name "Scorecard": triggers `pull_request`, `push` on `main`, weekly
  `schedule` (`cron: "29 5 * * 1"`), `workflow_dispatch`; top-level `permissions: {}`; job "Scorecard
  analysis" with `permissions: contents: read, actions: read`; steps: checkout
  (`persist-credentials: false`), scorecard-action with `results_file: results.json`,
  `results_format: json`, `publish_results: false`; upload-artifact (`name: scorecard-results`,
  `retention-days: 5`); a bash step that writes `jq -r '.checks[] | "| \(.name) | \(.score) |"'` to
  `$GITHUB_STEP_SUMMARY` and fails if `jq '.checks | length' results.json` is 0.
- [ ] **Step 2: Breakage (CI, during the PR)**: on the breakage branch (Task 7), set `results_file` of the
  summary step to a missing name; expected FAIL in the summary step. Revert is the branch deletion.
- [ ] **Step 3: Fallback if the action refuses this fork**: replace the action step by the
  `ghcr.io/ossf/scorecard` image pinned by digest, `--repo=github.com/${{ github.repository }}
  --format=json --show-details`, `GITHUB_AUTH_TOKEN: ${{ github.token }}`; same summary step.
- [ ] **Step 4: Commit**: `ci: run OpenSSF Scorecard without publishing its results`.

### Task 6: Threat table, tokenization page, README

**Couvre:** D6

**Files:**
- Modify: `docs/threat-model.md`, `docs/tokenization.md`, `README.md`

- [ ] **Step 1: Table.**
  - T28: add `rehash_refuses_to_run_with_kv` and the note that the re-hash tests also run without
    `key_custodian` (CI job name); stays `proven`.
  - T31 (`not tested`): a dependency with a known vulnerability, an unapproved license or an
    unapproved source enters the build; control `deny.toml` lines of each section and the job line of
    `.github/workflows/dependencies.yml`; evidence: the CI job, seen failing once on a breakage branch
    (run linked in the PR), no test in the repository repeats it.
  - T32 (`open`): known vulnerabilities of the original code, tolerated until 2027-02-21; evidence: the
    `deny.toml` lines that list them.
  - T33 (`open`): crates taken from git are not covered by the RustSec database; evidence: the
    `deny.toml` comment lines that say it.
  - T34 (`open`): existing workflows use moving tags (`@master`, `@v7`); evidence: their
    `CI-pr.yml` lines; Scorecard reports it.
  - Update "How to check it yourself" (the run without custodians, the `kv` test).
  - Fix every moved `file:line`.
- [ ] **Step 2: `docs/tokenization.md`**: remove the `kv` refusal and the run without `key_custodian`
  from the "Not tested" list, cite their tests; write the `kv` limit (two of six refusals on the path).
- [ ] **Step 3: `README.md`**: a "CI hygiene" entry listing every file of `git diff --name-only main`
  except `README.md`, with one line each.
- [ ] **Step 4: Checks**: `scripts/check-threat-model.sh` → `OK: 34 rows (14 proven, 7 not tested, 13 open)`
  (counts to be confirmed); `grep -c -i -E 'GHSA|advisories' docs/threat-model.md README.md docs/tokenization.md`
  → 0 each; the forbidden-wording search of the project `CLAUDE.md` on `git diff main` added lines → 0.
- [ ] **Step 5: Commit**: `docs: describe the dependency check, Scorecard and the re-hash feature paths`.

### Task 7: Push, PR, breakage branch, review

**Couvre:** D1, D2, D7

- [ ] **Step 1: Ask the owner** (DOING / EXPECT / IF WRONG): push `chore/hygiene` and open a draft PR
  on the fork, base `main`, `-R antoinevoinchet-spec/hyperswitch-card-vault`; later pushes to this
  branch during the PR covered by the same yes. Then Task 4 steps 3-4.
- [ ] **Step 2: Ask the owner**: create `chore/hygiene-breakage` from `chore/hygiene` with one commit:
  `Cargo.toml` adds `smallvec = "=0.6.13"` (a crates.io release with a known vulnerability) and a git
  dependency on a repository outside `allow-git`; `Cargo.lock` regenerated; `deny.toml` drops `"Zlib"`
  from `allow`; the Scorecard summary step reads a missing file. Push and open a draft PR with base
  `chore/hygiene` (never merged). Expected: "Dependencies" fails with `vulnerability`,
  `source-not-allowed` and `rejected` diagnostics; "Scorecard" fails in the summary step. Keep links and
  output. Then ask to close the PR and delete the branch.
- [ ] **Step 3: Final local checks**: `cargo test -j 4` (≥ 44 passed, exit 0); end-to-end with
  custodians (20 passed, 0 failed); `make demo` with `DEMO_DATABASE_URL` → `DEMO OK`; fmt and clippy as
  Task 1 step 5; `git diff --name-only main -- src demo config migrations Cargo.toml Cargo.lock CLAUDE.md .typos.toml LICENSE scripts`
  prints nothing; `git status --porcelain` empty.
- [ ] **Step 4: Review**: a fresh `opus` subagent and `second-avis --reserve 50` in parallel, each given
  the owner's request verbatim, the diff and the table, checking that each added test or job fails when
  its control is removed. Lines of context naming `custodian_key1`/`custodian_key2` are removed from the
  diff sent to `second-avis`.
- [ ] **Step 5: PR ready**: show the owner the verified title and body; mark ready on yes;
  `gh pr checks <n> -R antoinevoinchet-spec/hyperswitch-card-vault` all `pass`;
  `gh pr list -R juspay/hyperswitch-card-vault --author antoinevoinchet-spec --state all` empty.
  Merge only on the owner's yes.
