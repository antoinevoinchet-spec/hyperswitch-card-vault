# CI hygiene (ticket H1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Check the Rust dependencies and run OpenSSF Scorecard in CI, and prove in CI the two re-hash
paths that are only compiled today (refusal under `kv`, run without `key_custodian`).

**Architecture:** Two new workflows (`dependencies.yml`, `scorecard.yml`) and two new jobs in
`CI-pr.yml`; `deny.toml` at the root; `tests/vault_e2e.rs` made to compile with and without
`key_custodian`, plus one `kv` test. No change to `src/`, `Cargo.toml` or `Cargo.lock` on
`chore/hygiene`.

**Tech Stack:** GitHub Actions, cargo-deny 0.22.0, ossf/scorecard-action v2.5.0, Rust tests with
diesel against a throwaway PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-11-23-hygiene-ci-design.md`

## Global Constraints

- Branch: `git branch --show-current` prints `chore/hygiene` before every commit (created from `main`
  at `a8ee711`; `git merge-base --is-ancestor a8ee711 chore/hygiene` exits 0). `git status` before
  every commit; only the task's files are added.
- Allowed files: `.github/workflows/` (new jobs or files; existing jobs unchanged), `deny.toml`,
  `tests/`, `docs/threat-model.md`, `docs/tokenization.md`, `README.md`, `docs/superpowers/`.
  Check: `git diff --name-only main | grep -v -E '^(\.github/workflows/|deny\.toml$|tests/|docs/threat-model\.md$|docs/tokenization\.md$|README\.md$|docs/superpowers/)'`
  prints nothing.
- Every `cargo` command is prefixed by `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"` and uses `-j 4`.
- Every `gh pr` or `gh issue` command passes `-R antoinevoinchet-spec/hyperswitch-card-vault`. The one
  read of `juspay/*` is the owner's own final check (`gh pr list -R juspay/hyperswitch-card-vault --author antoinevoinchet-spec --state all`).
- Repository text in English; no word `typos` reads as a misspelling. Forbidden wording: the pattern
  file `$SCRATCH/forbidden.txt` (7 patterns, kept outside the repository, see the project `CLAUDE.md`,
  its rule on what may be said about the project; checked on 2026-11-23 to catch a test sentence, exit 0).
  `test -s "$SCRATCH/forbidden.txt"` first (a missing file would make `grep -f` exit 2, not 1); then
  `git diff main | grep '^+' | grep -i -f "$SCRATCH/forbidden.txt"`, the same on
  `git log main..HEAD --format=%B` and on the PR text, must exit 1 (no match); a match is accepted only
  in a sentence that denies the claim, and is quoted in the report.
- Pinning check for every new or changed workflow file:
  `grep -n 'uses:' <file> | grep -v -E '@[0-9a-f]{40} # '` prints only the lines of existing jobs
  (for `CI-pr.yml`, compare with `main`); seen failing once on a temporary `@v7` in Task 3 step 3.
- `docs/threat-model.md`, `docs/tokenization.md` and `README.md` never contain `GHSA` or `advisories`:
  write "known vulnerabilities", "RustSec database", and cite `deny.toml` by line numbers, never by
  the name of its section, nor the `cargo deny` command line.
- No `.env*` file, key value or `master_key` is read, printed or committed.
- `SCRATCH=/private/tmp/claude-501/-Users-antoinevoinchet/9481ae07-b10d-4898-9e67-3d434bf1dd22/scratchpad/h1`;
  every deletion uses `"${VAR:?}"`.
- Every action added is pinned by full commit SHA with its tag in a comment (checked on 2026-11-23
  with `git ls-remote`, peeled tags):
  - `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`
  - `actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2`
  - `ossf/scorecard-action@fa7117db83c52d787ae5a89f350999701505d78e # v2.5.0` (its option check, read
    at this tag, refuses only an empty token and a non-default branch outside `pull_request`)
  - `dtolnay/rust-toolchain@df2a88e9fe4098bad09cb42c3dec7187f15861fc # master on 2026-11-15`
  - `Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1`
  - `rui314/setup-mold@339e96b4ff1f3bd865856ba4cbbe8818a7acb038 # v1`
  - `taiki-e/install-action@fe3acb53a98b62c772db35de75ce0e4595e7ca8c # v2.90.8` (first version that
    knows cargo-deny 0.22.0; 0.21.0 or later is needed for `expiry`)
- Exceptions for known vulnerabilities of the original code each carry `expiry = "2027-02-21"`
  (owner's Q1 = A). A duration such as `P90D` counts from each entry's publication: not used.
- Stops for the owner's yes (DOING / EXPECT / IF WRONG first): each deliberate breakage in `src/`
  (Task 1 step 4, Task 2 step 3); installing a tool; editing a file outside the allowed list (the
  breakage branch); **each push** (commits are grouped, one push per stop; the first push of a branch
  and the PR it opens form one stop, as the owner's point 4 defines it; marking the PR ready goes with
  the push before it); each branch deletion (closing its PR goes with it); each merge; widening the allowed licenses, registries or git
  sources, or loosening `required-git-spec`, beyond Task 4 step 1; any GitHub setting.
- Local PostgreSQL: throwaway cluster, TCP only, port 54330 (Task 1 step 1), stopped and deleted at
  the end of each task that starts it.

## Review Focus

- A test filter that matches no test makes a green job: each new CI job checks the number of tests
  run, and that guard is seen failing (Task 3 step 3).
- A refusal test that passes for another reason (bad configuration, database unreachable): the `kv`
  test checks the error kind and the audit row `rehash_run` = `failure`.
- Dead code without `key_custodian` breaks `RUSTFLAGS="-D warnings"`: compile with default features
  and with `kv` alone (Task 1 step 5, Task 2 step 4); the existing `cargo hack` and nextest jobs are
  checked green in Task 8.
- An expired exception must fail again: seen on the breakage branch (Task 8 step 4).
- The Scorecard action may refuse a fork: Task 5 has a fallback that does not publish either.

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
  `unlocked_master_key(&Keys) -> Vec<u8>` returns the raw key in both modes; `unlock(&Vault, &Keys)` is
  a no-op without `key_custodian`.

- [ ] **Step 1: Start a throwaway PostgreSQL and record the baseline.**
  `PG=/opt/homebrew/opt/postgresql@14/bin; P="$SCRATCH/pg"; $PG/initdb -D "$P" -U postgres -A trust >/dev/null && $PG/pg_ctl -D "$P" -o "-p 54330 -c unix_socket_directories='' -c listen_addresses=127.0.0.1" -l "$P.log" start`.
  Run `VAULT_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:54330/postgres VAULT_TEST_REQUIRE_DB=1 cargo test -j 4 --test vault_e2e rehash_`
  (no feature). Expected: `running 0 tests` (the file is compiled out today).

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

- [ ] **Step 3: Run the re-hash tests without `key_custodian`.** Same command as step 1. Expected:
  `test result: ok. 11 passed; 0 failed` (12 re-hash tests minus `rehash_refuses_wrong_custodian_keys`).

- [ ] **Step 4: Deliberate breakage (stop for the owner's yes), then revert.** In `src/bin/utils.rs`,
  comment out the `fetch_raw_secrets` call (lines 217-220), so the master key is used as its hex text
  instead of its bytes. Run `... cargo test -j 4 --test vault_e2e rehash_moves_v1_rows_to_scoped_hashes`.
  Expected: FAIL with `does not cite its v2 hash` (output kept for the report). Revert with
  `git checkout -- src/bin/utils.rs`; `git diff --name-only -- src` prints nothing.

- [ ] **Step 5: No regression and no dead code.**
  - With custodians: `... cargo test -j 4 --features key_custodian --test vault_e2e`. Expected:
    `20 passed; 0 failed`.
  - `RUSTFLAGS="-D warnings" cargo clippy -j 4 --all-targets` (default features) and
    `cargo clippy -j 4 --all-features --all-targets`: no warning beyond those of `main` (the known
    `digest`, `gethostname` and `num-bigint-dig` notices).
  - `cargo fmt --all --check` (stable; the CI's nightly check is seen in Task 8): exit 0.
  - Stop and delete the cluster: `$PG/pg_ctl -D "$P" stop && rm -rf "${P:?}" "${P:?}.log"`.

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
  - `output.contains("rehash failed: RetrieveDataFailed")` (`find_locker_batch` refuses with
    `VaultDBError::DBFilterError`, mapped to `RetrieveDataFailed` in `src/error/transforms.rs:200`);
  - `db.snapshot() == before` ("a row changed under kv");
  - the `rehash_` audit rows are exactly `[("rehash_run", "failure")]` (the job itself ran and
    refused; no clean-up entry).

- [ ] **Step 2: Run it** with a throwaway cluster (Task 1 step 1):
  `... cargo test -j 4 --features key_custodian,kv --test vault_e2e rehash_refuses_to_run_with_kv`.
  Expected: `1 passed`.

- [ ] **Step 3: Deliberate breakage (stop for the owner's yes), then revert.** In `src/storage/db.rs`
  lines 309-614, for the five re-hash refusals, `DeletedHash` and the two imports of lines 2 and 5, replace each refusal's
  `#[cfg(feature = "kv")]` by `#[cfg(any())]` and the following `#[cfg(not(feature = "kv"))]` by
  `#[cfg(all())]`, so the PostgreSQL code runs under `kv`. Run step 2 again. Expected: FAIL on
  `rehash must refuse to run under kv` (exit code 0, the orphan row deleted). Revert with
  `git checkout -- src/storage/db.rs`; `git diff --name-only -- src` prints nothing.

- [ ] **Step 4: Run the suites again**: Task 1 step 5, plus
  `RUSTFLAGS="-D warnings" cargo clippy -j 4 --features kv --all-targets` (`kv` without `key_custodian`).

- [ ] **Step 5: Commit** `tests/vault_e2e.rs`: `test: prove that utils rehash refuses to run with the kv feature`.

### Task 3: CI jobs for the two re-hash paths

**Couvre:** D3, D4, D5

**Files:**
- Modify: `.github/workflows/CI-pr.yml` (append two jobs after `integration-db`; existing jobs untouched)

- [ ] **Step 1: Add job `rehash-without-custodian`**, name "Re-hash without the key_custodian feature":
  `permissions: contents: read`; same PostgreSQL service block as `integration-db`; steps checkout,
  setup-mold, rust-toolchain (`stable 2 weeks ago`), rust-cache, all pinned as in Global Constraints;
  run (bash) `cargo test --test vault_e2e rehash_ 2>&1 | tee test-output.txt` then
  `grep -q 'test result: ok. 11 passed' test-output.txt || { echo "::error::expected 11 re-hash tests"; exit 1; }`,
  with env `VAULT_TEST_DATABASE_URL: postgres://postgres@localhost:5432/postgres` and
  `VAULT_TEST_REQUIRE_DB: "1"`.

- [ ] **Step 2: Add job `rehash-kv`**, name "Re-hash refusal with the kv feature": same shape, run
  `cargo test --features key_custodian,kv --test vault_e2e rehash_refuses_to_run_with_kv -- --exact`,
  guard `grep -q 'test result: ok. 1 passed' test-output.txt || { echo "::error::expected 1 kv test"; exit 1; }`.

- [ ] **Step 3: Check the file and the guard.**
  - `git diff main -- .github/workflows/CI-pr.yml` shows only added lines after the last existing job.
  - `python3 -I -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' .github/workflows/CI-pr.yml` exits 0.
  - Guards seen failing: run each job's shell lines locally with the filter `rehash_zzz` (no test
    matches): expected `expected 11 re-hash tests` and `expected 1 kv test`, exit 1 (outputs kept).
    The counts are fixed on purpose: adding a `rehash_` test means updating the guard (comment in the
    workflow says so).
  - Pinning check (Global Constraints) on `CI-pr.yml`; once with a temporary `@v7` on a new step:
    the line is printed; reverted.

- [ ] **Step 4: Commit**: `ci: run the re-hash tests without key_custodian and with kv`.

### Task 4: Dependency check (files)

**Couvre:** D1, D5

**Files:**
- Create: `deny.toml`, `.github/workflows/dependencies.yml`

- [ ] **Step 1: Write `deny.toml`**:
  - `[graph] all-features = true`.
  - Vulnerability section: `unmaintained = "workspace"`, `unsound = "workspace"`, `yanked = "warn"`
    (the tool's default), `ignore = []` for now; a comment states the policy (owner's decision of
    2026-11-23: entries present in the original code at `a8ee711` are listed with a reason and expire
    on 2027-02-21) and that crates taken from git are not covered by the RustSec database.
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
  checkout (`persist-credentials: false`), rust-toolchain stable, install-action
  `tool: cargo-deny@0.22.0` with `checksum: true`, run `cargo deny --locked check advisories licenses sources`.
  YAML parses (Task 3 step 3 command).

- [ ] **Step 3: Commit**: `ci: check dependencies with cargo-deny`.

### Task 5: Scorecard (file)

**Couvre:** D2, D5

**Files:**
- Create: `.github/workflows/scorecard.yml`

- [ ] **Step 1: Write the workflow**, name "Scorecard": triggers `pull_request`, `push` on `main`,
  weekly `schedule` (`cron: "29 5 * * 1"`), `workflow_dispatch`; top-level `permissions: {}`; job
  "Scorecard analysis" with `permissions: contents: read, actions: read`; steps: checkout
  (`persist-credentials: false`); scorecard-action with `results_file: results.json`,
  `results_format: json`, `publish_results: false`; upload-artifact (`name: scorecard-results`,
  `path: results.json`, `retention-days: 5`); a bash step (env `RESULTS: results.json`) that writes
  `jq -r '.checks[] | "| \(.name) | \(.score) |"' "$RESULTS"` to `$GITHUB_STEP_SUMMARY` and fails if
  `jq '.checks | length' "$RESULTS"` is 0 or the file is missing.
- [ ] **Step 2: Checks**: `grep -n 'publish_results: false' .github/workflows/scorecard.yml` prints one
  line; `grep -c 'id-token' .github/workflows/scorecard.yml` prints 0; YAML parses; pinning check
  (Global Constraints) on this file and on `dependencies.yml`. The summary step's shell lines, run
  locally on `echo '{"checks":[]}' > "$SCRATCH/empty.json"` and on a missing file, exit 1 both times.
- [ ] **Step 3: Commit**: `ci: run OpenSSF Scorecard without publishing its results`.
- [ ] **Fallback, only if the action refuses this fork in Task 7**: replace the action step by the
  `ghcr.io/ossf/scorecard` image pinned by digest, arguments `--repo=github.com/${{ github.repository }}
  --format=json --show-details`, `GITHUB_AUTH_TOKEN: ${{ github.token }}`, output redirected to
  `results.json`; the command line has no publication option, so nothing is sent to the Scorecard
  API (checked: `grep -c -i 'publish' .github/workflows/scorecard.yml` prints 0). Same summary step.

### Task 6: Threat table, tokenization page, README (first version)

**Couvre:** D6

**Files:**
- Modify: `docs/threat-model.md`, `docs/tokenization.md`, `README.md`

- [ ] **Step 1: Table.**
  - T28: add `rehash_refuses_to_run_with_kv`, and the note that `rehash_moves_v1_rows_to_scoped_hashes`
    and the other re-hash tests also run without `key_custodian` (CI job "Re-hash without the
    key_custodian feature"); write that under `kv` only
    two of the job's five refusals are on the tested path (no card stored), the other three being
    compiled only. Stays `proven` for what it claims.
  - T31 (`not tested`): a dependency with a known vulnerability, an unapproved license or an unapproved
    source enters the build; control: the `deny.toml` lines of each rule and the job line of
    `.github/workflows/dependencies.yml`; evidence: the CI job "Dependencies"; "breakage run to be
    recorded" until Task 8 step 5; no test in the repository repeats it.
  - T32 (`open`): known vulnerabilities of the original code, tolerated until 2027-02-21; evidence: the
    `deny.toml` policy comment lines (written in Task 4); the list lines are added in Task 7 step 3.
  - T33 (`open`): crates taken from git are not covered by the RustSec database; evidence: the
    `deny.toml` comment lines that say it.
  - T34 (`open`): existing workflows use moving tags (`@master`, `@v7`); evidence: their `CI-pr.yml`
    lines; Scorecard reports it.
  - T22 and T30 keep their status and text; only their moved `file:line` references may change.
  - Update "How to check it yourself" (the run without custodians, the `kv` test). Fix every moved
    `file:line`.
- [ ] **Step 2: `docs/tokenization.md`**: remove the `kv` refusal and the run without `key_custodian`
  from the "Not tested" list, cite their tests; write the `kv` limit (two of five refusals on the path).
- [ ] **Step 3: `README.md`**: a "CI hygiene" entry under "Changes from the original" listing every file
  of `git diff --name-only main` except `README.md`, one line each.
- [ ] **Step 4: Checks**:
  - `scripts/check-threat-model.sh` exits 0; report its `OK: <n> rows (...)` line.
  - `grep -c -i -E 'GHSA|advisories' docs/threat-model.md README.md docs/tokenization.md` → 0 each.
  - `grep -c -i 'scorecard.dev/projects\|api.scorecard.dev' README.md` → 0.
  - README coverage, on the "Changes from the original" section only:
    `sed -n '/^### Changes from the original/,/^## /p' README.md > "$SCRATCH/changes.md"; for f in $(git diff --name-only main); do [ "$f" = README.md ] || grep -q -F -- "$f" "$SCRATCH/changes.md" || echo "MISSING $f"; done`
    prints nothing; seen once printing `MISSING deny.toml` on a copy of the section without that line.
  - `git diff main -- docs/threat-model.md | grep -E '^[-+]\| T(22|30) '`: any line shown differs only
    by a `file:line` reference.
  - Forbidden wording (Global Constraints) → nothing.
- [ ] **Step 5: Commit**: `docs: describe the dependency check, Scorecard and the re-hash feature paths`.

### Task 7: First push and draft PR, then the known vulnerabilities

**Couvre:** D1, D2, D3, D4

- [ ] **Step 1: Stop for the owner's yes**: push `chore/hygiene` and open a draft PR, base `main`,
  `-R antoinevoinchet-spec/hyperswitch-card-vault`, title and body shown first.
- [ ] **Step 2: Read the run.** Expected: "Dependencies" fails with `vulnerability` diagnostics for
  crates of the original code (`ignore` is empty), plus possibly unmaintained or unsound notices on
  direct dependencies, which are listed the same way in step 3; the two re-hash jobs pass with
  `11 passed` and `1 passed`; "Scorecard" passes with a results artifact. Record each run link. If
  the license or source checks reject anything, stop and ask before changing `allow`,
  `allow-registry` or `allow-git` (the root crate's `LICENSE` file, if reported unlicensed, gets a
  `[[licenses.clarify]]` with expression `Apache-2.0` and the hash the tool prints; that is not a
  widening). If Scorecard refuses the fork, apply the Task 5 fallback.
- [ ] **Step 3: Add the exceptions** from that output only: one
  `{ id = "...", reason = "present in the original code at a8ee711, not fixed by this fork", expiry = "2027-02-21" }`
  per identifier. If the date form is refused by the parser, the job says so: stop and report.
  Update T32's line references. Commit: `ci: record the known vulnerabilities of the original code until 2027-02-21`.
- [ ] **Step 4: Stop for the owner's yes**: push. Expected: every job of the PR passes.

### Task 8: Breakage branch, review, ready

**Couvre:** D1, D2, D5, D6, D7

- [ ] **Step 1: Stop for the owner's yes** (outside the allowed files): create `chore/hygiene-breakage`
  from `chore/hygiene` with one commit: `Cargo.toml` adds `smallvec = "=0.6.13"` (crates.io release
  with a known buffer overflow, fixed in 0.6.14) and `smallvec-git = { package = "smallvec", git =
  "https://github.com/servo/rust-smallvec", tag = "v1.13.2" }` (a source outside `allow-git`);
  `Cargo.lock` updated by `cargo update -p smallvec` only (no `cargo generate-lockfile`, which would
  resolve every crate again), then `git diff Cargo.lock` shows only the added packages; `deny.toml` drops `"Zlib"`
  from `allow` (`foldhash` and `zlib-rs` are Zlib only, so the license check must fail) and sets one
  exception's `expiry` to `2026-11-01`; `scorecard.yml` sets `RESULTS: missing.json` in the summary
  step; the guard of `rehash-without-custodian` uses the filter `rehash_zzz`.
- [ ] **Step 2: Stop for the owner's yes**: push it and open a draft PR with base `chore/hygiene`
  (never merged), `-R antoinevoinchet-spec/hyperswitch-card-vault`. Expected: "Dependencies" fails with
  `vulnerability` (smallvec), `source-not-allowed` (the git URL), `rejected` (a Zlib crate) and
  `advisory-ignore-expired`; "Scorecard" fails in the summary step; the re-hash job fails on its
  guard. Keep the links and the failing lines.
- [ ] **Step 3: Stop for the owner's yes**: close that PR and delete the branch, local and remote
  (`gh pr close <n> -R antoinevoinchet-spec/hyperswitch-card-vault`, `git push origin --delete chore/hygiene-breakage`,
  `git branch -D chore/hygiene-breakage`).
- [ ] **Step 4: Record the breakage** in T31 (run link) and finalise `README.md`; Task 6 step 4 checks
  again. Commit: `docs: record the dependency check's breakage run`.
- [ ] **Step 5: Final local checks**: `cargo test -j 4` (≥ 44 passed, exit 0); end-to-end with
  custodians (20 passed, 0 failed); `make demo` with `DEMO_DATABASE_URL` → `DEMO OK`; fmt and clippy as
  Task 1 step 5; the allowed-files check of Global Constraints; `git diff --name-only main -- src demo config migrations Cargo.toml Cargo.lock CLAUDE.md .typos.toml LICENSE scripts`
  prints nothing; `git status --porcelain` empty.
- [ ] **Step 6: Review**: a fresh `opus` subagent and `second-avis --reserve 50` in parallel, each given
  the owner's request verbatim, the diff and the table, checking that each added test or job fails
  when its control is removed. Lines of context naming `custodian_key1`/`custodian_key2` are removed
  from the diff sent to `second-avis`. Fix what changes the result; re-run Task 6 step 4 and step 5.
- [ ] **Step 7: Stop for the owner's yes**: push the last commits, mark the PR ready with the verified
  title and body. `gh pr checks <n> -R antoinevoinchet-spec/hyperswitch-card-vault`: every job `pass`
  (existing jobs included: nextest, cargo hack, nightly fmt, typos), or the failure reported as is;
  `gh pr list -R juspay/hyperswitch-card-vault --author antoinevoinchet-spec --state all` prints
  nothing. Merge only on the owner's yes.
