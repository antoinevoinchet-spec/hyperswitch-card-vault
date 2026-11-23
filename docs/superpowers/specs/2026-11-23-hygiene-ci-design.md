# Design: CI hygiene (ticket H1)

Date: 2026-11-23 (UTC). Branch: `chore/hygiene`, from `main` at `a8ee711`.

## Intent

A dependency with a known vulnerability would affect all the code, the original as well as the fork's
changes, and nothing checks for it today. Two paths of the re-hash job (`utils rehash`, ticket R1) are
only compiled: its refusal with the `kv` feature, and a run without the `key_custodian` feature.
`docs/tokenization.md` lists them as not tested. The owner does not read Rust: every effect below is
proven by a test, a CI job or a command that fails when the control it describes is removed.

## Requirements

- D1. A CI check of the Rust dependencies: known vulnerabilities (RustSec database), licenses, and
  the sources crates come from. Verifiable by: the job passes on the PR, and fails on a breakage
  branch that adds a crate with a known vulnerability or from an unapproved source (output shown).
- D2. OpenSSF Scorecard in CI, without a public badge and without publishing its results. Verifiable
  by: a run link with its results artifact; `publish_results: false` in the workflow; the README
  check `grep -c -i 'scorecard.dev/projects\|api.scorecard.dev' README.md` returns 0.
- D3. A test, run in CI, showing that `utils rehash` built with `kv` refuses to run and changes no
  row. Verifiable by: the test passes in its CI job, and fails locally when the refusal is removed.
- D4. A test, run in CI, showing that a full re-hash built without `key_custodian` gives the same
  result as with it (every row cites its expected hash, a new add returns `duplicated`). Verifiable
  by: the test passes in its CI job, and fails locally when reading the master key is broken.
- D5. Every action added is pinned as decided below, with the narrowest permissions that work.
  Verifiable by: reading each new workflow file (`uses:` lines and `permissions:` blocks).
- D6. The threat model table and `docs/tokenization.md` describe the state after this ticket.
  Verifiable by: `scripts/check-threat-model.sh` returns 0; `grep -c -i -E 'GHSA|advisories'` returns
  0 on the three documents; `README.md` lists every file of `git diff --name-only main`.
- D7. Nothing outside the allowed files changes. Verifiable by: `git diff --name-only main -- src demo
  config migrations Cargo.toml Cargo.lock CLAUDE.md .typos.toml LICENSE scripts` prints nothing;
  `cargo test -j 4` passes (at least 44 tests), the end-to-end tests report 0 failed (at least 20),
  `make demo` prints `DEMO OK`.

## Non-goals

- No fix of a dependency of the original code, no update of `Cargo.toml` or `Cargo.lock`.
- No change to the existing CI jobs, to `src/`, `demo/`, `migrations/`, `config/`, the check script,
  or the repository settings on GitHub.
- No mutation testing (postponed), no `tacet`, no key rotation (T22 is the next ticket), T30 stays open.

## Anti-goals

- A green job that proves nothing: each check is seen failing, for the reason it describes, on a
  deliberate breakage that is then reverted.
- A table row that claims more than the evidence: what this ticket does not settle stays `open`.

## What the code does today (read on 2026-11-23)

- Dependencies (`cargo metadata --all-features --locked`): 755 crates from crates.io, 12 from two git
  repositories (`github.com/juspay/hyperswitch` by tag, `github.com/juspay/framework-libs-rs` by
  revision), all licensed Apache-2.0. Licenses seen: MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception,
  Unicode-3.0, ISC, BSD-2-Clause, BSD-3-Clause, Zlib, CC0-1.0 (`tiny-keccak`), MPL-2.0
  (`webpki-roots`), OpenSSL (`aws-lc-sys`); the others appear only as an alternative to MIT or
  Apache-2.0. The root crate declares no license in `Cargo.toml`; its `LICENSE` file is Apache-2.0.
- Known vulnerabilities (OSV query of the locked crate versions, 2026-11-23, to be confirmed by the
  tool itself in CI): 11 crates of the default build graph and 13 more under `--all-features` match a
  RustSec vulnerability entry (among them `rustls`, `rustls-webpki`, `h2`, `openssl`, `aws-lc-sys`,
  `url`, `zstd`), plus unmaintained and unsound notices. A blocking check therefore fails on the
  current `main`, because of the original code.
- `utils rehash` under `kv`: the binary passes no Redis (`src/bin/utils.rs:261-262`); the job's first
  storage call, `find_locker_batch`, returns an error under `kv` before any query
  (`src/storage/db.rs:314-318`), as do four other primitives of the job. A PostgreSQL alone is
  enough to run it. The vault itself built with `kv` expects a Redis at start-up
  (`src/tenant.rs:58-71`), so the `kv` test cannot seed cards through the vault.
- Without `key_custodian`, the vault and `utils` take the master key from the configuration, hex
  decoded by `fetch_raw_secrets` (`src/config.rs:299-312`). The test helper `run_rehash` already copes
  with a command that does not read its input (`tests/vault_e2e.rs:838-843`). `tests/vault_e2e.rs` is
  compiled only with `key_custodian` (line 7).
- Scorecard: the repository is a GitHub fork (`isFork: true`). The action's README says a fork is "not
  supported" and that `pull_request` is "experimental"; its option check (`options/options.go`, read at tags `v2.5.0`, the one pinned, and
  `v2.6.0`) only refuses an empty token and a non-default branch outside `pull_request`.

## Approaches considered

### Dependencies

1. **cargo-deny** (chosen): one tool and one `deny.toml` for vulnerabilities, licenses and sources.
   Since 0.21.0, an ignored entry can carry a `reason` and an `expiry` date, after which it fails
   again.
2. cargo-audit: vulnerabilities only; licenses and sources would need a second tool.
3. Both: duplicates the vulnerability check for no gain.

### Testing the two re-hash paths

1. **Make `tests/vault_e2e.rs` compile with and without `key_custodian`** (chosen): the few helpers
   that depend on the feature (`Keys::generate`, `unlock`, `unlocked_master_key`) get a variant
   without custodians, the custodian-only tests and helpers are marked `key_custodian`, and the
   existing re-hash tests run unchanged in both modes. The same assertions then prove "same result".
   One new test, compiled only with `kv`, covers the refusal.
2. A new test file without `key_custodian`: needs a copy of about 250 lines of helpers, or moving them
   to a shared module (a refactor of a validated file).
3. Moving every helper to `tests/common/mod.rs`: cleanest long-term, but rewrites most of the file
   for no behaviour change.

### Scorecard

1. **`ossf/scorecard-action`, `publish_results: false`** (chosen), JSON results kept as a run artifact
   and printed in the job summary. If the action refuses to run on this fork, fall back to approach 2.
2. The Scorecard command-line image, pinned by digest, with the same token: works on forks, more
   lines to maintain.

## Design

### Dependency check (D1, D5)

- New workflow `.github/workflows/dependencies.yml`, triggered on pull requests, on pushes to `main`,
  weekly (`schedule`) and by hand (`workflow_dispatch`), because new RustSec entries appear without any
  change to the code. Permissions: `contents: read` only.
- One job: checkout, stable Rust (same action as the existing jobs), `cargo-deny` 0.22.0 installed by
  `taiki-e/install-action` with checksum verification (the pattern the CI already uses for
  `cargo-hack` and `cargo-nextest`), then `cargo deny --all-features check advisories licenses
  sources`. The `bans` check is not enabled: it was not asked for.
- `deny.toml` at the root:
  - `[advisories]`: every vulnerability fails; unmaintained and unsound notices keep the tool's
    default (`workspace`: they fail only for a direct dependency). The handling of entries already
    present in the original code is decision **Q1** below.
  - `[licenses]`: an explicit allow list of the licenses seen above; any other license fails. The
    root crate is clarified as Apache-2.0 from its `LICENSE` file (hash pinned), without touching
    `Cargo.toml`.
  - `[sources]`: crates.io only as registry (`unknown-registry = "deny"`); git sources limited to the
    two exact URLs above (`unknown-git = "deny"`), each pinned at least by a tag
    (`required-git-spec = "tag"`).
- Known limit, kept `open` in the table: the RustSec database describes crates.io releases, so the
  12 crates taken from git are checked for their source and license, not for vulnerabilities.

### Scorecard (D2, D5)

- New workflow `.github/workflows/scorecard.yml`, triggered on pull requests (to see it run on the
  PR of this ticket), on pushes to `main`, weekly and by hand.
- Workflow permissions `{}`; job permissions `contents: read`, `actions: read`. No `id-token: write`
  (only needed to publish), no `security-events: write` (no upload to the Security tab).
- `publish_results: false`: nothing is sent to the Scorecard API, so no badge can exist. Results in
  JSON, uploaded as an artifact kept 5 days (readable by anyone, as the run itself), and a step that
  writes each check's score to the job summary and fails if the file holds no check (the proof that
  it produced results).
- Scorecard is a report, not a gate: it will score the existing jobs low for their moving tags
  (`@master`, `@v7`), which this ticket does not change. That finding goes to the table as `open`.

### Pinning (D5)

- Every action added by this ticket is pinned by its full commit SHA, followed by a comment with its
  version tag. Existing jobs keep their tags (out of scope).
- Versions are those released on or before 2026-11-23, each read in its release notes. For
  `cargo-deny`, 0.21.0 or later is required by the `expiry` field.

### Refusal under `kv` (D3)

- New test `rehash_refuses_to_run_with_kv` in `tests/vault_e2e.rs`, compiled only with `kv`. It does
  not start the vault (which would need Redis): it inserts by SQL one unused hash row dated
  2000-01-01, which a working job would delete in its clean-up, takes a snapshot, runs
  `utils rehash`, and checks: exit code 1, the printed error kind of the refusal, the snapshot
  unchanged, an audit row `rehash_run` with outcome `failure` and no `rehash_cleanup` row (so the
  failure comes from the job, not from the configuration or the database connection).
- New CI job in `.github/workflows/CI-pr.yml`, "Re-hash refusal with the kv feature", PostgreSQL
  service only, `cargo test --features key_custodian,kv --test vault_e2e rehash_refuses_to_run_with_kv`.
- Breakage: remove the `kv` refusals of the job's storage primitives (keep the PostgreSQL code under
  `kv`); the test must fail on the snapshot or the exit code. Limit, written in the docs: with no
  card stored, only two of the five refusals are on the path; the other three stay compiled only.

### Run without `key_custodian` (D4)

- `tests/vault_e2e.rs` compiles in both modes. Without `key_custodian`, `Keys::generate` still runs
  `utils master-key`, decrypts the master key in memory and gives the vault and `utils` its raw hex
  value, as an operator without custodians would; `unlock` does nothing. Custodian-only tests
  (`custodian_steps_write_audit_rows`, `custodian_key_is_refused_when_audit_table_is_unwritable`,
  `rehash_refuses_wrong_custodian_keys`) and their helpers are compiled only with `key_custodian`.
  `stored_card_hash_is_not_a_plain_sha512` uses `unlocked_master_key` instead of its own copy of it.
- New CI job "Re-hash without the key_custodian feature", PostgreSQL service,
  `cargo test --test vault_e2e rehash_` (the re-hash tests only, so the job stays on this ticket).
  It includes `rehash_moves_v1_rows_to_scoped_hashes`, which checks each row's expected hash and a
  new add returning `duplicated`.
- Breakage: skip the hex decoding of the master key in `utils` (`fetch_raw_secrets`); the test must
  fail on a row's expected hash.
- The existing job "End-to-end tests and demo against PostgreSQL" is unchanged and keeps running
  every test with `key_custodian`.

### Table and pages (D6)

- `docs/threat-model.md`: T28 cites the two new tests; new rows for a new dependency with a known
  vulnerability, an unapproved license or source (control in `deny.toml`; status `not tested`,
  because the breakage run is a one-off and the check script counts only test functions and demo
  checks); the original code's known vulnerabilities (`open`, citing `deny.toml`); git dependencies
  not covered by the RustSec database (`open`); existing workflow actions on moving tags (`open`).
  Moved `file:line` references are corrected.
- `docs/tokenization.md`: the two paths leave the "Not tested" list and cite their tests.
- `README.md`: every changed file listed under "Changes from the original".
- None of the three documents contains the words forbidden by `scripts/check-threat-model.sh`; they
  say "known vulnerabilities" or "RustSec database".

## Decisions for the owner

- **Q1. What the dependency job does with a known vulnerability already in the original code.**
  - A (recommended): each current entry is listed in `deny.toml` with the reason "present in the
    original code at a8ee711, not fixed by this fork" and an expiry 90 days from today; the job then
    fails only on a new entry, and every exception fails again on its date.
  - B: report only (the job never fails on vulnerabilities): green PRs, but the breakage cannot be
    seen as a failure.
  - C: blocking with no exception: every PR stays red until the original dependencies are updated,
    which is out of this ticket.
  - Answer (owner, 2026-11-23): A, with an expiry of 90 days, that is 2027-02-21.

## Left to the builder

- Exact SHAs and versions of the actions, read on the day of the plan.
- The list of exception identifiers (if Q1 = A), taken from the tool's own output in CI, not from
  the OSV query above.
- The exact error kind printed by the `kv` refusal, read from a local run.

## Risks

- The Scorecard action may refuse to run on a fork; fallback: approach 2.
- GitHub disables scheduled workflows of a public repository after 60 days without activity.
- A new RustSec entry can turn a PR red for a reason unrelated to its content; this is the intended
  signal, and the weekly run shows it even without a PR.
