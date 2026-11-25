# Tests for controls already in the code (task T3): plan

Design: `docs/superpowers/specs/2026-11-25-untested-controls-design.md`. Branch:
`test/t3-untested-controls`.

## Global Constraints

- Only `tests/`, `docs/threat-model.md`, `docs/tokenization.md` (shifted references only),
  `README.md` ("Changes from the original" only) and `docs/superpowers/` change without a stop.
- No key, share, master key or environment file is read, printed or committed. Test keys are made
  at run time and never printed.
- Every cargo command with `-j 4`. End-to-end runs count only with `VAULT_TEST_REQUIRE_DB=1` and a
  real PostgreSQL (local: port 54330, `-c unix_socket_directories=''`).
- A breakage is applied, run, reverted, and `git diff` of the file must be empty afterwards.
- One logical change per commit, `git status` before each.
- Steps of every test task: write the test; green run; apply the breakage; red run, its failing
  line copied below with card numbers and ids masked; revert and check `git diff` of the file is
  empty; green run; `git status`; commit.
- Stop rule: if a test fails on the unbroken code because of a real defect, stop, keep the red
  output, and ask the owner (A or B) before any production change.
- Dependencies used by the tests are already in `Cargo.toml` (read 2026-11-25): `uuid` (v7),
  `josekit`, `ring`, `hex`; dev: `rsa`, `rand`. No dependency is added.
- Before each commit touching `docs/threat-model.md`, `README.md` or `docs/tokenization.md`: the
  count of `GHSA` and `advisories` in those three files is 0, and no compliance wording.
- CI coverage (read in `.github/workflows/CI-pr.yml`): the end-to-end job runs
  `cargo test --features key_custodian --test vault_e2e` (T12, T14, T15, T17); the test job runs
  `cargo nextest run --all-features` (picks up `tests/dependency_policy.rs`, T31). No job ran the
  `middleware_` tests (T16) before this task; the owner accepted a CI step (see the notes).
- Branch name `test/t3-untested-controls` is the one the owner's brief names.

## Review Focus

- Each test must fail on its breakage for the reason the row claims (the failing line below), not
  for an unrelated reason such as a start-up panic.
- No assertion that compares with output of the same code under test when an outside oracle exists.

### Task 1: T15, unknown tenant
**Couvre:** D1

Test `unknown_tenant_is_refused_on_every_data_route`, helpers `Vault::post_as_tenant`,
`data_row_counts`, `every_data_request`. Breakage:

```diff
--- a/src/custom_extractors.rs
+++ b/src/custom_extractors.rs
@@ -28,7 +28,6 @@
             .and_then(|h| h.to_str().ok())
             .ok_or(ApiError::TenantError("x-tenant-id not found in headers"))?;

-        state.is_known_tenant(tenant_id)?;
         Ok(Self(state.get_app_state_of_tenant(tenant_id).await?))
     }
```

Failing line: _filled in at execution_.

### Task 2: T14, data before unlock
**Couvre:** D2

Test `data_routes_are_refused_before_unlock` (`key_custodian` only). Breakage: build the tenant
states at start-up under `key_custodian` too:

```diff
--- a/src/tenant.rs
+++ b/src/tenant.rs
@@ -88,10 +88,10 @@
         let tenants_app_state = {
-            #[cfg(feature = "key_custodian")]
+            #[cfg(any())]
             {
                 FxHashMap::default()
             }
-            #[cfg(not(feature = "key_custodian"))]
+            #[cfg(all())]
             {
```

If the vault then panics at start-up (the master key is still encrypted), the red would come from
the start, not from the control: fall back to answering the state in `get_app_state_of_tenant`
from any tenant already unlocked or, failing that, to replacing `.ok_or(ApiError::CustodianLocked)`
by a state built on demand. The breakage actually used and its failing line: below.

### Task 3: T17, generated reference
**Couvre:** D3

Test `generated_card_reference_is_a_uuid_v7`. Breakage in `src/storage/utils.rs`:
`uuid::Uuid::now_v7().to_string()` replaced by
`uuid::Uuid::from_u128(uuid::Uuid::now_v7().as_u128() ^ (0xF_u128 << 76)).to_string()` (same shape,
version nibble changed). Failing line: _filled in at execution_.

### Task 4: T12, fingerprint key
**Couvre:** D4

Test `fingerprint_differs_for_two_caller_keys`. Breakage in `src/domain/fingerprint.rs:21`: the
HMAC built under a fixed key instead of the request's key:

```diff
-    let algo = HmacSha512::<1>::new(key.map(|inner| inner.into_bytes()));
+    let algo = HmacSha512::<1>::new(Secret::new(b"fixed".to_vec()));
+    let _ = key;
```

Failing line: _filled in at execution_.

### Task 5: T16, JWE middleware
**Couvre:** D5

Tests `middleware_requests_and_responses_are_jwe` and `middleware_refuses_plain_and_forged_requests`
under `#[cfg(feature = "middleware")]`. Command:
`cargo test -j 4 --features key_custodian,middleware --test vault_e2e middleware_`. Breakages: the
response sent in clear (`src/middleware.rs:92-98`); `wants_jws_response` without its path check
(`src/middleware.rs:39`, `parts.uri.path() == consts::V2_FINGERPRINT_PATH &&` removed). Response
in clear:

```diff
-        let jwe_payload = record_jwe_middleware_operation(
-            async { keys.encrypt(response_body.to_vec()) },
-            "response_encrypt",
-        )
-        .await?;
-
-        (parts, axum::Json(jwe_payload)).into_response()
+        (parts, response_body).into_response()
```

Also run clippy with `--features key_custodian,middleware --all-targets`. The row moves to
`proven` only if the owner accepts a CI line running these tests (asked before Task 7); otherwise
it stays `not tested` and Evidence names the local tests.

### Task 6: T31, dependency policy
**Couvre:** D6

New file `tests/dependency_policy.rs`. Breakages: `unknown-git = "allow"` in `deny.toml`; the
`pull_request:` trigger removed from the workflow. Failing lines: _filled in at execution_.

### Task 7: threat table, README
**Couvre:** D7, D8

Rows T12, T14, T15, T16 (per the owner's answer), T17, T31: Evidence cites the tests, status
`proven`, what is not covered stays in the row (T31: the weekly schedule after 60 days without
activity and whether the check is required before merging, not tested); `file:line` in the six
rows and in `docs/tokenization.md` checked against the code and fixed if shifted; the header list
of end-to-end rows gains the new ones, and the T16 command if it is proven; T31 written without
the two forbidden words. `scripts/check-threat-model.sh` exits 0. README entry compared with
`git diff main --name-only`, `docs/superpowers/` files included.

### Task 8: full checks and reviews
**Couvre:** D1, D2, D3, D4, D5, D6, D7, D8

Full `cargo test -j 4`, end-to-end suite with and without `key_custodian`, `middleware_` tests
with `key_custodian,middleware`, clippy with `--all-targets` for those feature sets, grep of
compliance wording and of the two forbidden words in changed files,
scan of kept outputs (card numbers, 64-hex runs: 0), `security-review`, fresh Opus review and
`second-avis --reserve 50`.

### Task 9: push, PR, CI, note (each after the owner's yes)
**Couvre:** D7

Push to `origin` only; every `gh pr` command with `-R antoinevoinchet-spec/hyperswitch-card-vault`.
"Note" is the owner's Obsidian note `Projets/hyperswitch-card-vault.md`: tick T3 and add one dated
log line, nothing else. Report the stale "UUID v4" doc comment of `src/storage/utils.rs:7`.

## Execution notes

All runs on 2026-11-25 against a local PostgreSQL 14 (port 54330) with `VAULT_TEST_REQUIRE_DB=1`,
`--features key_custodian` unless stated. After each breakage, `git checkout` of the file and
`git diff --stat src/` empty. Ids and references are masked below.

- T15: green. Breakage of Task 1. Red:
  `assertion left == right failed: /data/add with tenant Some("no-such-tenant")`,
  `left: (401, {"code":"TE_00","message":"Custodian is locked","data":null})`,
  `right: (400, {"code":"TE_03","message":"Tenant error: Invalid x-tenant-id","data":null})`.
  Restored, green.
- T14: green. The breakage of Task 2 did not compile at first (`TenantConfig` is imported only
  without the custodian feature); a compile error does not count. Used: the same patch plus the
  import made unconditional (`#[cfg(not(feature = "key_custodian"))]` above
  `use crate::config::TenantConfig;` replaced by `#[cfg(all())]`). The vault started; red:
  `assertion left == right failed: /data/add before any key`,
  `left: (500, {"code":"TE_02","message":"Failed while getting merchant from DB","data":null})`,
  `right: (401, ... "Custodian is locked" ...)`: the request reached the database before unlock.
  Restored, green.
- T17: green. Breakage of Task 3. Red: `assertion left == right failed: version 7: <uuid>`,
  `left: 8`, `right: 7`. Restored, green.
- T12: green. Breakage of Task 4 (compiles: `HmacSha512::new` takes a `Secret<Vec<u8>>`). Red:
  `assertion left != right failed: two keys, two fingerprints`, `left: "<id>"`, `right: "<id>"`.
  Restored, green.
- T16 (`--features key_custodian,middleware`, filtered on `middleware_`): green, 2 passed.
  - Response in clear (patch of Task 5): `middleware_requests_and_responses_are_jwe` red at
    `assert!(!body.contains("card_reference"), "add response not in clear")`.
  - Path check of `wants_jws_response` removed: the same test red at `.expect("JWE field")` in
    `open_response` (the retrieve response was a signed-only JWS).
  - Request signature not verified (in `src/crypto/encryption_manager/managers/jw.rs`,
    `verify_sign` replaced by a base64 decode of the JWS payload; the first version did not
    compile and does not count): `middleware_refuses_plain_and_forged_requests` red with
    `signed with another key: refused, got 200`.
  - Restored, green.
  - The owner accepted a CI step on 2026-11-25 (decision A): `.github/workflows/CI-pr.yml`, job
    "End-to-end tests and demo against PostgreSQL", step "Run the JWE middleware tests", which
    also checks that exactly 2 tests passed.
- T31 (`cargo test -j 4 --test dependency_policy`): green, 4 passed.
  - `unknown-git = "allow"` in `deny.toml`: `deny_policy_checks_every_feature_and_every_source`
    red at `sources: unknown-git = "deny"`.
  - `  pull_request:` removed from `.github/workflows/dependencies.yml`:
    `dependency_workflow_runs_on_every_pull_request_main_and_weekly` red at `pull_request`.
  - Restored (`git diff --stat` empty), green.
- Table: `scripts/check-threat-model.sh` → `OK: 40 rows (24 proven, 0 not tested, 16 open)`. The
  first run refused `src/tenant.rs:145-151` (blank last line); fixed to `145-150`.
  `docs/tokenization.md` references still point at the right code: unchanged.
- Note: the CI test job (`cargo nextest run --all-features`) also builds the `middleware_` tests;
  without a database URL they print "skipped" and pass, as every end-to-end test does there.

### After the reviews (2026-11-25)

Second opinion (gpt-6.2-sol) and a fresh Opus review. Applied, each re-run green:

- Failures never print a card number: T14 and T15 compare response bodies with runs of 13 or
  more digits masked; T16 compares the decrypted number with `assert!` and a fixed message.
- T31 tightened, each new assertion seen red then green:
  - `pull_request:` followed by `    branches: [release]`: red at `pull_request without a filter`;
  - one more exception in the right form: red at `number of vulnerability exceptions`;
  - cron changed to once a year: red at `weekly schedule, Mondays at 05:17 UTC`.
- Row T17 says the random bits are not measured; the table header no longer ties T16 to the
  command without the middleware feature; the design shows the real error body.
- Test files formatted with `rustfmt --edition 2024` (the CI runs nightly `cargo fmt --check`,
  not installed here); stable `cargo fmt --all --check` then reports no diff.
- Re-runs: end-to-end with the custodian feature 47 passed (exit 0); `middleware_` 2 passed
  (exit 0); `unknown_tenant` without the custodian feature 1 passed (exit 0);
  `dependency_policy` 4 passed; `scripts/check-threat-model.sh` OK, 24 proven, 0 not tested.
- Not applied: running the whole `vault_e2e` file with the middleware feature (every other test
  sends plain JSON and is refused by design); the CI step runs the two `middleware_` tests.

