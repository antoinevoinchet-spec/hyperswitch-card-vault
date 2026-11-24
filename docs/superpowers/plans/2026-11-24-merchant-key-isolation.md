# Merchant data key isolation (threat T13): implementation plan

Date: 2026-11-24 (UTC). Branch: `test/merchant-key-isolation` (design commit `e15dd6a`, from `main`
`a45457e`). Design: `docs/superpowers/specs/2026-11-24-merchant-key-isolation-design.md`.
This plan is copied to `docs/superpowers/plans/2026-11-24-merchant-key-isolation.md` and committed
as Task 0. The branch name comes from the owner's brief (kept as is). The repository copy is in English only.

## Context

T13 ("One merchant's key decrypts another merchant's cards") is `not tested`. The control exists
(one random data key per merchant, `src/domain/merchant.rs:33-36`; card data encrypted with it,
`src/crypto/keymanager/internal_keymanager.rs:128-136`; retrieve decrypts with the key of the
merchant named in the request, `src/routes/data.rs:248-266`). Two e2e tests prove it on write and on
read, each seen failing on a breakage that reaches its own assertion. No production code changes.

Shared setup for every cargo command:
`export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"`, always `-j 4`.
E2E command (`E2E` below):
`VAULT_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:54330/postgres VAULT_TEST_REQUIRE_DB=1 cargo test -j 4 --features key_custodian --test vault_e2e`.

Reused helpers, all in `tests/vault_e2e.rs`: `admin_url`, `TestDb::{create, exec, count}`,
`Keys::generate`, `Vault::{start, post}`, `unlock`, `store_card_with_ref`, `card_data`,
`card_data_with`, `unlocked_master_key`, `merchant_keys`, `locker_data`, `opens`,
`retrieve_request` (uses `CUSTOMER`), `assert_card_number`, `assert_no_secret`; constants
`MERCHANT`, `MERCHANT_2`, `MERCHANT_3`, `CUSTOMER`, `CARD_NUMBER`, `CARD_2`. No new helper.

### Task 0: commit the plan
**Covers:** (process)
- Copy this file to `docs/superpowers/plans/2026-11-24-merchant-key-isolation.md`, with French labels translated; check it holds no forbidden identifier or forbidden claim wording
  (patterns kept in the session scratchpad, never written in the repository); `git status`; commit
  `docs: plan for merchant data key isolation tests (T13)`.

### Task 1: disposable PostgreSQL and baseline
**Covers:** D8
- `initdb` into `<session scratchpad>/pg54330` (user `postgres`, trust auth) from
  `/opt/homebrew/opt/postgresql@14/bin`; `pg_ctl start` with
  `-o "-c unix_socket_directories='' -c listen_addresses=127.0.0.1 -p 54330"`.
- Run `E2E` on the unchanged branch: expect `31 passed; 0 failed`.

### Task 2: matrix test (write side)
**Covers:** D1, D2, D3, D5
Read before writing (done during planning, re-checked at execution): `LockerDataRow` has
`locker_id`, `merchant_id`, `customer_id`, `enc_data`, `hash_id`; `opens(key, blob)` returns the
AES-GCM plaintext or `None`; `merchant_keys` returns `BTreeMap<merchant_id, key>`; the plaintext is
the JSON of `StoredData` (`src/routes/data/types.rs:228-231`), so it holds the card number as text.
Failure messages of `store_card_with_ref` and `assert_card_number` name the reference only.
Append after `rotation_with_external_key_manager` (end of file), no `cfg` gate (same as the
rotation tests):

```rust
/// Threat T13, write side: each merchant's data key opens every card row of that merchant and no
/// row of another merchant; the master key opens none. Failure messages name references and
/// merchants only.
#[tokio::test]
async fn each_merchant_key_opens_only_its_own_cards() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    // CARD_NUMBER is held by two merchants; the other numbers by one merchant only.
    let cards = [
        (MERCHANT, "iso-m1-a", CARD_NUMBER),
        (MERCHANT, "iso-m1-b", CARD_2),
        (MERCHANT_2, "iso-m2-a", CARD_NUMBER),
        (MERCHANT_3, "iso-m3-a", "4012888888881881"),
    ];
    for (merchant, reference, number) in cards {
        store_card_with_ref(&vault, merchant, CUSTOMER, card_data_with(number), reference).await;
    }
    drop(vault);

    let master = unlocked_master_key(&keys);
    let deks = merchant_keys(&db, &master);
    let rows = locker_data(&db);

    // D1: every stored card is there, under its own merchant.
    assert_eq!(deks.len(), 3, "three merchant keys");
    assert_eq!(rows.len(), cards.len(), "locker row count");
    for merchant in [MERCHANT, MERCHANT_2, MERCHANT_3] {
        let expected = cards.iter().filter(|card| card.0 == merchant).count();
        let stored = rows.iter().filter(|row| row.merchant_id == merchant).count();
        assert_eq!(stored, expected, "{merchant} row count");
    }

    // D2: each merchant's key opens its own rows to the card number it stored.
    for row in &rows {
        let (_, _, number) = cards
            .iter()
            .find(|card| card.0 == row.merchant_id && card.1 == row.locker_id)
            .expect("row stored by this test");
        let plain = deks
            .get(&row.merchant_id)
            .and_then(|key| opens(key, &row.enc_data));
        assert!(
            plain.is_some_and(|plain| String::from_utf8_lossy(&plain).contains(number)),
            "{} of {} does not open to its card under its own merchant key",
            row.locker_id,
            row.merchant_id
        );
    }

    // D3: exactly one key opens each row, its own merchant's.
    let mut openers: Vec<(&str, &[u8])> = deks
        .iter()
        .map(|(merchant, key)| (merchant.as_str(), key.as_slice()))
        .collect();
    openers.push(("master key", master.as_slice()));
    let mut isolated = true;
    let mut matrix = String::new();
    for row in &rows {
        let (open, refuse): (Vec<_>, Vec<_>) = openers
            .iter()
            .partition(|(_, key)| opens(key, &row.enc_data).is_some());
        let open: Vec<&str> = open.iter().map(|(name, _)| *name).collect();
        let refuse: Vec<&str> = refuse.iter().map(|(name, _)| *name).collect();
        isolated &= open == [row.merchant_id.as_str()];
        matrix.push_str(&format!(
            "{} of {}: OPENS {open:?} REFUSES {refuse:?}\n",
            row.locker_id, row.merchant_id
        ));
    }
    assert!(isolated, "a card row opens under another key than its merchant's:\n{matrix}");
}
```
- Run `E2E each_merchant_key_opens_only_its_own_cards -- --exact`: expect `1 passed`.
  (If the plaintext check of D2 fails on green code, read `StoredData` in
  `src/routes/data/types.rs:228-231` and adjust the check, not the control.)

### Task 3: transplant test (read side)
**Covers:** D4, D5

```rust
/// Threat T13, read side: a card row copied in the database from one merchant to another is not
/// returned to the second merchant, because the vault decrypts with the requesting merchant's key.
#[tokio::test]
async fn card_moved_to_another_merchant_is_not_returned() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data_with(CARD_NUMBER), "iso-a").await;
    store_card_with_ref(&vault, MERCHANT_2, CUSTOMER, card_data_with(CARD_2), "iso-b").await;

    // Positive control: merchant 2 reads its own card through the same route.
    let (status, body) = vault
        .post("/data/retrieve", retrieve_request(MERCHANT_2, "iso-b"))
        .await;
    assert_eq!(status, 200, "merchant 2 reads its own card");
    assert_card_number(&body, CARD_2, "iso-b");

    // Copy merchant 1's row under merchant 2, unchanged except merchant and reference.
    db.exec(&format!(
        "INSERT INTO locker \
         (locker_id, merchant_id, customer_id, enc_data, hash_id, created_at, ttl, updated_by) \
         SELECT 'iso-moved', '{MERCHANT_2}', customer_id, enc_data, hash_id, created_at, ttl, \
         updated_by FROM locker WHERE merchant_id = '{MERCHANT}' AND locker_id = 'iso-a'"
    ));
    assert_eq!(db.count("locker"), 3, "row copied");

    let (status, body) = vault
        .post("/data/retrieve", retrieve_request(MERCHANT_2, "iso-moved"))
        .await;
    let refused = !(200..300).contains(&status);
    let leaked = [CARD_NUMBER, CARD_2].iter().any(|number| body.contains(number));
    assert!(
        refused && !leaked,
        "a card copied from {MERCHANT} is served to {MERCHANT_2} \
         (status {status}, refused {refused}, card number in body {leaked})"
    );
    assert_no_secret(&body, &[CARD_NUMBER.to_string(), CARD_2.to_string()]);
}
```
- The copy keeps every column of `locker` (read in `migrations/`) except `id` (serial),
  `locker_id` and `merchant_id`, as the design says.
- Run `E2E card_moved_to_another_merchant_is_not_returned -- --exact`: expect `1 passed`; note the
  refusal status seen (expected 500 from the decryption error, recorded, not asserted).

### Task 4: proof by breakage, then back to green
**Covers:** D6
Temporary edits in `src/`, never committed; after each, `git diff --stat -- src` shown, then
`git checkout -- <file>` and `git diff main -- src` empty.
Each breakage run must compile, report `1 failed` per targeted test, and panic with the expected
message at the expected line of the new test; otherwise it does not count. Each output is saved in
the session scratchpad and scanned with `grep -c` for the three card numbers and for 64-character
hex runs (patterns in the scratchpad, nothing printed); only outputs with a count of 0 are quoted.
1. Breakage 1, `src/domain/merchant.rs:35`: `enc_key: aes::generate_aes256_key().to_vec().into()`
   → `enc_key: vec![7u8; 32].into()` (all merchants share one data key). Run both tests.
   Expect: matrix test fails at the D3 `assert!` (message "opens under another key than its merchant's", D1 and D2
   passed before it); transplant test fails at the refusal `assert!` ("is served to"). Record the
   panic lines (`file:line` inside the new tests).
2. Breakage 2, `src/crypto/keymanager/internal_keymanager.rs:128-136`: `encrypt_data` encrypts with
   `GcmAes256::new(tenant_app_state.config.tenant_secrets.master_key.clone().expose())` instead of
   `self.get_inner()` (parameter renamed from `_tenant_app_state`); this is the same unlocked value
   `find_or_create_entity` uses to wrap merchant keys (`internal_keymanager.rs:48-55`). Run both
   tests. Expect: the matrix test fails at the D2 `assert!` ("does not open to its card under its
   own merchant key"); the transplant test fails at its positive control ("merchant 2 reads its own
   card"), which proves that control is live (it does not count for D4).
3. Undo; run both tests: `2 passed`.
- If a breakage fails before the targeted assertion (for example a 500 on `/data/add`), it does not
  count: change the breakage, not the test, and record it.
- Commit `test: prove each merchant key opens only its own cards (T13)` with `tests/vault_e2e.rs`
  only. Then add an "Execution notes" section at the end of the repository copy of the plan with
  each breakage, the failing test, its panic line and message, and the refusal status of Task 3;
  commit `docs: record the T13 breakage runs in the plan`. The same lines go in the PR body.

### Task 5: threat model table
**Covers:** D7
- `docs/threat-model.md` row T13: Control adds `src/domain/merchant.rs:33-36`; Evidence:
  `each_merchant_key_opens_only_its_own_cards` (each key opens its own rows and no other; the master
  key opens none), `card_moved_to_another_merchant_is_not_returned` (a row copied from another
  merchant is refused). Limits, without underscores outside the test names: the honest case only
  (AES-GCM does not commit to its key); a row moved to another customer of the same merchant still
  opens (no associated data); the external key manager is not covered. Status `proven`.
- Line 19: add T13 to the list of rows cited by end-to-end tests.
- Re-read every `file:line` reference in the table, `docs/tokenization.md` and `README.md` that
  points into a changed file: `grep -nE '(threat-model|README|vault_e2e|tokenization)\.(md|rs):[0-9]'
  docs/*.md README.md`; appending at the end of `tests/vault_e2e.rs` should move none. Update any
  count of statuses in the docs (rows proven / not tested) if one exists.
- `scripts/check-threat-model.sh` → exit 0. Commit `docs: T13 proven by two end-to-end tests`.

### Task 6: README
**Covers:** D9
- New group under "Changes from the original": merchant data key isolation tests, listing
  `tests/vault_e2e.rs`, `docs/threat-model.md`, the design and this plan (and
  `docs/tokenization.md` if it changed). Check against `git diff --name-only main` (every file but
  `README.md` itself); re-check after any fix from the review in Task 7. Commit `docs: list the T13 test changes in the README`.

### Task 7: full verification
**Covers:** D8, D5
- `cargo fmt --all --check`; `RUSTFLAGS="-D warnings" cargo clippy -j 4 --all-features --all-targets`.
- `cargo test -j 4` → at least 77 passed. `E2E` → `33 passed; 0 failed`.
- Same two tests without `key_custodian` against the cluster (as the CI jobs without custodians
  build): `VAULT_TEST_DATABASE_URL=... VAULT_TEST_REQUIRE_DB=1 cargo test -j 4 --test vault_e2e
  -- each_merchant_key_opens_only_its_own_cards card_moved_to_another_merchant_is_not_returned`
  → `2 passed`.
- CI jobs read (read only, `.github/workflows/CI-pr.yml`): `integration-db` runs the whole file with
  `key_custodian`; the jobs without custodians filter on `rehash_` and `rotation_`; the `kv` and
  external key manager jobs run one test each with `--exact`; `nextest --all-features` has no
  database, so the e2e tests return early. The new tests therefore never run with the external key
  manager; no `cfg` gate is needed.
- CI formats with `cargo +nightly fmt`; the nightly toolchain is not installed here, so local fmt
  is stable only; the CI job is the check (reported as such).
- Green `--nocapture` output of both tests saved in the scratchpad and scanned like the breakage
  outputs (count 0).
- `make demo` with `DEMO_DATABASE_URL` on an empty database of the cluster → `DEMO OK`.
- Checks: the forbidden-identifier count on `docs/threat-model.md`, `README.md`,
  `docs/tokenization.md` → 0 each; forbidden claim wording; both patterns kept in the session
  scratchpad, run on the added lines of `git diff main`, on `git log main..HEAD --format=%B` and on
  the PR title and body before they are shown; `git diff --name-only main -- src migrations config demo
  Cargo.toml Cargo.lock deny.toml CLAUDE.md .typos.toml LICENSE scripts .github` empty;
  `git merge-base --is-ancestor a45457e HEAD`.
- Review in parallel: fresh subagent (`model: opus`) and `second-avis --reserve 50`, each with the
  request word for word, the diff as `git diff -U0 main` (no unchanged context lines, so no
  `custodian_key1`/`custodian_key2` context; any such line left is filtered out) and the table; each checks that the tests fail when the control is removed.

### Task 8: PR and close
**Covers:** D8
- Stop: DOING / EXPECT / IF WRONG, then `git push -u origin test/merchant-key-isolation` (after
  yes); then PR title and body shown, then `gh pr create -R antoinevoinchet-spec/hyperswitch-card-vault`
  (after yes).
- `gh pr checks <n> -R antoinevoinchet-spec/hyperswitch-card-vault`: every job pass, or reported.
- Merge only after yes: `gh pr merge <n> -R antoinevoinchet-spec/hyperswitch-card-vault` with the
  method of earlier PRs (merge commit). Stop and delete the cluster. Tick T1 in the Obsidian note with a dated
  journal line. Final report against every completion criterion; next task T2.

## Verification summary
Both new tests green; each seen red on the breakage that reaches its assertion; `E2E` 33 passed;
unit tests ≥ 77; demo OK; check script 0; CI green on the PR.

## Execution notes (2026-11-24, UTC)

- Baseline before the tests: e2e suite with `key_custodian`, `31 passed; 0 failed`.
- Both new tests green on unchanged `src/`. The refusal of the copied row is HTTP 400 with the
  crypto error message ("encrypting/decrypting"), not the 500 this plan expected.
- After review (second opinion), two checks were tightened: the decrypted plaintext is parsed and
  its `CardData.card_number` field compared exactly; the refusal must be that 400 crypto error, so a
  lookup that misses the row (404) fails the test. The runs below are the ones after that change.
- Breakage 1 (`src/domain/merchant.rs`, every merchant key set to the same 32 bytes): both tests
  compile and fail at their targeted assertion.
  - `each_merchant_key_opens_only_its_own_cards` panics at `tests/vault_e2e.rs:2508` (the
    one-opener assertion, after the counts and the own-key checks passed): every row
    `OPENS ["demo-merchant", "demo-merchant-2", "demo-merchant-3"] REFUSES ["master key"]`.
  - `card_moved_to_another_merchant_is_not_returned` panics at `tests/vault_e2e.rs:2565`: "a card
    copied from demo-merchant is not refused by decryption for demo-merchant-2 (status 200,
    decryption refusal false, card number in body true)".
- Breakage 2 (`src/crypto/keymanager/internal_keymanager.rs`, card data encrypted with the master
  key instead of the merchant key):
  - `each_merchant_key_opens_only_its_own_cards` panics at `tests/vault_e2e.rs:2479`: "iso-m1-a of
    demo-merchant does not open to its card under its own merchant key".
  - `card_moved_to_another_merchant_is_not_returned` panics at `tests/vault_e2e.rs:2544`, its
    positive control ("merchant 2 reads its own card"); this shows the control is live and does not
    count for the refusal.
- Missing-row check (test edited for one run only: the read asks for a reference that does not
  exist): `card_moved_to_another_merchant_is_not_returned` panics at `tests/vault_e2e.rs:2565`
  with "status 404, decryption refusal false", so a lookup miss cannot pass as a refusal.
- Both breakages undone with `git checkout`; `git diff main -- src` empty; both tests green again.
- Every saved output (green, both breakages, missing-row check) scanned for the three card numbers
  and for 64-character hex runs: 0 matches.
