# Merchant-scoped duplicate-check hash (I6): implementation plan

Design: `docs/superpowers/specs/2026-11-23-merchant-scoped-dedup-design.md` (decisions S1, S2, S3
taken by the owner on 2026-11-23). Branch: `feat/merchant-scoped-dedup`, from `main` (`dcbe7c1`).

## Global constraints

- `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"` before `cargo`; `-j 4`.
- `git status` before each commit, one logical change per commit, message in English. Before each
  `git commit`, the forbidden compliance wording of the project's `CLAUDE.md` is searched in the
  message from the session (pattern never written into a repository file).
- No environment file is read. No assertion message, log line or report excerpt contains a key; the
  tests recompute the master key in memory only, as `stored_card_hash_is_not_a_plain_sha512`
  already does.
- Files allowed to change: `src/crypto/hash_manager/managers/sha.rs`, `src/routes/data.rs`,
  `src/routes/data/transformers.rs`, `src/domain/hash.rs` (only if needed), `tests/vault_e2e.rs`,
  `docs/threat-model.md`, `docs/tokenization.md`, `README.md`, `docs/superpowers/`.
  Not touched: `demo/`, `migrations/`, `src/storage/schema.rs`, `config/`, `Cargo.toml`,
  `Cargo.lock`, `LICENSE`, the environment file, `.typos.toml`, `CLAUDE.md`, `.github/`,
  `scripts/check-threat-model.sh`.
- Callers checked before the change (`grep -r -n -E 'CardDedupHmac|from_master_key'` over the
  repository, outside `target/`, on 2026-11-23): only `sha.rs`, `src/routes/data.rs`,
  `src/routes/data/transformers.rs` and `tests/vault_e2e.rs`; none in `demo/`.
- Starting point (owner's brief, `main` at `dcbe7c1`): `cargo test -j 4` passes 38 tests; the e2e
  suite passes 6. Task 1 records the exact counts again before any change.
- Each e2e test creates and drops its own database (`TestDb::create`), so row counts are per test.

End-to-end runs use a throwaway PostgreSQL cluster, TCP only, port 54330, created in the session's
scratch directory and removed afterwards:

```
initdb -D "$PGDIR" -U postgres --auth=trust
pg_ctl -D "$PGDIR" -o "-c unix_socket_directories='' -c listen_addresses=127.0.0.1 -p 54330" -l "$PGDIR.log" -w start
VAULT_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:54330/postgres VAULT_TEST_REQUIRE_DB=1 \
  cargo test -j 4 --features key_custodian --test vault_e2e
pg_ctl -D "$PGDIR" -w stop && rm -rf "$PGDIR" "$PGDIR.log"
```

### Task 1: end-to-end tests, seen failing on the current code

**Couvre:** D6, D7, D7b

- `git branch --show-current` must print `feat/merchant-scoped-dedup` before any commit.
- Record the baseline first: `cargo test -j 4` and the e2e suite on `dcbe7c1`, passed counts and
  the clippy warning count of the command used in Task 6.
- In `tests/vault_e2e.rs`:
  - add `store_card_as(vault, merchant, customer, card_number)`; `store_card_for` calls it with
    `CUSTOMER` and `CARD_NUMBER`;
  - add `TestDb::count(table)` (a `SELECT count(*)` on `hash_table` or `locker` of the test's own
    database);
  - replace `same_card_for_two_merchants_shares_one_hash_row` by
    `same_card_for_two_merchants_gets_two_hash_rows`: merchant 1, merchant 2, merchant 1 again with
    the same customer; asserts 2 `hash_table` rows and `duplication_check` = `duplicated` on the
    third add, with no third row; also asserts that the `locker.hash_id` of merchants 1 and 2
    differ (the link a database reader would use), which is false on the current code;
  - add `card_known_to_others_takes_the_new_card_path`, with one public test card number per pair
    so that each pair changes one fact only:
    - pair 1, card A: add for merchant 1, customer 1 (known to no one), then card A for merchant 2,
      customer 1 (known only to another merchant);
    - pair 2, card B: add for merchant 1, customer 1, then card B for merchant 1, customer 2 (known
      only to another customer of the same merchant);
    - in each pair, the change in `hash_table` and `locker` counts of the second add must equal the
      change of the first add (`+1`, `+1`), and no response carries `duplication_check`;
    - each assertion names its pair, so the failure on the current code shows which pair failed;
  - add `tenant_wide_v1_hash_row_is_not_matched`: unlock, recompute the master key as
    `stored_card_hash_is_not_a_plain_sha512` does, compute the `v1` value with `ring` in the test
    (HKDF-SHA512, info `hyperswitch-card-vault/card-dedup/v1`, then HMAC-SHA512 of the quoted
    number), insert it into `hash_table` with a fixed `hash_id`, add the card, assert 2
    `hash_table` rows and no `duplication_check`.
- Run the e2e suite on the current code. Expected: the three new tests fail by assertion (one row
  instead of two; `+0` instead of `+1` for both pairs; the `v1` row matched), the others pass. Keep
  the output for the report.
- Commit: `test: end-to-end tests for a merchant- and customer-scoped duplicate check`.

### Task 2: unit tests in `sha.rs`, seen failing on the current code

**Couvre:** D1, D2, D3, D4, D5

- In `src/crypto/hash_manager/managers/sha.rs`, tests module, with constructor
  `CardDedupHmac::from_master_key(&key, merchant, customer)`:
  - `card_dedup_same_scope_gives_same_hash` (replaces `card_dedup_same_card_same_key_gives_same_hash`);
  - `card_dedup_two_merchants_give_two_hashes`;
  - `card_dedup_two_customers_give_two_hashes`;
  - `card_dedup_scope_framing_is_unambiguous` (`ab` + `c` against `a` + `bc`);
  - adapt `card_dedup_two_master_keys_give_two_hashes`,
    `card_dedup_differs_from_plain_sha512_and_from_master_key`,
    `card_dedup_rejects_empty_master_key`, `card_dedup_key_is_hkdf_of_master_key_with_context`
    (expected info built in the test from the context, the 8-byte big-endian lengths and the ids);
  - `card_dedup_context_is_versioned_and_specific` pins `.../card-dedup/v2`.
- Run `cargo test -j 4 --lib card_dedup`. Expected: does not compile (the constructor takes one
  argument). Keep the error lines for the report. The behaviour of each test is proven by the
  deliberate breaks of Task 3.
- Not committed alone (the crate would not compile); committed with Task 3.

### Task 3: scoped derivation, then deliberate breaks

**Couvre:** D1, D2, D3, D4, D5, D8, D9

- `sha.rs`: `CARD_DEDUP_INFO` = `b"hyperswitch-card-vault/card-dedup/v2"`; doc comments updated;
  `from_master_key(master_key, merchant_id: &str, customer_id: &str)` refuses an empty master key,
  builds the two 8-byte big-endian lengths, and calls `expand(&[CARD_DEDUP_INFO, &m_len,
  merchant_id.as_bytes(), &c_len, customer_id.as_bytes()], HKDF_SHA512)`. Nothing else changes.
- `src/routes/data.rs`: `add_card_inner` passes `&request.merchant_id` and
  `&request.merchant_customer_id`; comment updated.
- `src/routes/data/transformers.rs`: its test passes a scope.
- `tests/vault_e2e.rs`: `stored_card_hash_is_not_a_plain_sha512` passes `MERCHANT`, `CUSTOMER`.
- Run `cargo test -j 4` (expected: exit 0, baseline count plus the new unit tests) and the e2e suite
  (expected: `0 failed`, baseline plus 2 passed).
- Deliberate breaks, one at a time, each undone before the next (not committed):
  1. remove both length prefixes: `card_dedup_scope_framing_is_unambiguous` must fail;
  2. leave the customer id out of the info: `card_dedup_two_customers_give_two_hashes` must fail;
  3. leave the merchant id out of the info: `card_dedup_two_merchants_give_two_hashes` must fail;
  4. put back the `v1` context: `card_dedup_context_is_versioned_and_specific` must fail;
  5. in `src/routes/data.rs`, pass the merchant id in place of the customer id:
     `stored_card_hash_is_not_a_plain_sha512` and `card_known_to_others_takes_the_new_card_path`
     (pair 2) must fail in the e2e suite.
  After the last undo, `git diff --stat` matches the intended change and `cargo test -j 4 --lib
  card_dedup` passes. Each failing test name goes in the report.
- Commit: `feat: scope the duplicate-check hash to the merchant and customer`.

### Task 4: docs and threat model table

**Couvre:** D10

- `docs/tokenization.md`: the duplicate-check section describes the `v2` context and the scope;
  "Rows written before the keyed hash" gains the `v1` rows (not matched, keep the shared `hash_id`);
  a short paragraph on the own-history path; line references updated. The cache sentence is kept
  only if the cache code read in this task supports it.
- `docs/threat-model.md`:
  - T9, T10: lines and test names;
  - T11: the new e2e and unit tests;
  - T24: `proven` for rows written after the change; control = the scoped derivation lines;
  - T25: reworded to the cross-party oracle, `proven`, with "code path proven, duration not
    measured" in the row;
  - T28 (`open`): `v1` rows keep the shared `hash_id` and are no longer matched, so a duplicate of
    an old card is not detected; evidence = the `docs/tokenization.md` lines; closed by the planned
    re-hash ticket;
  - T29 (`open`): the same merchant and customer who stored, deleted and add a card again take a
    shorter path and learn only their own past; evidence = the `docs/tokenization.md` lines;
  - T21, T22: line ranges;
  - the "How to check" line lists every row with e2e evidence (T2 to T6, T9, T11, T24, T25).
  Every `file:line` in the table reread by hand after the move, not only by the script.
- Run `scripts/check-threat-model.sh` (expected `OK: 29 rows (13 proven, 6 not tested, 10 open)`)
  and the owner's forbidden-word check on the three public docs (expected 0 for each).
- Commit: `docs: threat model and tokenization page after the scoped duplicate check`.

### Task 5: README

**Couvre:** D10

- `README.md`, "Changes from the original": a new entry for this ticket listing each file of
  `git diff --name-only main`; the earlier entry that names
  `same_card_for_two_merchants_shares_one_hash_row` says that test was replaced, so the README cites
  no test that no longer exists.
- Commit: `docs: list the files changed by the scoped duplicate check`.

### Task 6: full verification and reviews

**Couvre:** D9, D10

- `make demo` (expected last line `DEMO OK`, against the throwaway cluster).
- `cargo clippy -j 4 --all-features --all-targets` as the CI does; if a feature cannot build on
  this Mac, rerun with `--features key_custodian`, say why, and compare with the baseline.
  `cargo fmt --all --check` with the stable toolchain (the CI uses nightly, not installed here);
  `typos` is not installed: reported "not run locally", checked by the CI.
- `git -C ~/hyperswitch-card-vault merge-base --is-ancestor dcbe7c1 feat/merchant-scoped-dedup`.
- `git diff --name-only main -- demo config migrations src/storage/schema.rs Cargo.toml Cargo.lock .github CLAUDE.md .typos.toml LICENSE scripts`
  returns nothing, and every line of `git diff --name-only main` is in the allowed list above.
- The forbidden compliance wording defined in the project's `CLAUDE.md` is searched in the added
  lines of `git diff main`, in `git log main..HEAD --format=%B`, and in the PR title and body before
  they are published. The search pattern is run from the session and never written into a
  repository file.
- `grep -r -n -E 'same_card_for_two_merchants_shares_one_hash_row|card_dedup_same_card_same_key_gives_same_hash'`
  over the repository outside `target/` and `docs/superpowers/` (past designs keep their history)
  returns only the README line that says the test was replaced.
- README lists every changed file; `git status --porcelain` empty.
- `security-review` skill on the branch; a fresh reviewer subagent (`model: opus`) given the
  owner's request verbatim, the diff and the table, asked to check that each added test fails when
  its control is removed; `second-avis --reserve 50` in parallel. Findings that change the result
  are fixed and the affected checks rerun.

### Task 7: push and pull request (stops for the owner)

- `git remote get-url origin` must name `antoinevoinchet-spec/hyperswitch-card-vault`.
- Stop with DOING / EXPECT / IF WRONG before `git push -u origin feat/merchant-scoped-dedup`.
- Write the PR title and body in English, search them for the forbidden compliance wording from
  the session, and show both text and result in the DOING / EXPECT / IF WRONG block that comes
  before `gh pr create -R antoinevoinchet-spec/hyperswitch-card-vault --base main`. Every `gh pr`
  command takes `-R antoinevoinchet-spec/hyperswitch-card-vault`.
- `gh pr checks <n> -R antoinevoinchet-spec/hyperswitch-card-vault` until done; a failure is
  reported as is, and a failure caused by the original code is brought to the owner before any fix.
  Merging waits for the owner.
