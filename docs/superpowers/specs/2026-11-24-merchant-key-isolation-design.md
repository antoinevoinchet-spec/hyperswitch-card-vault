# Merchant data key isolation (threat T13): design

Date: 2026-11-24 (UTC). Branch: `test/merchant-key-isolation` (from `main`, `a45457e`). Status:
decision K1 taken by the owner (option A); plan to follow in
`docs/superpowers/plans/2026-11-24-merchant-key-isolation.md`.

## Intent

Threat T13 in `docs/threat-model.md` reads "One merchant's key decrypts another merchant's cards"
and is `not tested`: no test stores cards for two merchants and checks that each merchant's data key
opens only that merchant's rows. This ticket adds end-to-end tests that prove the existing control,
shows that they fail when the control is removed on purpose, and updates the T13 row. It changes no
production code. This is a study fork; see `CLAUDE.md` for what may not be claimed about it.

Research reused: the owner's 2026-11-23 outside review of this ticket (kept outside the
repository). Ideas adopted from it: one opener per row over a matrix of keys, strict positive
checks first, one card number shared by two merchants, two deliberate breakages, and (decision K1)
a transplanted row read through the real API. Practice read on 2026-11-23: Tink and AWS KMS both
recommend binding a ciphertext to its context so that a ciphertext moved to another record is
refused (https://developers.google.com/tink/bind-ciphertext,
https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html).

## Current state (read in the code on 2026-11-23)

- A merchant's data key is 32 random bytes generated on its first `/data/add`
  (`src/domain/merchant.rs:33-36`), stored in `merchant.enc_key` encrypted with the tenant master
  key (AES-256-GCM, `src/storage/types.rs:483-498`).
- Card data is encrypted with that data key (`src/crypto/keymanager/internal_keymanager.rs:128-136`)
  and stored in `locker.enc_data`.
- `/data/retrieve` loads the key of the merchant named in the request
  (`src/crypto/keymanager/internal_keymanager.rs:19-41`), reads the row by reference, merchant and
  customer, and decrypts it with that key (`src/routes/data.rs:248-266`).
- `locker.enc_data` carries no associated data: nothing in the ciphertext names its merchant or
  customer.
- Existing e2e helpers already read `merchant` and `locker` rows and open them with `GcmAes256`
  (`merchant_keys`, `locker_data`, `opens`, `unlocked_master_key` in `tests/vault_e2e.rs`).

## Requirements

- **D1.** One e2e test stores cards for three merchants of the same tenant through `/data/add`,
  with one card number held by two merchants and other numbers held by one merchant only.
  Verifiable by: the test's row count per merchant, asserted before any isolation check.
- **D2.** In that test, each merchant's data key, opened with the unlocked master key, decrypts every
  row of that merchant, and each plaintext holds the card number that merchant stored.
  Verifiable by: an assertion per row in the same test.
- **D3.** In that test, every `locker` row opens under exactly one key among all merchant data keys
  plus the master key: its own merchant's key. On failure the message shows an OPENS / REFUSES
  matrix with merchant ids only, never a key or a card number.
  Verifiable by: the same test; seen failing when every merchant gets the same data key (D6).
- **D4.** A second e2e test copies one `locker` row of merchant A, in the database, under merchant B
  (same customer id, new reference), then asks `/data/retrieve` as merchant B for that reference.
  The vault refuses: a non-2xx status, and no stored card number in the response body. Before that,
  merchant B reads its own card through the same route (positive control).
  Verifiable by: the second test; seen failing when every merchant gets the same data key (D6).
- **D5.** No key, master key or card number is printed by either test, passing or failing.
  Verifiable by: key bytes compared only with `assert!`; failure messages built from merchant ids
  and statuses; `assert_no_secret` on the D4 response body.
- **D6.** Each new assertion is seen failing on a deliberate, temporary breakage in `src/` that
  reaches it, then green again once the breakage is undone. Breakage 1: every merchant gets the same
  data key (`src/domain/merchant.rs:35`), which must fail D3 and D4. Breakage 2: card data is
  encrypted with the master key instead of the merchant key, which must fail D2. `git diff main --
  src` is empty at the end.
  Verifiable by: the failing lines recorded in the plan's execution notes and in the PR body.
- **D7.** Row T13 becomes `proven`, cites the two tests and `src/domain/merchant.rs:33-36`, and
  states what is not covered. T13 is added to the list of rows proven by e2e tests. Every
  `file:line` reference moved by this change is fixed.
  Verifiable by: `scripts/check-threat-model.sh` exit code 0; a re-read of each cited range.
- **D8.** Nothing else regresses.
  Verifiable by: `cargo fmt --all --check`; `RUSTFLAGS="-D warnings" cargo clippy -j 4
  --all-features --all-targets`; `cargo test -j 4` with at least 77 passed; the e2e suite with
  `key_custodian` at "0 failed" and at least 33 passed; `make demo` printing `DEMO OK`; every CI job
  of the PR green.
- **D9.** README "Changes from the original" lists every file changed by this branch.
  Verifiable by: comparing the list with `git diff --name-only main`.

## Goals, non-goals, anti-goals

- Goal: prove T13 on the write side (each row is encrypted under its own merchant's key) and on the
  read side (the vault decrypts with the key of the merchant named in the request, so a row moved
  from another merchant is refused).
- Non-goal: T19 (any caller of a tenant can read any merchant's cards). Naming another merchant in
  the request is an access-control question, outside this ticket.
- Non-goal: binding ciphertexts to their merchant and customer with associated data. Without it, a
  row moved to another customer of the same merchant still opens. Recorded as a limit in T13.
- Non-goal: the external key manager mode. The tests run with the internal key manager only.
- Anti-goal: no change to `src/`, `migrations/`, `config/`, `scripts/`, `.github/`, `Cargo.*`.
- Anti-goal: no replayed breakage in CI (it would need `scripts/` and `.github/`); kept as an idea
  for later.

## Approaches considered

1. **Chosen: two e2e tests on the real vault and database.** The first reads rows written by the API
   and checks the key matrix; the second moves a row and reads it through the API. Each breakage
   reaches the assertion it targets.
2. Rejected: a plaintext scan of the whole database for the card number. It proves T1 (cards are
   encrypted at rest), which the demo already checks, not T13.
3. Rejected: bit-flip or tampered-ciphertext vectors. They test the AES-GCM library, not the vault.

## Design

Two `#[tokio::test]` functions in `tests/vault_e2e.rs`, after the existing tests of the same area.
Their names contain neither `rehash_` nor `rotation_`, so the fixed counts of the CI jobs
`rehash-without-custodian` and `rotation-without-custodian` stay valid. Working names:
`each_merchant_key_opens_only_its_own_cards` (D1 to D3) and
`card_moved_to_another_merchant_is_not_returned` (D4).

Both start with `let Some(admin) = admin_url() else { return };`, create a `TestDb`, generate
`Keys`, start the vault, unlock it, and reuse the existing helpers: `store_card_with_ref`,
`card_data_with`, `merchant_keys`, `locker_data`, `opens`, `unlocked_master_key`,
`retrieve_request`, `assert_no_secret`. Card numbers are public test numbers already used in the
file (`CARD_NUMBER`, `CARD_2`, `4012888888881881`).

The matrix test checks counts first (D1), then strict positives (D2), then the one-opener matrix
(D3). No assertion that the keys differ comes before D3, so breakage 1 reaches D3.

The transplant test inserts the copied row with SQL through `TestDb::exec`, keeping `enc_data`,
`hash_id` and the other columns, and changing only `merchant_id` and `locker_id`. The unique index on
`(hash_id, merchant_id, customer_id)` does not collide because merchant B does not hold that hash.

## Table changes planned (`docs/threat-model.md`)

- T13: status `proven`; Evidence: the two test names; Control: adds
  `src/domain/merchant.rs:33-36`. Limits written in the row: the honest case only (AES-GCM does not
  commit to its key, so a ciphertext built on purpose to open under two keys is not covered); no
  associated data (a row moved to another customer of the same merchant is not covered); the
  external key manager is not covered.
- The list of rows proven by end-to-end tests gains T13.

## Decisions for the owner

- **K1 (taken: A).** Add the transplanted-row read through the API (D4) to this ticket, so that T13
  is proven on read as well as on write. Option B (database-side proof only) was not chosen.
