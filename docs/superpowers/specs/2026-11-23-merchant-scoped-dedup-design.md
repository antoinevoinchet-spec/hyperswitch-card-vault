# Merchant-scoped duplicate-check hash (I6): design

Date: 2026-11-23. Branch: `feat/merchant-scoped-dedup` (from `main`, `dcbe7c1`). Status: draft;
decision S1 taken by the owner (merchant and customer); S2 and S3 not taken yet.

## Intent

`/data/add` keeps one row in `hash_table` per card and per tenant, shared by every merchant and
customer of that tenant. Someone who reads the database cannot recover the card number (the hash is
keyed since the previous ticket), but can see that two merchants hold the same card, because their
`locker` rows carry the same `hash_id` (threat T24, `open`). The response time of an add also
differs when another merchant or customer of the tenant already stored the card (T25, `open`).

This ticket narrows the scope of the hash so that the same card gives different hashes for
different merchants (and, depending on S1, customers), proves it with tests that fail on `main`,
and updates the threat model table. Callers of the API see no change. This is a study fork; see
`CLAUDE.md` for what may not be claimed about it.

Research reused: the owner's 2026-11-23 research note after the threat model table (ideas I1 and
I2), kept outside the repository. Comparable product, read on 2026-11-23: Stripe documents a card
fingerprint that is unique per account by default; a platform-wide value is a separate, opt-in view
for the platform itself (https://support.stripe.com/questions/how-can-i-detect-duplicate-cards-or-bank-accounts,
https://docs.stripe.com/changelog/2018-01-23/connect-platforms-identify-reused-cards-bank-accounts).
A per-merchant scope is therefore the common default, not an unusual restriction.

## Current state (read in the code on 2026-11-23)

- The hash is computed once, in `add_card_inner` (`src/routes/data.rs:116-122`):
  `CardDedupHmac::from_master_key(master_key)` derives a 64-byte key with HKDF-SHA512 (`ring`),
  info `hyperswitch-card-vault/card-dedup/v1` (`src/crypto/hash_manager/managers/sha.rs:82`,
  `:93-108`), then `get_hash` computes one HMAC-SHA512 of the JSON-serialised card number
  (`src/routes/data/transformers.rs:83-104`). No other code computes it (checked with
  `grep -r -n -E 'CardDedupHmac|get_hash\(' src`).
- Lookup by `data_hash` (`src/routes/data.rs:124-127`). If found, the vault looks for a `locker`
  row with that `hash_id` **and the same merchant and customer** (`src/routes/data.rs:135-142`):
  found means `duplicated` or `meta_data_changed`; not found means encrypt and insert with the
  shared `hash_id`. If the hash is not found, a new `hash_table` row is inserted first
  (`src/routes/data.rs:172-184`).
- Consequence: the shared `hash_table` row has no effect a caller can see. `duplication_check` is
  only ever returned for the same merchant and the same customer. Sharing the row across merchants
  and customers only saves rows and creates the link of T24 and the time difference of T25.
- `hash_table.data_hash` is unique (`migrations/2023-10-26-072935_duplication-table/up.sql:7`), and
  `locker` has a unique index on `(hash_id, merchant_id, customer_id)`
  (`migrations/2026-07-13-150329-0000_add_locker_hash_id_merchant_id_customer_id_index/up.sql:1`).
  Neither needs to change: a narrower hash only creates more distinct values.
- `tests/vault_e2e.rs` has `same_card_for_two_merchants_shares_one_hash_row`, which asserts one row
  for two merchants: the opposite of this ticket's goal. It is replaced.

## Requirements

- **D1** The duplicate-check key is derived with HKDF-SHA512 (`ring`) from the tenant master key and
  an info value made of a new versioned context `hyperswitch-card-vault/card-dedup/v2` followed by
  the scope ids (merchant id, and customer id if S1 = A). The hash stays one HMAC-SHA512 of the same
  bytes as today, 64 bytes, not truncated.
  Verifiable by: unit test recomputing the key with `ring::hkdf` from the master key and the
  expected info, and comparing; unit test pinning the context string to `v2`.
- **D2** Same card, same master key, two different merchant ids: two different hashes. Same card,
  same master key, same merchant (and customer): the same hash.
  Verifiable by: unit test in `sha.rs` that does not compile on `main` (the constructor takes no
  scope there), shown failing before the code.
- **D3** (if S1 = A) Same card, same merchant, two customers: two different hashes.
  Verifiable by: unit test in `sha.rs`.
- **D4** The scope ids are framed so that two different scopes can never produce the same info
  value: each id is preceded by its length as 8 bytes, big-endian. For example merchant `ab` with
  customer `c` and merchant `a` with customer `bc` give different hashes.
  Verifiable by: unit test that fails if the length prefix is removed.
- **D5** Error case: an empty master key is still refused (existing test kept and adapted).
  Verifiable by: `card_dedup_rejects_empty_master_key`.
- **D6** End to end against a real PostgreSQL: the same card stored for two merchants of one tenant
  creates two `hash_table` rows; a second add by the same merchant and the same customer returns
  `duplication_check` = `duplicated` and creates no extra row.
  Verifiable by: the e2e test that replaces `same_card_for_two_merchants_shares_one_hash_row`, run
  with `VAULT_TEST_REQUIRE_DB=1`; it fails on `main` (one row instead of two).
- **D7** (T25, depends on S1 and S3) End to end: an add of a card known only to another merchant
  (and, if S1 = A, another customer of the same merchant) inserts a new `hash_table` row, so it
  takes the same code path as a card the tenant has never seen.
  Verifiable by: e2e test counting `hash_table` rows before and after that add; it fails on `main`.
- **D8** The stored value is still the keyed hash recomputed from the unlocked master key, now with
  the scope.
  Verifiable by: `stored_card_hash_is_not_a_plain_sha512`, adapted to pass the scope.
- **D9** No change visible to a caller: same routes, bodies and `duplication_check` behaviour for
  cards stored after the change; no migration, no configuration change, no new dependency (unless
  S3 = B).
  Verifiable by: `cargo test -j 4`, the e2e suite, `make demo` printing `DEMO OK`, and
  `git diff --name-only main -- demo config migrations src/storage/schema.rs Cargo.toml Cargo.lock`
  returning nothing.
- **D10** The threat model table and `docs/tokenization.md` describe the state after I6; every
  moved `file:line` is corrected and reread; `README.md` lists every changed file.
  Verifiable by: `scripts/check-threat-model.sh` exit code 0; rows listed under "Table changes".

## Goals, non-goals, anti-goals

- Goal: a reader of the database can no longer tell, from `hash_table` or `locker.hash_id`, that two
  merchants (and, with S1 = A, two customers) of one tenant hold the same card, for rows written
  after this change.
- Non-goals: converting rows written before this change (see S2); key rotation; the fingerprint
  route; per-caller access rules (T19).
- Anti-goals: hand-written cryptography; any change to `migrations/`, `src/storage/schema.rs`,
  `config/`, `Cargo.toml` or `Cargo.lock` without approval; a lookup that tries the new hash then
  the old one (it would keep the old link and the time difference alive).

## Approaches considered

- Where the scope enters: in the HKDF info (chosen; one key per scope, as the owner's brief allows,
  and the HMAC input bytes stay unchanged) versus in the HMAC input with one tenant key (same
  strength, but it changes the hashed bytes and the existing `get_hash` test). Both use only `ring`.
- Framing of the ids: length prefix before each id (chosen; the usual way to make a concatenation
  unambiguous) versus a separator byte (fails if an id contains that byte; ids are free text up to
  255 characters).
- Context: new `v2` label (chosen; makes the change of derivation explicit and keeps `v1` meaning
  "tenant-wide") versus keeping `v1` with a longer info (the old values would still never match, but
  the label would lie).

## Design

- `src/crypto/hash_manager/managers/sha.rs`: `CARD_DEDUP_INFO` becomes the `v2` context.
  `CardDedupHmac::from_master_key(master_key, merchant_id[, customer_id])` refuses an empty master
  key, then calls `expand` with the info parts `[CARD_DEDUP_INFO, len(merchant), merchant[,
  len(customer), customer]]` (`ring` concatenates the parts). `Encode` is unchanged.
- `src/routes/data.rs`: `add_card_inner` passes `request.merchant_id` (and
  `request.merchant_customer_id`) to the constructor. Nothing else in the add path changes.
- `src/routes/data/transformers.rs`: its unit test passes a scope.
- `src/domain/hash.rs`: no change needed.
- No new dependency, no migration, no configuration change.

## Rows written before this change (decision S2)

Every value stored under `v1` is tenant-wide. After the change, no lookup can match it:

- A card stored before the change and added again by the same merchant and customer gets a new
  `hash_table` row and a second `locker` row, without `duplication_check`, because the unique index
  is on `(hash_id, merchant_id, customer_id)` and the `hash_id` is new.
- The old `locker` rows keep their shared `hash_id`, so the link of T24 stays readable for them
  until they are deleted. The old `hash_table` rows stay too; they are keyed, so they reveal no card
  number.
- Cached copies (Redis, in-memory) expire with their TTL and are never hit again.
- A real deployment would need a one-off job that decrypts each `locker` row, recomputes the scoped
  hash, gives the row its own `hash_table` row, then deletes the old rows. Not written here unless
  the owner decides otherwise (S2).

## Time difference (T25, decision S3)

- With scope merchant and customer (S1 = A), an add of a card known only to anyone else computes a
  hash that is not in the table, so it takes exactly the new-card path. The branch "hash found, no
  `locker` row" remains only when the same merchant and customer stored the card before and deleted
  it (the delete removes the `locker` row, not the `hash_table` row): it tells callers about their
  own past, not about others.
- With scope merchant only (S1 = B), the branch remains for a card known to another customer of the
  same merchant: T25 stays open for that case.
- The time itself is not measured unless S3 = B. D7 proves the code path, not the clock.

## Table changes planned (`docs/threat-model.md`)

- T9, T10: `file:line` in `sha.rs` and `data.rs` move; tests unchanged or renamed accordingly.
- T11: evidence becomes the new e2e test of D6 and the unit test of D2 (same scope, same hash).
- T24: control = scoped derivation (`sha.rs`, `data.rs` lines); evidence = D2 and D6 tests; status
  `proven` for rows written after the change.
- New row T28 (`open`): rows written before the change keep the shared `hash_id` (link of T24) and
  are not matched any more (duplicate not detected); evidence = the `docs/tokenization.md` lines.
- T25: depends on S1 and S3 (see the decisions below).
- T21, T22: wording reread; only their `docs/tokenization.md` line ranges may move.

## Decisions for the owner

- **S1** scope: **merchant and customer** (owner, 2026-11-23; option A). Option B, merchant only,
  was rejected. Reasoning given to the owner: A closes T24
  also between customers of one merchant and leaves no T25 branch about others; it loses nothing a
  caller sees, since `duplicated` is already only reported for the same merchant and customer. Cost:
  one `hash_table` row per card, merchant and customer instead of per card and tenant.
- **S2** rows written under `v1`: **A, no migration, documented** (recommended; the fork holds no
  real card, and migrations are out of scope) or **B, write the one-off conversion job**.
- **S3** T25: **A, prove the code path end to end (D7), keep "time not measured" written in the
  row** (recommended) or **B, add `tacet` as a development dependency and measure** (new dependency,
  timing tests on shared CI machines) or **C, leave T25 `open` as it is**.

## Left to the builder

- Exact test names; the helper added to `tests/vault_e2e.rs` to store a card for a given merchant
  and customer.
