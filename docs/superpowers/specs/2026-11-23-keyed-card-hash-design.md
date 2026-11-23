# Keyed card hash for the duplicate check: design

Date: 2026-11-23. Branch: `fix/keyed-card-hash` (from `main`, `7f3eb55`). Status: decisions I3 and I4
taken by the owner; implemented on this branch.

## Intent

`/data/add` detects a card that is already stored by looking up a hash of the card number in
`hash_table.data_hash`. That hash is a plain SHA-512 with no key. Once the issuer prefix and the check
digit are known, a card number has only about a billion candidates, so anyone who can read
`hash_table` can recover the numbers by trying them all, although the stored cards are encrypted.
Industry guidance (PCI SSC FAQs 1573 and 1308, requirement 3.5.1.1 of the v4 standard) asks for a
keyed hash of the whole number, with the key managed as a secret. This ticket replaces the plain hash
by a keyed one and proves it with tests. Callers of the API see no change. This is a study fork; see
`CLAUDE.md` for what may not be claimed about it.

Research report reused: the owner's 2026-11-23 research note on this ticket, kept outside the
repository (ideas I1, I2 and I5 adopted; I3 and I4 asked to the owner; I6 and I7 left for later).

## Current state (read in the code on 2026-11-23)

- The only place that computes the hash is `src/routes/data.rs:116`:
  `transformers::get_hash(&request.data, Sha512)`. `get_hash`
  (`src/routes/data/transformers.rs:83-104`) serialises the card number (or the caller's
  `enc_card_data` string) as JSON, so the hashed bytes are the number between double quotes, then
  calls `Encode::encode` on the algorithm it receives.
- Every other use of `data_hash` only carries the value: lookup (`src/routes/data.rs:122`,
  `src/domain/hash.rs:28`, `src/storage/db.rs:313`), insert (`src/domain/hash.rs:18`), cache
  (`src/storage/caching/hash_table.rs:20`), KV key name (`src/storage/kv/partition_key.rs:53`, hex of
  the hash). Checked with `grep -rn 'get_hash\|data_hash' src`.
- `hash_table` lives in each tenant's schema (`tenant_secrets.<tenant>.schema`), so the duplicate
  check spans one tenant and all its merchants. This scope is kept.
- The tenant master key is `config.tenant_secrets.master_key` (`src/config.rs:143`), 32 random bytes
  from `utils master-key`. Under `key_custodian`, a `TenantAppState` exists only after
  `/custodian/decrypt`, and then holds the decrypted key; without it, the key is read from the
  configuration. It already encrypts each merchant's data key (`internal_keymanager.rs`).
- `HmacSha512::<N>` (`src/crypto/hash_manager/managers/sha.rs:67-78`) signs the input, then signs the
  result N more times: `HmacSha512::<1>` computes `HMAC(K, HMAC(K, x))`. It is not plain HMAC-SHA512
  and cannot reproduce the published RFC 4231 test vectors. It is used only by the fingerprint route,
  which this ticket does not touch.
- `ring` 0.17.14 is already a dependency and provides both `ring::hmac` and `ring::hkdf`.

## Requirements

- **D1** `/data/add` stores, in `hash_table.data_hash`, a full 64-byte HMAC-SHA512 of the same bytes
  as today (JSON-serialised card number, or `enc_card_data`), no longer a plain SHA-512.
  Verifiable by: `grep -n 'Sha512)' src/routes/data.rs` returns nothing; e2e test D6b.
- **D2** The HMAC key is derived with HKDF-SHA512 from ring, from the tenant master key, with the
  context `info = "hyperswitch-card-vault/card-dedup/v1"` (idea I1). The derived key is never the
  master key itself and is never logged. (Source of the secret: I3.)
  Verifiable by: unit test "derived key differs from the master key".
- **D3** The HMAC is plain HMAC-SHA512 from `ring::hmac`, not truncated (idea I5).
  Verifiable by: unit test reproducing an RFC 4231 HMAC-SHA512 vector.
- **D4** Same number and same master key give the same hash; two different master keys (two tenants)
  give two different hashes; the hash differs from the plain SHA-512 of the number.
  Verifiable by: three unit tests.
- **D5** An empty master key is refused with an error instead of producing a hash (error case
  required by `CLAUDE.md`).
  Verifiable by: unit test on the error.
- **D6** End to end, against a real PostgreSQL: (a) the same card stored for two merchants of the
  same tenant creates exactly one `hash_table` row; (b) the stored `data_hash` differs from the plain
  SHA-512 of `4111111111111111`, computed in the test with `ring::digest`, both with and without the
  JSON quotes.
  Verifiable by: two new tests in `tests/vault_e2e.rs`, run with `VAULT_TEST_REQUIRE_DB=1`.
- **D7** No change visible to a caller: same routes, same request and response bodies, same
  `duplication_check` behaviour for cards stored after the change. `make demo` still prints `DEMO OK`.
  Verifiable by: existing tests and `make demo`.
- **D8** Docs: `docs/tokenization.md` no longer describes the hash as unkeyed and cites the new unit
  test and the `file:line` of the HMAC; `README.md` lists every changed file.
  Verifiable by: `grep -c 'unkeyed hash' docs/tokenization.md` returns 0; README check.

## Goals, non-goals, anti-goals

- Goal: a reader of `hash_table` alone can no longer test candidate card numbers.
- Non-goals (left for later): key rotation, a stored key version (I4), a change of
  duplicate-check scope (I6), stable identity across key versions (I7), the fingerprint route.
- Anti-goals: hand-written cryptography; wrapping the old SHA-512 in an HMAC; truncating the hash;
  any change to `config/`, `Cargo.toml`, `Cargo.lock` or the existing migrations without approval.

## Approaches considered

- Key source: derived from the tenant master key by HKDF with a versioned context (recommended for
  I3) versus a dedicated secret in the configuration (needs a `config/` change) versus a random
  per-tenant key stored encrypted under the master key (needs a new table and a migration; kept as
  the exit path for a master key change). Chosen by the owner: the first. See I3.
- HMAC primitive: the existing `HmacSha512::<1>` (rejected: it signs twice, so it is not the standard
  construction and no published vector can check it) versus `ring::hmac` called once (chosen; it is
  the same library the existing type wraps).
- Where the key is derived: once per tenant when its state is built (rejected: touches tenant start-up
  and the custodian unlock path for a saving of microseconds) versus on each `/data/add` call (chosen:
  HKDF costs a few HMAC operations, and the change stays in the add path).
- Hash input: keep today's bytes (JSON-serialised number) (chosen: smallest change, the key is what
  closes the gap) versus hashing the bare digits (no security gain, and it widens the change).

## Design

- New type in `src/crypto/hash_manager/managers/sha.rs`, for example `CardDedupHmac`, holding the
  derived key as a `Secret`. Constructor `from_master_key(&Secret<Vec<u8>>)`: refuses an empty key,
  then runs `ring::hkdf::Salt::new(HKDF_SHA512, &[])`, `extract(master_key)`,
  `expand(&[CARD_DEDUP_INFO], HKDF_SHA512)` and fills a 64-byte key. It implements
  `Encode<Vec<u8>, Vec<u8>>` with one `ring::hmac::sign(HMAC_SHA512, …)`, so `get_hash` keeps its
  signature.
- `src/routes/data.rs:116` becomes `get_hash(&request.data, CardDedupHmac::from_master_key(...)?)`,
  reading `tenant_app_state.config.tenant_secrets.master_key`. The `Sha512` type stays in place
  (public, still documented) but is no longer used by the route.
- No new dependency, no migration, no configuration change.

## Existing `hash_table` rows

Rows written before this change hold plain SHA-512 values. After it, no lookup can match them:

- A card stored before the change and added again gets a new `hash_table` row. For the same merchant
  and customer, a second `locker` row is created and `duplication_check` is not returned, because the
  unique index is on `(hash_id, merchant_id, customer_id)` and the `hash_id` is new.
- The old rows keep their plain SHA-512 values, readable by anyone who reads the table, until they are
  deleted. Cached copies (Redis, in-memory) expire with their TTL and are never hit again.
- This fork holds no real card, so no migration is written. A real deployment would need a one-off job
  that decrypts each `locker` row, recomputes the keyed hash, rewrites `hash_table` and then deletes
  the plain values; that job is out of scope and is described in `docs/tokenization.md`.

## Note found in review

With the `external_key_manager` feature enabled, `tenant_secrets.master_key` no longer encrypts the
cards (`src/crypto/keymanager.rs:59-67`) but is still required and still feeds this derivation. It
must therefore stay a real secret in that mode too; `docs/tokenization.md` says so.

## Decisions for the owner

- **I3** source of the secret: **the tenant master key** (owner, 2026-11-23). No new configuration,
  and the secret stays behind the two custodians. Known consequence: a future change of master key
  would change every hash. Exit path for that day, without recomputing any hash: freeze the dedup key
  in use, store it encrypted under the new master key (envelope pattern, as for merchant keys), and
  derive from it from then on. A dedicated secret in `config/` was rejected: it would sit in clear in
  the configuration, outside the custodians' protection.
- **I4** store a key version with the hash: **no, not now** (owner, 2026-11-23). The version is
  already in the HKDF context (`card-dedup/v1`). It can be added later at no loss: every v1 hash is
  exactly 64 bytes, so a future version can prefix one version byte (65 bytes) and any hash without a
  prefix is read as v1. A `key_version` column was rejected (needs a migration for the same benefit).

## Left to the builder

- Exact type and constant names; test names; the RFC 4231 test case used (case 2, "what do ya want
  for nothing?", is short and printable).
