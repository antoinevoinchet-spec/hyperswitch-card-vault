# Keyed Card Hash Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the plain SHA-512 stored in `hash_table.data_hash` by a full HMAC-SHA512 whose key is
derived by HKDF from the tenant master key, without changing what an API caller sees.

**Architecture:** A new type `CardDedupHmac` next to the existing hash types derives its key once per
`/data/add` call and implements the existing `Encode<Vec<u8>, Vec<u8>>` trait, so `get_hash` keeps its
signature and only the call site in `src/routes/data.rs` changes. No dependency, configuration or
migration change.

**Tech Stack:** Rust, `ring` 0.17.14 (`ring::hkdf`, `ring::hmac`, `ring::digest`), diesel, PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-11-23-keyed-card-hash-design.md`

## Global Constraints

- HKDF context, byte for byte: `hyperswitch-card-vault/card-dedup/v1`. HKDF salt: empty. Hash: SHA-512.
  Derived key length: 64 bytes.
- HMAC output: 64 bytes, never truncated, no version prefix (I4).
- Hashed input unchanged: the bytes `get_hash` already builds (JSON-serialised card number or
  `enc_card_data`).
- No hand-written cryptography; no change to `config/`, `migrations/`, `Cargo.toml`, `Cargo.lock`,
  `.github/`, `.env`, `CLAUDE.md`, `.typos.toml`.
- Test data only: card `4111111111111111`, keys from `generate_aes256_key()` (the generator behind
  `utils master-key`) or `utils master-key`, and RFC 4231 vectors. Never print a key.
- Everything written in the repository is in English; no compliance claim (see `CLAUDE.md`).
- Unchanged by this plan: `Sha512`, `HmacSha512`, the fingerprint route, the duplicate-check scope
  (one tenant). If any step seems to need a `Cargo.toml` change, a migration or a `config/` change,
  stop and ask the owner.
- Every cargo command is prefixed with `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"`
  and runs with `-j 4`.

## Review Focus

1. Locked vault (`key_custodian`): `/data/add` must not compute a hash from the still-encrypted master
   key. Expected: unreachable, since `TenantAppState` exists only after `/custodian/decrypt`; the e2e
   tests store cards only after `unlock`, and the reviewer checks `src/tenant.rs` keeps that order.
2. Empty or missing master key: refused with an error, never a hash keyed by nothing (Task 1 test
   `card_dedup_rejects_empty_master_key`).
3. The derived key or the hash appearing in a log: `CardDedupHmac` holds its key in a `Secret` and has
   no `Debug` or `Display` that prints it (reviewer check; no log line is added).
4. `enc_card_data` requests (no `card` object): hashed with the same keyed function, so duplicates are
   still found (Task 2 e2e test stores a card; the reviewer checks the `EncData` branch of `get_hash`
   is untouched).
5. Same card, same merchant and customer, added twice after the change: response keeps
   `duplication_check` (`duplicated`) as before (Task 2 test `same_card_for_two_merchants_shares_one_hash_row`
   also re-adds for the first merchant and checks it).

---

### Task 0: starting point

**Covers:** R1, R2, R7, D6

- [ ] **Step 1:** `git branch --show-current` → `fix/keyed-card-hash`;
  `git merge-base --is-ancestor 7f3eb55 fix/keyed-card-hash` → exit 0; `git log --oneline -- docs/superpowers/specs`
  shows the design commit.
- [ ] **Step 2:** `cargo test -j 4` on the branch before any code change; record the number of tests
  passed (baseline B). Target after the change: B + 7 unit tests, and at least 34. If B + 7 < 34,
  stop and tell the owner instead of adding filler tests.
- [ ] **Step 3:** start the throwaway PostgreSQL 14 cluster in the session scratchpad
  (`SCRATCH` = the session scratchpad directory; port 54331):
  `initdb -D $SCRATCH/pg -U vault --auth=trust -E UTF8`, then
  `pg_ctl -D $SCRATCH/pg -l $SCRATCH/pg.log -o "-p 54331 -k '' -c listen_addresses=127.0.0.1" -w start`.
  It runs until the end of Task 3, which stops and deletes it.
- [ ] **Step 4:** commit this plan (the design is already committed): `docs: implementation plan for the keyed card hash`.

### Task 1: `CardDedupHmac` with its unit tests

**Covers:** D2, D3, D4, D5

**Files:**
- Modify: `src/crypto/hash_manager/managers/sha.rs` (new type, constant, private helper, tests in the
  existing `mod tests`)

**Interfaces:**
- Produces:
  - `pub const CARD_DEDUP_INFO: &[u8] = b"hyperswitch-card-vault/card-dedup/v1";`
  - `pub struct CardDedupHmac(Secret<Vec<u8>>);` (derived key, 64 bytes)
  - `impl CardDedupHmac { pub fn from_master_key(master_key: &Secret<Vec<u8>>) -> Result<Self, error::ContainerError<error::CryptoError>> }`
    — empty key → `CryptoError::InvalidData("empty master key")`.
  - `impl Encode<Vec<u8>, Vec<u8>> for CardDedupHmac` with
    `type ReturnType<T> = Result<T, error::ContainerError<error::CryptoError>>;`
  - private `fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8>` (one `ring::hmac::sign`).

- [ ] **Step 1: Add the skeleton with `todo!()` bodies** so the tests compile and each fails on its own:
  the constant, the struct, `from_master_key`, `encode` and `hmac_sha512`, all bodies `todo!()`.

- [ ] **Step 2: Write the seven tests** in `mod tests` of `sha.rs`:

```rust
#[test]
fn hmac_sha512_matches_rfc4231_case_2() {
    let expected = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                    9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
    assert_eq!(hex::encode(hmac_sha512(b"Jefe", b"what do ya want for nothing?")), expected);
}

#[test]
fn card_dedup_same_card_same_key_gives_same_hash() {
    let key = Secret::new(generate_aes256_key().to_vec());
    let a = CardDedupHmac::from_master_key(&key).unwrap().encode(CARD.to_vec()).unwrap();
    let b = CardDedupHmac::from_master_key(&key).unwrap().encode(CARD.to_vec()).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
}

#[test]
fn card_dedup_two_master_keys_give_two_hashes() {
    let k1 = Secret::new(generate_aes256_key().to_vec());
    let k2 = Secret::new(generate_aes256_key().to_vec());
    let a = CardDedupHmac::from_master_key(&k1).unwrap().encode(CARD.to_vec()).unwrap();
    let b = CardDedupHmac::from_master_key(&k2).unwrap().encode(CARD.to_vec()).unwrap();
    assert_ne!(a, b);
}

#[test]
fn card_dedup_differs_from_plain_sha512_and_from_master_key() {
    let key = Secret::new(generate_aes256_key().to_vec());
    let algo = CardDedupHmac::from_master_key(&key).unwrap();
    let quoted = [b"\"", CARD, b"\""].concat();
    let hash = algo.encode(quoted.clone()).unwrap();
    let sha = |d: &[u8]| ring::digest::digest(&ring::digest::SHA512, d).as_ref().to_vec();
    assert_ne!(hash, sha(CARD));
    assert_ne!(hash, sha(&quoted));
    assert_eq!(algo.0.peek().len(), 64);
    assert!(algo.0.peek() != key.peek()); // no key printed on failure
}

#[test]
fn card_dedup_key_is_hkdf_of_master_key_with_context() {
    // Recomputes the expected key with ring::hkdf (empty salt, CARD_DEDUP_INFO, 64 bytes) and checks
    // algo.0 equals it, and that algo.encode(x) == hmac_sha512(algo.0.peek(), x). Catches a missing
    // or empty `info` and the master key used directly. Compare with assert!(a == b) so no key is
    // printed on failure.
}

#[test]
fn card_dedup_context_is_versioned_and_specific() {
    assert_eq!(CARD_DEDUP_INFO, b"hyperswitch-card-vault/card-dedup/v1");
}

#[test]
fn card_dedup_rejects_empty_master_key() {
    assert!(CardDedupHmac::from_master_key(&Secret::new(Vec::new())).is_err());
}
```

  `const CARD: &[u8] = b"4111111111111111";` in the test module; `generate_aes256_key` from
  `crate::crypto::encryption_manager::managers::aes`.

- [ ] **Step 3: Run, expect six failures and one pass**

Run: `cargo test -j 4 --lib -- card_dedup hmac_sha512_matches`
Expected: the 6 behaviour tests FAIL (panic `not yet implemented`); the constant test passes as soon
  as the constant exists (it pins the value, it has nothing to implement). Record which failed.

- [ ] **Step 4: Implement** `hmac_sha512` with `ring::hmac::{Key::new(HMAC_SHA512, key), sign}`;
  `from_master_key` with `ring::hkdf::Salt::new(HKDF_SHA512, &[]).extract(master).expand(&[CARD_DEDUP_INFO], HKDF_SHA512)?.fill(&mut [0u8; 64])`,
  mapping a ring error to `CryptoError::InvalidData("hkdf")`; `encode` calls `hmac_sha512(self.0.peek(), &input)`.

- [ ] **Step 5: Run, expect seven passes**, then `cargo fmt --all` and `cargo test -j 4` → exit 0, B + 7 passed.

- [ ] **Step 6: Commit** `sha.rs`: `feat(crypto): add CardDedupHmac, an HKDF-derived HMAC-SHA512 for the duplicate check`.

### Task 2: use the keyed hash in `/data/add`, prove it end to end

**Covers:** D1, D6, D7

**Files:**
- Modify: `src/routes/data.rs:16` (import) and `:115-118` (call site); `src/routes/data/transformers.rs` (tests only)
- Test: `tests/vault_e2e.rs` (helper + two tests)

**Interfaces:**
- Consumes: `CardDedupHmac::from_master_key`, `impl Encode<Vec<u8>, Vec<u8>>` (Task 1).

- [ ] **Step 1: Write the two e2e tests** in `tests/vault_e2e.rs`. Turn `store_card(vault)` into
  `store_card_for(vault, merchant) -> (String, serde_json::Value)` (reference + full response) and keep
  `store_card` as a wrapper. Add a `QueryableByName` row with `data_hash: Binary` and a
  `TestDb::data_hashes() -> Vec<Vec<u8>>` (`SELECT data_hash FROM hash_table`).
  - `same_card_for_two_merchants_shares_one_hash_row`: store for `MERCHANT`, then for
    `"demo-merchant-2"`, then again for `MERCHANT` with the same `CUSTOMER` as the first call; assert `db.data_hashes().len() == 1` and the third
    response has `payload.duplication_check == "duplicated"`.
  - `stored_card_hash_is_not_a_plain_sha512`: store once; read the single `data_hash`; assert its
    length is 64 and it differs from `ring::digest::digest(&SHA512, CARD_NUMBER.as_bytes())` and from
    the digest of `format!("\"{CARD_NUMBER}\"")` (the bytes the old code hashed).

- [ ] **Step 2: Run them before the change** with the throwaway PostgreSQL 14 cluster started in Task 0,
  Step 3:
  `VAULT_TEST_REQUIRE_DB=1 VAULT_TEST_DATABASE_URL=postgres://vault@127.0.0.1:54331/postgres cargo test -j 4 --features key_custodian --test vault_e2e`
  Expected: `stored_card_hash_is_not_a_plain_sha512` FAILS (the stored value equals the digest of the
  quoted number); `same_card_for_two_merchants_shares_one_hash_row` passes (it guards behaviour that
  already works and must survive the change; reported to the owner as a non-regression test, not a
  test seen failing).

- [ ] **Step 3: Change the call site**: `transformers::get_hash(&request.data, CardDedupHmac::from_master_key(&tenant_app_state.config.tenant_secrets.master_key)?)`
  with the error mapped to `ApiError::EncodingError`, as today; drop the `Sha512` import.
  Check: `grep -n 'Sha512)' src/routes/data.rs` → no line.

- [ ] **Step 4: Run** the e2e command again → 6 passed, exit 0; `cargo test -j 4` → exit 0.

- [ ] **Step 4b: Unit test for the `enc_card_data` branch** in `src/routes/data/transformers.rs`
  (`mod tests`): `get_hash` with `CardDedupHmac` on `Data::EncData` gives 64 bytes, is stable for the
  same input and key, and differs from the `Data::Card` hash of the same string. Covers D1.
- [ ] **Step 5: Commit** `src/routes/data.rs`, `src/routes/data/transformers.rs` and `tests/vault_e2e.rs`:
  `fix(data): key the duplicate-check hash with the tenant master key`.

### Task 3: docs, demo and full verification

**Covers:** D7, D8

**Files:**
- Modify: `docs/tokenization.md` (bullet "The duplicate check keeps…" → moved to what the vault does,
  citing `CardDedupHmac` `file:line`, the test `card_dedup_two_master_keys_give_two_hashes`, and the
  fate of existing rows from the design), `README.md` ("Changes from the original": new group listing
  `src/crypto/hash_manager/managers/sha.rs`, `src/routes/data.rs`, `tests/vault_e2e.rs`,
  `docs/tokenization.md`, the design and this plan), design status line.

- [ ] **Step 1: Update the docs** (after `cargo fmt`, so the cited `file:line` is final). Check:
  `grep -c 'unkeyed hash' docs/tokenization.md` → 0 and `grep -r -i -n -E 'unkeyed|plain SHA-512' docs/tokenization.md`
  shows only text about the old behaviour or existing rows. The fate of existing rows is stated as
  "read in the code, not tested", and the page notes that a change of master key would change every
  hash (design, I3);
  every path of `git diff --name-only main` except `README.md` appears in `README.md`; the forbidden
  compliance phrases from `CLAUDE.md` do not appear in added lines:
  `git diff main -- . ':!docs/superpowers' | grep '^+' | grep -inE 'compliant|compliance|certified|production-ready'`
  → nothing, then a manual read of the design and plan, of every added mention of PCI, of the commit
  messages and of the PR text.
- [ ] **Step 2: Full verification**: `cargo build -j 4` → 0; `cargo test -j 4` → 0, baseline + 6 passed (at least 34);
  e2e command → 0, ≥ 6 passed; `make demo` → `DEMO OK`; `cargo clippy --all-features --all-targets -j 4`
  → no warning in changed files; `cargo fmt --all --check` → 0; `git diff --name-only main -- config migrations Cargo.toml Cargo.lock .github .env CLAUDE.md .typos.toml LICENSE` → empty.
- [ ] **Step 3: Commit** the docs: `docs: describe the keyed duplicate-check hash`.
- [ ] **Step 4: Reviews** before calling it ready: a fresh `opus` subagent (owner's request verbatim,
  the diff, the completion criteria) and `second-avis --reserve 50`, in parallel; fix what changes the
  result.
- [ ] **Step 5: Close the loop**: commit review fixes; check every `file:line` cited in
  `docs/tokenization.md` still points at the cited code; rerun the README check (R12), the protected
  paths check (R14) and `cargo fmt --all --check`; stop and delete the throwaway cluster;
  `git status --porcelain` → empty.
- [ ] **Step 6: Push and PR** only after the owner's yes (DOING / EXPECT / IF WRONG): `git push -u origin
  fix/keyed-card-hash`, `gh pr create -R antoinevoinchet-spec/hyperswitch-card-vault --base main`,
  then `gh pr checks <n> -R antoinevoinchet-spec/hyperswitch-card-vault --watch`; report every job.
  Check `gh pr list -R juspay/hyperswitch-card-vault --author antoinevoinchet-spec --state all` → empty.
