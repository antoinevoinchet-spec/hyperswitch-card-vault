# Threat model

This is a study fork: see [CLAUDE.md](../CLAUDE.md) for what may and may not be said about it. This
page lists what the vault protects against, how each protection is proven, and what is still open.
It adds no feature.

Each row gives a **threat** (what could go wrong), the **attack** that would exploit it (in prose,
never as a command), the **control** in the code (`file:line` on this branch, or `none`), the
**evidence** (a test name, a check printed by `make demo`, or the lines that describe a limit) and a
**status**:

- `proven`: a test or a demo check fails if the control stops working;
- `not tested`: the control exists in the code, but no test proves it;
- `open`: a known limit, not addressed.

## How to check it yourself

- Unit tests: `cargo test -j 4`.
- End-to-end tests (cited in T2 to T6, T9, T11, T24), against a real PostgreSQL:
  `VAULT_TEST_DATABASE_URL=<admin URL> VAULT_TEST_REQUIRE_DB=1 cargo test -j 4 --features key_custodian --test vault_e2e`.
  Without these two variables, they are skipped and still reported as passed.
- Demo checks: `make demo` (last line `DEMO OK`).
- Every reference in this table exists: `scripts/check-threat-model.sh`.

The end-to-end tests and the demo also run on every pull request, in the CI job "End-to-end tests and
demo against PostgreSQL". The script above runs in the CI job "Threat model references". It proves
that each cited test, line and demo check exists, not that it says what the row claims: open the
reference to check that.

## The table

| ID | Threat | Attack | Control | Evidence | Status |
|---|---|---|---|---|---|
| T1 | Card numbers read from a copy of the database. | Someone with a backup or read access to PostgreSQL reads the stored card rows. | Card data is encrypted with AES-256-GCM under the merchant key before insert (`src/crypto/keymanager/internal_keymanager.rs:128-136`). | demo check "locker rows while the card was stored" (at least 1 row, 0 containing the card number in clear); `test_gcm_aes_256_encode_message`, `test_gcm_aes_256_decode_message` | proven |
| T2 | One custodian alone, or a wrong key, unlocks the vault. | A custodian sends their own key and a guessed second key, then asks the vault to unlock. | Unlock needs both keys (`src/routes/key_custodian.rs:161-170`) and AES-GCM decryption of the master key fails on a wrong key (`src/routes/key_custodian.rs:228-236`). | `custodian_steps_write_audit_rows` (wrong key 2: unlock refused), `custodian_key_is_refused_when_audit_table_is_unwritable` (key 1 missing: unlock refused) | proven |
| T3 | A card leaves the vault without a trace. | An insider makes the audit table unwritable, then reads cards. | The audit row is written before the response; if it fails, the card is withheld and HTTP 500 is returned (`src/audit.rs:213-238`, called on retrieve at `src/routes/data.rs:241`). | `retrieve_fails_closed_when_audit_table_is_unwritable`, `record_fails_closed_when_sink_fails` | proven |
| T4 | A custodian key is held without a trace. | An insider makes the audit table unwritable before sending a custodian key. | The key is kept only after its audit row is written (`src/routes/key_custodian.rs:72-84`). | `custodian_key_is_refused_when_audit_table_is_unwritable` | proven |
| T5 | The audit log leaks the card number. | Someone with read access to the audit log, or to its exports, collects card numbers from it. | Entries hold only ids, outcome and status, never the request body (`src/audit.rs:114-126`, `src/audit.rs:241-249`). | `store_card_entry_never_contains_card_number`, `store_data_entry_never_contains_payload`, `audit_row_is_written_for_each_card_step`; demo check "audit rows containing the card number" (0) | proven |
| T6 | The audit log leaks a key. | Someone with read access to the audit log collects custodian, master or fingerprint keys from it. | Custodian and fingerprint entries take nothing from the request (`src/audit.rs:277-279`, `src/routes/key_custodian.rs:74-79`). | `custodian_steps_write_audit_rows` (no key in any row), `fingerprint_entry_has_no_payload`; demo check "generated key values found in this output" (0) | proven |
| T7 | A card number chosen by the caller as an id reaches the audit log. | A caller sends a card number as merchant, customer or card reference id. | Ids that look like a card number (13 to 19 digits passing the Luhn check) are stored as redacted (`src/audit.rs:66-96`, `src/audit.rs:101-108`). | `pending_redacts_card_shaped_ids` | proven |
| T8 | Free text or control characters are injected into the audit log. | A caller puts text, a NUL byte or a very long id in a header or an id field to forge or break log rows. | Request ids are kept only if they are UUIDs; ids lose control characters and are cut to 255 characters (`src/audit.rs:59-62`, `src/audit.rs:101-108`). | `parse_request_id_rejects_non_uuid`, `pending_strips_control_characters`, `pending_truncates_long_ids` | proven |
| T9 | Card numbers recovered from the duplicate-check hash. | With the former unkeyed SHA-512, anyone who could read the hash table could try every possible card number (about a billion once the issuer prefix and check digit are known) until a hash matched. | The hash is now one HMAC-SHA512 under a secret key (`src/crypto/hash_manager/managers/sha.rs:111-117`), used by the add route (`src/routes/data.rs:116-122`). | `stored_card_hash_is_not_a_plain_sha512`, `card_dedup_differs_from_plain_sha512_and_from_master_key`, `hmac_sha512_matches_rfc4231_case_2` | proven |
| T10 | The duplicate-check key is shared between tenants, or equals another key. | Someone who learns one tenant's hashes, or the key that encrypts merchant keys, uses it to compute another tenant's hashes. | The key is derived with HKDF-SHA512 from each tenant's master key and a context used only here (`src/crypto/hash_manager/managers/sha.rs:82`, `src/crypto/hash_manager/managers/sha.rs:93-108`). | `card_dedup_two_master_keys_give_two_hashes`, `card_dedup_key_is_hkdf_of_master_key_with_context`, `card_dedup_context_is_versioned_and_specific`, `card_dedup_rejects_empty_master_key` | proven |
| T11 | The keyed hash breaks the duplicate check. | A card stored twice gets two hash rows, so duplicates are no longer detected. | Same card and same key give the same hash, looked up before insert (`src/routes/data.rs:124-127`). | `same_card_for_two_merchants_shares_one_hash_row`, `card_dedup_same_card_same_key_gives_same_hash` | proven |
| T12 | The card fingerprint can be computed without the caller's key. | Someone who reads the fingerprint table hashes candidate card numbers to match fingerprints. | The fingerprint is an HMAC under the key the caller supplies (`src/domain/fingerprint.rs:21-22`). | Only the primitive is tested: `test_key_not_equal`, `test_key_equal`. No test calls the fingerprint route with two keys. | not tested |
| T13 | One merchant's key decrypts another merchant's cards. | A caller passes another merchant's id with a stolen card reference. | Each merchant has its own data key, stored encrypted under the master key (`src/crypto/keymanager/internal_keymanager.rs:43-55`, `src/crypto/keymanager/internal_keymanager.rs:61-65`). | No test stores cards for two merchants and checks that each key decrypts only its own rows. | not tested |
| T14 | Cards are served before both custodians have unlocked the vault. | A caller sends data requests right after the vault starts. | A tenant has no data state until unlock, and requests get CustodianLocked (`src/tenant.rs:133-142`). | No test sends a data request before unlock. | not tested |
| T15 | A request for an unknown tenant reaches the data. | A caller sends a made-up tenant id header. | The tenant header must name a configured tenant (`src/custom_extractors.rs:24-30`). | No test sends an unknown tenant id. | not tested |
| T16 | Card numbers travel in clear between the application and the vault. | Someone on the internal network reads requests and responses. | With the middleware feature, request bodies are JWE-decrypted and responses signed (`src/middleware.rs:58-60`, `src/middleware.rs:80-82`). | Only the primitives are tested (`test_jwe`, `test_jws`); the demo runs without the middleware, and no test sends a request through it. | not tested |
| T17 | A generated card reference reveals or resembles the card number. | Someone holding references tries to derive cards from them, or a system mistakes one for a card. | A reference not supplied by the caller is a random UUID v7 (`src/storage/types.rs:160-162`, `src/storage/utils.rs:8-10`). | No test checks the form of the generated reference. | not tested |
| T18 | A caller-chosen reference looks like a card number and is stored as is. | A careless or hostile caller supplies a card number as its own card reference. | none | `docs/tokenization.md:111-116`; the audit log redacts it (`pending_redacts_card_shaped_ids`), the vault table does not. | open |
| T19 | Any caller of a tenant can read any card of that tenant, unmasked. | A compromised application of the tenant retrieves cards of every merchant and customer. | none (access control is per tenant only, `src/custom_extractors.rs:24-30`) | `docs/tokenization.md:66-69`, `docs/tokenization.md:133-134` | open |
| T20 | Before unlock, the vault already holds full database credentials. | Someone who takes over the vault process before unlock uses its connection to change or delete rows. | none | `docs/tokenization.md:135-139`, `demo/README.md:157-160` | open |
| T21 | Hash rows written before the keyed hash are still readable and reversible. | Someone who reads the hash table of an older deployment tries every candidate number against the old unkeyed values. | none | `docs/tokenization.md:117-124` | open |
| T22 | A change of master key changes every duplicate-check hash. | Not an attack: after a rotation, every card already stored looks new, so duplicates are no longer detected. | none | `docs/tokenization.md:130-132` | open |
| T23 | With an external key manager, the master key no longer protects cards but still keys the duplicate-check hash. | An operator leaves a public or placeholder master key, which makes the hash computable by anyone again. | none | `docs/tokenization.md:125-129` | open |
| T24 | Someone who reads the database sees that two merchants hold the same card. | A database reader compares the hash id of locker rows across merchants of one tenant, without learning the number. | none (one hash row per card and tenant, `src/storage/schema.rs:50-55`, shared through the locker hash id at `src/storage/schema.rs:74`) | `same_card_for_two_merchants_shares_one_hash_row` shows the shared row; the scope of the duplicate check is the next planned change (I6). Lines: `src/storage/schema.rs:62-79`. | open |
| T25 | The response time of a card add tells whether the card is already known to the tenant. | A caller times repeated adds of candidate cards; the response body is identical, only the time differs. | none | Known card: extra lookup and decryption (`src/routes/data.rs:133-171`); new card: hash insert (`src/routes/data.rs:172-184`). Read in the code on 2026-11-23, not measured. | open |
| T26 | Requests refused before their handler leave no audit row. | An attacker probes with unknown tenants, bad JWE or calls before unlock without leaving traces in the audit log. | none | `demo/README.md:144-147` | open |
| T27 | For an add or a delete, the database change has already happened when the audit write fails. | An insider makes the audit table unwritable, then deletes cards: the delete succeeds although the caller gets HTTP 500. | none | `demo/README.md:153` | open |
