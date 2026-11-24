# What the vault already does for tokenization

This page describes the vault's existing behaviour with the vocabulary of the PCI Security Standards
Council (PCI SSC). It adds no feature and makes no claim about the project's standing against any
standard: this is a study fork. Every statement about the vault cites a test or a `file:line` on the
branch where this page was written.

Source of the vocabulary: PCI SSC, *Tokenization Product Security Guidelines – Irreversible and
Reversible Tokens*, information supplement, version 1.0, April 2015
(https://listings.pcisecuritystandards.org/documents/Tokenization_Product_Security_Guidelines.pdf,
read on 2026-11-23). Page numbers below refer to that document.

Each protection and each known limit is also listed, with the test that proves it or the text that
describes it, in the [threat model table](./threat-model.md).

## The vocabulary, in short

- **Tokenization**: "a process by which a surrogate value, called a 'token,' replaces the primary
  account number (PAN) and, optionally, other data" (p. 5).
- **De-tokenization**: exchanging "a token for the original PAN" (p. 5).
- **Reversible token**: the original PAN can be obtained again by de-tokenization (p. 7). Two kinds:
  - *reversible cryptographic*: "generated from PANs using strong cryptography"; the PAN itself is
    not stored, only the key (p. 7);
  - *reversible non-cryptographic*: the PAN is obtained "only by a data look-up in a card data vault
    (CDV)", from a PAN-to-token table; the token "has no mathematical relationship with its
    associated PAN" (p. 8).
- **Irreversible token**: can never be converted back to the PAN (p. 7). It is *authenticatable* when
  a one-way function "could be used to verify that a given PAN was used", and *non-authenticatable*
  otherwise (p. 7).
- **Card data vault (CDV)**: the store a non-cryptographic token is looked up in (p. 8).
- The document adds that "the token should be distinguishable from a valid PAN" (p. 7), and that
  de-tokenization goes "through an appropriate access control mechanism" (p. 7).

## How the vault maps onto it

### `card_reference` is a reversible, non-cryptographic token

- `/data/add` stores the card and answers with a `card_reference` instead of the card. Unless the
  caller supplies its own reference, the vault generates it (`src/storage/types.rs:178-181`) as a
  UUID v7 (`src/storage/utils.rs:8-9`): a timestamp plus random bits, with no mathematical
  relationship to the card number.
- The reference is returned to the caller from the stored row (`src/routes/data/transformers.rs:19`).
- A UUID such as `01a2062c-7844-7062-a363-d0f9bc0c18ce` contains letters and hyphens, so a generated
  reference cannot be mistaken for a card number.
- Proven end to end by `audit_row_is_written_for_each_card_step` (`tests/vault_e2e.rs`), which stores
  a card, reads it back with its reference and deletes it.

### The `locker` table is the card data vault and its mapping table

- Each row maps a `(merchant_id, customer_id, locker_id)` key to the encrypted card data `enc_data`
  (`src/storage/schema.rs:62-77`). `locker_id` is the `card_reference`.
- The card data is not stored in clear: it is encrypted with the merchant's key
  (`src/crypto/keymanager/internal_keymanager.rs:128-136`), and the merchant's key is itself stored
  encrypted under the tenant's master key (`src/crypto/keymanager/internal_keymanager.rs:48-55`, where the master key is loaded, and
  `src/crypto/keymanager/internal_keymanager.rs:61-65`, where the merchant row is read through it).
  All layers use AES-256-GCM through the existing `GcmAes256` type.
- So the vault combines a look-up token with encrypted storage: the token has no relation to the
  card, and the vault row holding the card is encrypted.
- Checked by `make demo`: right after the card is stored, one `locker` row exists and none of the
  stored bytes contain the card number.

### `/data/retrieve` is de-tokenization

- Given a `card_reference`, the vault finds the row and decrypts it
  (`src/routes/data.rs:296`), then returns the card.
- Access control in this code base is per tenant: every data call must carry a known `x-tenant-id`
  (`src/custom_extractors.rs:27-31`), and with the `middleware` feature every request body must be
  a JWE that the vault decrypts with its key pair (`src/middleware.rs:58-59`), and responses are
  signed, then encrypted as a JWE (`src/middleware.rs:92-96`), unless the caller asks for a
  signed-only response on the fingerprint route, which is then readable (`src/middleware.rs:79-90`).
- Every tenant declares its callers: each has a random key, of which the configuration holds only
  the SHA-256, a list of merchants and the rights it has for them, among `read`, `add` and
  `delete` (`read` only when it lists none) (`src/config.rs:154-175`). A read, an add or a delete
  needs the `x-vault-caller-key` header with a known key, the merchant of the request (the entity,
  on the second API version) on that caller's list, and the matching right
  (`src/custom_extractors.rs:139-195`). The check runs before any key or row is loaded or written,
  on reads (`src/routes/data.rs:275-280`, `src/routes/routes_v2/data.rs:91-96`), adds
  (`src/routes/data.rs:118-123`, `src/routes/routes_v2/data.rs:171-176`) and deletes
  (`src/routes/data.rs:228-233`, `src/routes/routes_v2/data.rs:43-48`); a missing or unknown key,
  or a tenant that declares no caller, gets HTTP 401, a merchant not on the list or a missing right
  HTTP 403. Tests (`tests/vault_e2e.rs`): `caller_reads_only_its_merchants_cards`,
  `caller_without_a_valid_key_is_refused`, `caller_reads_only_its_entities_through_v2`,
  `caller_adds_only_for_its_merchants`, `caller_deletes_only_its_merchants_cards`,
  `caller_without_a_valid_key_cannot_add_or_delete`,
  `caller_adds_and_deletes_only_its_entities_through_v2`,
  `caller_without_a_valid_key_cannot_add_or_delete_through_v2`,
  `caller_needs_the_right_for_each_operation`, `tenant_without_callers_refuses_every_data_call`.
  The fingerprint routes are not limited per caller.
- Every de-tokenization leaves an audit row before the card leaves the vault, and none is returned if
  that row cannot be written: `audit::record` is called on every retrieve (`src/routes/data.rs:267`),
  proven by `retrieve_fails_closed_when_audit_table_is_unwritable` (`tests/vault_e2e.rs`).
- The row never holds the card: `store_card_entry_never_contains_card_number` (`src/audit.rs`) and
  the demo's check "audit rows containing the card number: 0".

### The fingerprint is an irreversible value for matching cards

- `/cards/fingerprint` computes an HMAC-SHA512 of the data under a caller-supplied key
  (`src/domain/fingerprint.rs:21-22`) and returns a `fingerprint_id`, a random id stored next to
  that hash (`src/domain/fingerprint.rs:37-38`).
- The HMAC value is irreversible and *authenticatable* in the guidelines' sense: whoever holds the
  fingerprint key can check whether a given card produced it. The `fingerprint_id` given to the caller
  is a random id, linked to the card only through the vault's table.
- The audit row for a fingerprint takes nothing from the request: `fingerprint_entry_has_no_payload`
  (`src/audit.rs`).

### The duplicate check uses a keyed hash, scoped to the merchant and customer

- To detect a card already stored, `/data/add` computes a hash of the card number
  (`src/routes/data.rs:127-138`) and looks it up in `hash_table.data_hash`
  (`src/storage/schema.rs:51-55`). That hash is one HMAC-SHA512 from `ring`
  (`src/crypto/hash_manager/managers/sha.rs:142-145`), 64 bytes, not truncated.
- Its key is derived with HKDF-SHA512 from the tenant master key, the context
  `hyperswitch-card-vault/card-dedup/v2` (`src/crypto/hash_manager/managers/sha.rs:83`) and the
  merchant and customer ids of the request, each preceded by its length
  (`src/crypto/hash_manager/managers/sha.rs:96-130`). It is independent of the keys that encrypt the
  cards, and two tenants with different master keys get different keys. Under the `key_custodian`
  feature, the vault cannot compute it before both custodians have unlocked the master key.
- Someone who reads `hash_table` alone can no longer test candidate card numbers against it: they
  would need the master key. Tests: `card_dedup_two_master_keys_give_two_hashes` and
  `hmac_sha512_matches_rfc4231_case_2` (`src/crypto/hash_manager/managers/sha.rs`), and, against a
  real database, `stored_card_hash_is_not_a_plain_sha512` (`tests/vault_e2e.rs`).
- The same card stored by two merchants, or by two customers of one merchant, gets two different
  hashes and two `hash_table` rows, so the `hash_id` of their `locker` rows no longer links them.
  `duplication_check` is still returned only when the same merchant and customer add the same card
  again, for cards whose hash was written after this change or converted by the re-hash job (older
  rows: see below). Tests: `card_dedup_two_merchants_give_two_hashes`,
  `card_dedup_two_customers_give_two_hashes`, `card_dedup_scope_framing_is_unambiguous`, and
  `same_card_for_two_merchants_gets_two_hash_rows` (`tests/vault_e2e.rs`).
- An add of a card known only to another merchant or customer now takes the same code path as a
  card the tenant has never seen: its hash is not in the table, so a new row is inserted. Proven by
  `card_known_to_others_takes_the_new_card_path`, which compares the rows each add creates: the
  branch for a known hash, which inserts no hash row, did not run. A read that writes no row would
  not be seen by this test, and the response time itself is not measured.
- One different path remains: when the same merchant and customer stored a card, deleted it and add it
  again, the hash row is found, because a delete removes the `locker` row and keeps the `hash_table`
  row (read in the code, `src/storage/db.rs:327-370`, not tested). Their response time may differ,
  but it can only tell them about their own past adds. The re-hash job's clean-up deletes such kept
  rows of cards deleted before it runs; a delete after the job keeps its hash row again.

## What the vault does not do

- **No format-preserving token.** The reference is a UUID, not a 16-digit value that looks like a
  card number. Systems that expect a card-shaped field cannot store it as is.
- **No reversible cryptographic token.** The reference is not derived from the card by encryption;
  the vault always looks the card up in its table.
- **A caller-chosen reference is not checked.** `requestor_card_reference`
  (`src/routes/data/types.rs:52`) is stored as given (`src/storage/types.rs:178-180`), so a caller
  could choose a reference that looks like a card number. The audit log replaces such an id by
  `redacted` (`looks_like_card_number`, `src/audit.rs:76`; test `pending_redacts_card_shaped_ids`),
  but the vault itself stores it. As a side effect, about one in ten purely numeric ids of 13 to 19
  digits also passes the Luhn check and is redacted in the audit log (review note M1).
- **Rows written before the keyed hash are converted only once the re-hash job has run.** Until
  this fork's fix, the duplicate check stored a plain SHA-512 of the card number, which anyone
  reading `hash_table` could reverse by trying every candidate number. No lookup matches those old
  rows any more (read in the code, not tested): a card stored before the fix and added again gets
  a new row, and for the same merchant and customer a second stored copy, without
  `duplication_check`. The old values stay readable until they are deleted. The re-hash job
  described below replaces them too, through the same comparison of each cited hash with the
  recomputed one; this case is not tested with plain SHA-512 values.
- **Rows written before the merchant scope are converted only once the re-hash job has run.**
  Until then, hashes stored under the tenant-wide `v1` context are never matched by the `v2` lookup
  (test `tenant_wide_v1_hash_row_is_not_matched`): a card stored before the change and added again
  by the same merchant and customer gets a second stored copy, without `duplication_check`, and the
  old `locker` rows keep their shared `hash_id`, which links merchants and customers.
- **The re-hash job.** `utils rehash --tenant <id>` (`src/bin/utils.rs`, job in
  `src/domain/hash.rs`) decrypts each stored card, recomputes the hash that `/data/add` computes
  today, points the `locker` row at it, deletes each old hash row that no row cites any more
  (`src/storage/db.rs:607-609`), and at the end deletes unused rows created more than one minute
  before the run (`src/storage/db.rs:648-650`). Nothing about progress is stored: each row is
  recomputed, so a second run changes nothing and a run stopped half-way is resumed by running it
  again. Tests (`tests/vault_e2e.rs`): `rehash_moves_v1_rows_to_scoped_hashes`,
  `rehash_twice_changes_nothing`, `rehash_resumed_after_interruption_matches_a_full_run`,
  `rehash_detaches_the_older_duplicate`, `rehash_on_an_empty_tenant_changes_nothing`.
- **How to run it.** Stop the vault, run the command, start the vault again. With the
  `key_custodian` feature, the two custodian keys are read from standard input, one per line:
  pipe them from a file only the custodians can read, or type them with echo off (for example with
  the shell's `read -s`), never as arguments, so they stay off the screen and out of the shell
  history. The command prints counts only; it exits 0 when every row is done, 2 when `--max-rows`
  stopped it, and 1 on an error, whose message names the error kind only. To finish a run stopped
  by `--max-rows`, run the command again without that option: with the same limit, it examines the
  same first rows again and stops at the same place. A batch size below 1 is refused (test
  `rehash_refuses_a_batch_size_of_zero`). A wrong custodian key changes nothing (test
  `rehash_refuses_wrong_custodian_keys`), but, unlike the vault's custodian routes, the command
  writes no audit entry for it. One row that cannot be read (missing merchant key, data that does
  not decode) stops the whole run, every time: the job never skips a row.
- **What the audit log keeps of it.** One `rehash_row` entry per changed row, with merchant,
  customer and card reference, written before the change (it records the attempt), one
  `rehash_cleanup` entry written before the final clean-up, and one `rehash_run` entry per run (its
  result). If an entry cannot be written, the job stops and nothing it was about to change is
  changed. Tests: `rehash_audit_rows_hold_no_card_or_key`,
  `rehash_stops_when_audit_table_is_unwritable`,
  `rehash_cleanup_stops_when_audit_table_is_unwritable`.
- **What the job leaves.** A card stored twice by the same merchant and customer (once before the
  change, once after) keeps both copies. The newer copy keeps the current hash, also after a change
  of master key (test `rehash_keeps_the_newer_copy_after_a_key_change`); the other one is detached,
  that is, it gets a `hash_id` that matches no hash row, so it links no one. Both card references
  still return the card, and later adds find the newer copy and return `duplicated`. A run resumed
  right after an interruption may leave an unused old hash row younger than one minute, which the
  next run removes. Run next to a live vault: an add during the run can create such a duplicate,
  which a second run handles; the vault's in-memory cache (`src/storage/caching.rs:50-64`) may keep
  a hash row that the clean-up deleted until the vault restarts; an add that reads a deleted
  card's hash row at the moment the clean-up deletes it can store a card citing a missing hash row;
  and a clock difference between the hosts shortens the one-minute margin. Not tested: two writers
  changing the same row at once (the update then changes no row and the job stops), and the removal
  of deleted rows from the cache.
- **The job without `key_custodian`, and under `kv`.** Without the `key_custodian` feature, the
  command takes the master key from the configuration; the re-hash tests run in that mode too, in
  the CI job "Re-hash without the key_custodian feature", and give the same result (for example
  `rehash_moves_v1_rows_to_scoped_hashes`: each row cites its expected hash, a new add returns
  `duplicated`). With the `kv` feature, the job refuses to run and changes no row (test
  `rehash_refuses_to_run_with_kv`, CI job "Re-hash refusal with the kv feature"). It was seen
  failing with the five refusals removed. With no card stored, only two of them are on its path
  (the read of the rows, then the final clean-up); the three refusals on the path of a stored card
  are compiled, not tested.
- **The master key must stay a real secret even with an external key manager.** With the
  `external_key_manager` feature enabled, the cards are encrypted by the external service
  (`src/crypto/keymanager.rs:59-67`) and `tenant_secrets.master_key` no longer protects them, but it
  is still required (`src/config.rs:143`) and the duplicate-check key is still derived from it. A
  placeholder or public value there would make the duplicate-check hash computable by anyone again.
- **Master key rotation.** `utils rotate-master-key --tenant <id>` (`src/bin/utils.rs`, job in
  `src/domain/master_key.rs`) re-encrypts each merchant key of the tenant under a new master key,
  then runs the re-hash job under that key, so the duplicate check keeps working (design:
  `docs/superpowers/specs/2026-11-23-master-key-rotation-design.md`). The merchant keys themselves
  do not change, so no card is re-encrypted. The AES-GCM tag tells which of the two keys wraps each
  row (`src/domain/master_key.rs:34-42`): nothing about progress is stored, and a run stopped
  anywhere is finished by running the command again with the same keys. Before any write, every row
  is read and must open under the former or the new key; a row under a third key stops the run
  (`src/domain/master_key.rs:122-132`). Each rewritten row's audit entry comes first, and the update
  applies only if the row has not changed since it was read (`src/domain/master_key.rs:192-208`).
  After the last row, every row must open under the new key and none under the former one, before
  the hash step runs (`src/domain/master_key.rs:152-153`). Tests (`tests/vault_e2e.rs`):
  `rotation_cards_read_back_for_two_merchants`, `rotation_former_key_opens_no_merchant_row`,
  `rotation_keeps_duplicate_detection`, `rotation_resumed_after_interruption_matches_a_full_run`
  (runs stopped by a row limit and finished from a mixed state, and a run killed before the hash
  step, each compared with a complete run).
- **How to run it.** Stop the vault and back up the database. Generate the new key with
  `utils master-key`. Run the command: the keys are read from standard input, one per line, never
  from arguments (`src/bin/utils.rs:327-335`). With the `key_custodian` feature, the current
  custodians give the former key 1 and key 2, then the new encrypted master key and the new key 1
  and key 2 follow; without it, one line holds the new master key. The command prints counts only
  and exits 0 when done, 2 when `--max-rows` stopped it, 1 on an error, whose message names its kind
  only. Then put the new encrypted master key in the configuration (the raw key without custodians),
  start the vault and unlock it with the new custodian keys. `utils rehash`, run with the new keys,
  checks that the configuration holds the right key: it reports `moved: 0` (asserted by
  `rotation_keeps_duplicate_detection`).
- **What it refuses.** Custodian keys that do not unlock their master key, fewer than five lines,
  a new encrypted master key that the new custodian keys do not open, a new master key equal to the
  former one (also when only the custodian keys change), a raw new key that is not 32 bytes, a row
  under a third key, and a batch size below 1: each changes no row. Tests:
  `rotation_refuses_wrong_custodian_keys`, `rotation_refuses_the_same_master_key`,
  `rotation_refuses_a_row_under_a_third_key`, `rotation_refuses_a_batch_size_of_zero`.
- **What the audit log keeps of it.** One `master_key_rotation_row` entry per row to rewrite, with
  the merchant id only, written before the row changes (it records the attempt, as for the re-hash
  job), and one `master_key_rotation_run` entry per run with its outcome, a refused run included (the
  only row a refused run adds); the re-hash step writes its own entries. No entry and
  no output holds a key, a key part, a merchant key or a hash. If an entry cannot be written, the
  run stops and the row it was about to change is unchanged. Tests:
  `rotation_audit_and_output_hold_no_key`, `rotation_stops_when_audit_table_is_unwritable`.
- **What a rotation covers, and what it does not.** It answers a routine change of master key: a
  schedule, or a custodian who leaves. It does not answer a leak of the master key together with a
  copy of the database: the former key and a copy taken before the rotation still give every
  merchant key, which still decrypts the cards stored today. Copies taken before the rotation can be
  read only with the former key, so it must be kept outside the vault until they expire, then
  destroyed; this fork writes no tool for either step. Between the end of the command and the
  configuration change, a vault started with the former key reads no card; a vault started while a
  run is stopped half-way reads only the cards of merchants not yet rewritten. A vault left running
  during the rotation can create a merchant under the former key after the final check, which the
  command does not see. The vault must be stopped for the whole run.
- **Modes.** The tests run with and without the `key_custodian` feature (CI job "Master key
  rotation without the key_custodian feature"). With `kv`, the command refuses before any write
  (test `rotation_refuses_to_run_with_kv`, CI job "Master key rotation refusal with the kv
  feature"). With an external key manager, the rotation runs against Juspay's Hyperswitch Encryption
  Service, built from source at tag `v0.1.14` with no optional feature (test
  `rotation_with_external_key_manager`, CI job "Master key rotation with an external key manager"):
  cards stored through the service read back, duplicates are still detected, and a merchant row
  still waiting for `/key/transfer` opens only under the new key and is then transferred. The keys
  the service holds are its own and are not rotated by this command.
- **Not tested.** Two writers changing the same merchant row at once (read in the code: the update
  then changes no row and the run stops). Two checks are not observable on their own, since another
  one gives the same result: the five-line check (a missing line does not unlock the key either)
  and the rotation's own batch size check (the re-hash step refuses a batch size below 1 too).
- **No masking, and no per-caller rule on fingerprints.** An allowed read returns the full card
  number; the fingerprint routes, `/entity` and `/key/transfer` are not limited per caller (a later
  phase of this fork may study them).
- **Custodian unlock before the database role is narrowed.** Since custodian steps are recorded in
  `audit_log`, the vault opens an audit connection before it is unlocked, with the same database
  credentials as the rest of the vault. It still cannot read any card before unlock, because every
  stored card is encrypted under keys derived from the still-encrypted master key. A database role
  allowed only to insert into `audit_log` is a possible next step.
