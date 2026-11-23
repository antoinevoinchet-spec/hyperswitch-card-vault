# What the vault already does for tokenization

This page describes the vault's existing behaviour with the vocabulary of the PCI Security Standards
Council (PCI SSC). It adds no feature and makes no claim about the project's standing against any
standard: this is a study fork. Every statement about the vault cites a test or a `file:line` on the
branch where this page was written.

Source of the vocabulary: PCI SSC, *Tokenization Product Security Guidelines – Irreversible and
Reversible Tokens*, information supplement, version 1.0, April 2015
(https://listings.pcisecuritystandards.org/documents/Tokenization_Product_Security_Guidelines.pdf,
read on 2026-11-23). Page numbers below refer to that document.

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
  caller supplies its own reference, the vault generates it (`src/storage/types.rs:160-163`) as a
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
  (`src/routes/data.rs:262`), then returns the card.
- Access control in this code base is per tenant: every data call must carry a known `x-tenant-id`
  (`src/custom_extractors.rs:26-30`), and with the `middleware` feature every request body must be
  a JWE that the vault decrypts with its key pair (`src/middleware.rs:58-59`), and every response is
  signed (`src/middleware.rs:81`). There is no finer per-caller rule.
- Every de-tokenization leaves an audit row before the card leaves the vault, and none is returned if
  that row cannot be written: `audit::record` is called on every retrieve (`src/routes/data.rs:241`),
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

### The duplicate check uses a keyed hash

- To detect a card already stored, `/data/add` computes a hash of the card number
  (`src/routes/data.rs:116-122`) and looks it up in `hash_table.data_hash`
  (`src/storage/schema.rs:51-55`). That hash is one HMAC-SHA512 from `ring`
  (`src/crypto/hash_manager/managers/sha.rs:120-122`), 64 bytes, not truncated.
- Its key is derived with HKDF-SHA512 from the tenant master key and the context
  `hyperswitch-card-vault/card-dedup/v1` (`src/crypto/hash_manager/managers/sha.rs:82` and
  `:93-108`), so it is independent of the keys that encrypt the cards, and two tenants never share
  it. Under the `key_custodian` feature, the vault cannot compute it before both custodians have
  unlocked the master key.
- Someone who reads `hash_table` alone can no longer test candidate card numbers against it: they
  would need the master key. Tests: `card_dedup_two_master_keys_give_two_hashes` and
  `hmac_sha512_matches_rfc4231_case_2` (`src/crypto/hash_manager/managers/sha.rs`), and, against a
  real database, `stored_card_hash_is_not_a_plain_sha512` and
  `same_card_for_two_merchants_shares_one_hash_row` (`tests/vault_e2e.rs`).
- The duplicate check still spans one tenant and all its merchants, as before.

## What the vault does not do

- **No format-preserving token.** The reference is a UUID, not a 16-digit value that looks like a
  card number. Systems that expect a card-shaped field cannot store it as is.
- **No reversible cryptographic token.** The reference is not derived from the card by encryption;
  the vault always looks the card up in its table.
- **A caller-chosen reference is not checked.** `requestor_card_reference`
  (`src/routes/data/types.rs:52`) is stored as given (`src/storage/types.rs:160-162`), so a caller
  could choose a reference that looks like a card number. The audit log replaces such an id by
  `redacted` (`looks_like_card_number`, `src/audit.rs:66`; test `pending_redacts_card_shaped_ids`),
  but the vault itself stores it. As a side effect, about one in ten purely numeric ids of 13 to 19
  digits also passes the Luhn check and is redacted in the audit log (review note M1).
- **Rows written before the keyed hash are not converted.** Until this fork's fix, the duplicate
  check stored a plain SHA-512 of the card number, which anyone reading `hash_table` could reverse by
  trying every candidate number. No lookup matches those old rows any more (read in the code, not
  tested): a card stored before the fix and added again gets a new row, and for the same merchant and
  customer a second stored copy, without `duplication_check`. The old values stay readable until they
  are deleted. This fork holds no real card, so no migration is provided; a real deployment would
  need a one-off job that decrypts each stored card, recomputes the keyed hash and deletes the old
  values.
- **A change of master key would change every duplicate-check hash**, since the key is derived from
  it. The design (`docs/superpowers/specs/2026-11-23-keyed-card-hash-design.md`, decision I3)
  describes how to keep the current key in that case. Key rotation is not implemented.
- **No per-caller access rules or masking** on retrieval (a later phase of this fork may study
  them).
- **Custodian unlock before the database role is narrowed.** Since custodian steps are recorded in
  `audit_log`, the vault opens an audit connection before it is unlocked, with the same database
  credentials as the rest of the vault. It still cannot read any card before unlock, because every
  stored card is encrypted under keys derived from the still-encrypted master key. A database role
  allowed only to insert into `audit_log` is a possible next step.
