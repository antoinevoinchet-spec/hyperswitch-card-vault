# Demo: one test card through the vault

`make demo` plays, in a few seconds once the programs are built, the whole life of a test card in the
vault: two custodians unlock it, the card is stored, read back, fingerprinted and deleted, and the
audit log is printed at the end. Nothing needs to be configured, and nothing is left behind.

This is a study fork. The demo uses only a public test card number (`4111111111111111`) and keys
generated for the run, which are never printed.

## Run it

Prerequisites: Rust (`cargo`), PostgreSQL 14 or later (`initdb`, `pg_ctl`, `psql`), `jq`, `curl`,
`openssl`.

```bash
make demo
```

The script (`demo/run.sh`):

1. builds the `locker` and `utils` programs with the `key_custodian` feature (debug profile);
2. creates a throwaway PostgreSQL cluster in a temporary folder, listening on `127.0.0.1:54329`
   (`DEMO_PG_PORT` to change it), and applies every migration, including the `audit_log` table;
3. generates a throwaway encrypted master key and its two custodian keys with `utils master-key`;
4. starts the vault and plays the ten steps below;
5. prints the audit log and six checks, then stops the vault, stops the cluster and deletes the
   temporary folder, even if a step fails or the run is interrupted.

It exits with code 0 only if every step returns the expected status, step 7 returns the card that
was stored, and every check matches. In CI,
`DEMO_DATABASE_URL` points it to an existing empty database instead of a throwaway cluster.

## How the keys fit together

```
custodian key 1 + custodian key 2  --decrypt-->  master key
master key                         --decrypt-->  merchant key  (one per merchant, stored encrypted)
merchant key                       --encrypt-->  card data     (stored in the `locker` table)
```

All three layers use AES-256-GCM from the existing code (`src/crypto/encryption_manager/managers/aes.rs`).
The master key is kept in the configuration only in encrypted form; the vault can decrypt it only
once both custodian keys have arrived (`aes_decrypt_custodian_key` in
`src/routes/key_custodian.rs`). The merchant key is created on the merchant's first card and stored
encrypted under the master key (`src/crypto/keymanager/internal_keymanager.rs`).

## The ten steps

Custodian keys are shown as `<hidden>` in the output. They are sent to the vault through standard
input, so they do not appear in the process list either.

1. **Custodian 1 sends key 1** (`/custodian/key1`, 200). The vault writes an audit row
   `custodian_key1, success` first, then keeps the key in memory. If the row cannot be written, the
   key is refused with HTTP 500: a key is never held without a trace.
2. **Custodian 2 sends a wrong key 2** (`/custodian/key2`, 200). The key has the right shape (16
   bytes in hex), so the vault accepts it for now and records `custodian_key2, success`. It cannot
   know the key is wrong before trying to decrypt. A key of the wrong shape would be rejected before
   the handler, and would leave no row.
3. **Unlock fails** (`/custodian/decrypt`, 401). The two keys do not decrypt the master key. The vault
   stays locked and records `custodian_decrypt, failure, 401, DecryptingKeysFailed`. Before this
   phase, this failure left only a log line (limit D8 of the audit design).
4. **Custodian 2 sends the right key 2** (`/custodian/key2`, 200). Key 1 is still held from step 1;
   key 2 is replaced. See "Known limits".
5. **Unlock succeeds** (`/custodian/decrypt`, 200). The vault writes `custodian_decrypt, success`
   before it starts serving the tenant: if that row cannot be written, the tenant stays locked.
6. **Store the test card** (`/data/add`, 200). The request carries the card number in clear (the
   `middleware` envelope is off in this demo, see below). The vault encrypts it with the merchant key
   and returns a random `card_reference`. The audit row `locker_add` holds the merchant id, the
   customer id and that reference, never the card. Right after this step the script checks the
   `locker` table: one row, and its stored bytes do not contain the card number.
7. **Read the card back** (`/data/retrieve`, 200). The vault decrypts the row and returns the card.
   The audit row `locker_retrieve` holds the reference, not the card. If that row could not be
   written, the vault would answer HTTP 500 and return no card (fail-closed; proven by the test
   `retrieve_fails_closed_when_audit_table_is_unwritable` in `tests/vault_e2e.rs`).
8. **Fingerprint the card** (`/cards/fingerprint`, 200). The vault returns a `fingerprint_id`: the
   same card with the same fingerprint key always gives the same id, so a merchant can spot a card it
   has already seen without storing it. The fingerprint key is shown as `<hidden>`. The audit row
   `fingerprint` holds no part of the request.
9. **Delete the card** (`/data/delete`, 200). The stored row is removed; `locker_delete` is recorded.
10. **Read after delete** (`/data/retrieve`, 404). The reference no longer points to anything;
    `locker_retrieve, failure, 404, NotFoundError` is recorded.

## What the audit row records, and what it never records

Each row holds: a random id, the UTC time, the request id (only if it is a UUID), the tenant, the
operation, the merchant, customer and stored-object ids, the outcome, the HTTP status and the error
kind. It never holds card data, request or response bodies, encrypted content, custodian keys,
master or merchant keys, or fingerprint keys. An id that looks like a card number (13 to 19 digits
passing the Luhn check) is stored as `redacted`. See `src/audit.rs`.

## The checks at the end

- audit rows written by the journey: 10;
- audit rows match the journey step by step (operation, outcome and status of each of the ten
  steps, in order): yes;
- audit rows containing the card number: 0;
- `locker` rows while the card was stored: at least 1, and 0 of them contain the card number in
  clear;
- server log lines containing the card number: measured and printed (0 on the run below);
- generated key values found in the demo's own output: 0.

## Abridged output (run of 2026-11-23)

```
=== Step 3: unlock attempt fails
  request : POST /custodian/decrypt {}
  status  : 401
=== Step 6: store the test card
  request : POST /data/add {"merchant_id":"demo-merchant","merchant_customer_id":"demo-customer","card":{"card_number":"4111111111111111"}}
  status  : 200
  response: {"status":"Ok","payload":{"card_reference":"01a2062c-…","duplication_check":null,"dedup":null}}
  check   : rows in the locker table: 1; rows whose stored bytes contain the card number: 0
=== Audit log (table audit_log, UTC)
     operation     |  merchant_id  |  customer_id  | resource_id | outcome | status_code |      error_type
 custodian_key1    |               |               |             | success |         200 |
 custodian_key2    |               |               |             | success |         200 |
 custodian_decrypt |               |               |             | failure |         401 | DecryptingKeysFailed
 custodian_key2    |               |               |             | success |         200 |
 custodian_decrypt |               |               |             | success |         200 |
 locker_add        | demo-merchant | demo-customer | 01a2062c-…  | success |         200 |
 locker_retrieve   | demo-merchant | demo-customer | 01a2062c-…  | success |         200 |
 fingerprint       |               |               |             | success |         200 |
 locker_delete     | demo-merchant | demo-customer | 01a2062c-…  | success |         200 |
 locker_retrieve   | demo-merchant | demo-customer | 01a2062c-…  | failure |         404 | NotFoundError
=== Checks
audit rows containing the card number: 0 (expected 0)
generated key values found in this output: 0 (expected 0)
DEMO OK
```

## What the demo does not show

- **The JWE envelope.** With the `middleware` feature, every request and response between the
  application and the vault is encrypted (JWE) and signed (JWS), so the card number would never
  travel in clear, even inside a private network. The demo leaves it off so the messages stay
  readable. To try it by hand, see the `utils jwe-encrypt` and `jwe-decrypt` commands in
  `docs/guides/testing.md`.
- **The rate limit** (`limit` feature) and the external key manager.

## Known limits

Recorded in `audit_log`: every vault and custodian operation that reaches its handler. Not recorded:

- requests rejected before the handler: unknown tenant, JWE decryption failure, malformed JSON
  (including a custodian key of the wrong shape), data calls while the custodian is locked
  (`CustodianLocked`), custodian calls after unlock (`CustodianUnlocked`), and `/delete` calls
  rejected by the rate limit (`limit` feature, HTTP 429);
- with `middleware`, a failure while encrypting the response, which happens after the row says
  `success`.

Other limits:

- For an add or a delete, the database change has already happened when the audit write fails.
- The custodian keys are two halves of one key: each custodian knows half of its bits.
- A decrypt that fails on a wrong key keeps both stored keys (only a missing key resets them), and a
  second key 1 before decrypt replaces the first. Both submissions are recorded.
- To write custodian rows before unlock, the vault opens its audit connection with the same database
  credentials as the rest of the vault. Before unlock it cannot read any card, since every row is
  encrypted under keys derived from the still-encrypted master key. A database role allowed only to
  insert into `audit_log` is a possible next step.
