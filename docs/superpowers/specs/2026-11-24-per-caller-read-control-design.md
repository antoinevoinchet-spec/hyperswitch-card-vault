# Per-caller read control (threat T19): design

Date: 2026-11-24 (UTC). Branch: `feat/per-caller-read-control` (from `main`, `8336394`). Status:
draft, waiting for the owner's decision R1 (rights model). Plan to follow in
`docs/superpowers/plans/2026-11-24-per-caller-read-control.md`.

## Intent

Threat T19 in `docs/threat-model.md` reads "Any caller of a tenant can read any card of that
tenant, unmasked" and is `open`, with no control. Unlike T13, this ticket adds a control: a caller
may read only the cards of the merchants it is allowed to read. The control is proven by end-to-end
tests that fail when it is removed, pass when it is back, and keep allowed reads working. This is a
study fork; see `CLAUDE.md` for what may not be claimed about it.

Research reused: the owner's 2026-11-24 outside review of this ticket (kept outside the
repository). Practice read on 2026-11-24: Adyen API credentials can be limited to selected merchant
accounts, with roles kept apart from that scope
(https://docs.adyen.com/development-resources/api-credentials); Stripe restricted keys start with
no access to any resource, one key per service, and a refusal names what is missing
(https://docs.stripe.com/keys/restricted-api-keys); HashiCorp Vault policies deny by default
(https://developer.hashicorp.com/vault/docs/concepts/policies); OWASP API Security 2023, API1
(broken object level authorization), asks for the check in every function that reads a record from
a client-supplied id
(https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization).

## Current state (read in the code on 2026-11-24)

- Every data call goes through `TenantStateResolver`, which checks only that `x-tenant-id` names a
  configured tenant (`src/custom_extractors.rs:24-31`).
- With the `middleware` feature, bodies are JWE under one key pair per tenant
  (`src/middleware.rs:55-60`): it protects transport, it does not tell callers apart.
- Three routes return stored data in clear:
  - `/data/retrieve` and `/cards/retrieve`, the same handler (`src/app.rs:193-207`,
    `src/routes/data.rs:84`), which loads the key of the merchant named in the body and decrypts the
    row found by reference, merchant and customer (`src/routes/data.rs:248-266`);
  - `/api/v2/vault/retrieve` (`src/app.rs:219-224`), which does the same with `entity_id`
    (`src/routes/routes_v2/data.rs:74-87`).
- The audit row of a retrieve is written for every outcome, refusals included, because the handler
  wraps the inner function in `audit::record` (`src/routes/data.rs:237-246`,
  `src/routes/routes_v2/data.rs:61-70`).
- A request that names another merchant's card today is refused only by accident: the row lookup
  misses (404) or, for a row moved in the database, decryption fails (T13). Neither is an access
  rule.
- Configuration is read from TOML files and from `LOCKER__…` environment variables
  (`src/config.rs:227-231`); the e2e tests start the vault with environment variables
  (`tests/vault_e2e.rs:313-337`), so a test can configure callers without touching `config/`.
- `make demo` and the 33 existing e2e tests call the retrieve route with `x-tenant-id` only.

## Decision R1 (owner): the rights model

**Option A (recommended): one secret key per caller, with the list of merchants it may read, in
the tenant's configuration.**
- Effect: each application that calls the vault gets its own random key, sent in a new header
  `x-vault-caller-key`. The vault finds the caller whose key matches and serves a read only if the
  merchant (or v2 entity) named in the body is on that caller's list. A reporting tool allowed for
  merchant M1 can no longer read M2's cards, even if it is compromised.
- `src/`: a new optional `callers` section in `TenantSecrets` (`src/config.rs`), a header
  extractor (`src/custom_extractors.rs`), one check function, two new error kinds
  (`src/error.rs`), and one call at the top of each of the two retrieve functions.
- `config/`: no change. The configuration stores only the SHA-256 of each key (computed with
  `ring`, already a dependency), never the key. A tenant that declares no caller keeps today's
  behaviour (see "Default" below).
- `migrations/`: no change.
- Closest to Adyen and Stripe practice; simplest to prove end to end (a test sets two callers by
  environment variable and reads across them).

**Option B: a signed token carrying the allowed merchants (JWS, `josekit`, already a dependency).**
- Effect: an issuer outside the vault signs, for each call or session, a token listing merchants;
  the vault checks the signature with the issuer's public key from the configuration and serves
  only the listed merchants.
- `src/`: same places as A, plus signature and expiry checks. `config/`: one public key per tenant,
  no change to the files if it stays optional. `migrations/`: none.
- Set aside: the issuer becomes the critical piece, and in this deployment the issuer would be the
  same application T19 describes as compromised, so it could sign any list. It adds expiry,
  clock and key-rotation cases to test, for no gain over A in this fork.

**Also set aside:** a merchant list per tenant with no caller identity (every caller of the tenant
still reads every listed merchant, so T19 is unchanged); a rights table in the database (a
migration, and an administration route to fill it, outside this ticket).

### Default when a tenant declares no caller

Under option A, a tenant with no `callers` section keeps today's behaviour, so that `make demo`,
`config/` and the 33 existing tests stay unchanged without the owner's separate approval. Once a
tenant declares at least one caller, every retrieve on it needs a known key: a missing or unknown
key is refused. The T19 row will say that the control applies only to tenants that declare callers.
Making it mandatory for every tenant would need changes to `config/`, `demo/` and every existing
test, and is left as a later decision.

## Requirements (written for option A; rewritten if the owner picks B)

- **D1.** A caller whose key lists merchant M1 reads a card of M1 through `/data/retrieve`: status
  200 and the exact stored card number.
  Verifiable by: e2e test `caller_reads_only_its_merchants_cards`, positive half.
- **D2.** The same caller asking for a card of merchant M2 of the same tenant, with M2's correct
  reference and customer, gets status 403, `error_code` `TE_00` and the exact message
  `Caller is not allowed to read this merchant's data`; the body holds no card number.
  Verifiable by: same test, refused half, comparing the whole parsed body with the expected JSON.
- **D3.** The refusal happens before any key is loaded or any row is read, so it cannot be confused
  with the 404 of a missed lookup or the decryption error of T13.
  Verifiable by: D2's exact status and message (a 404 or a 500 fails it), and the check placed as
  the first statement of each retrieve function (read in the diff).
- **D4.** When the tenant declares callers, a retrieve with no `x-vault-caller-key` header, or with
  a key that matches no caller, gets status 401, `error_code` `TE_00` and the exact message
  `Caller key missing or unknown`, with no card number.
  Verifiable by: e2e test `caller_without_a_valid_key_is_refused` (no header, then a random key).
- **D5.** `/api/v2/vault/retrieve` applies the same rule to `entity_id`: allowed entity, 200 and the
  stored data; other entity, D2's status and message.
  Verifiable by: e2e test `caller_reads_only_its_entities_through_v2`.
- **D6.** A refused retrieve still writes its audit row, with a failure outcome and no card number.
  Verifiable by: D2's test reads the last `audit_log` row (operation `retrieve`, outcome not
  success) and checks that no audit row contains the card number.
- **D7.** A tenant with no `callers` section reads as before, with no header.
  Verifiable by: the 33 existing e2e tests and `make demo` (`DEMO OK`) unchanged and passing.
- **D8.** The configuration holds only the SHA-256 (hex) of each key; keys are never logged or
  printed, and test keys are generated at random in the test and never printed.
  Verifiable by: unit tests of the check function (matching key, wrong key, merchant list parsing,
  an empty list refuses every merchant), and a scan of the kept test output for 64-character hex
  strings and card numbers, count 0.
- **D9.** Each new e2e test fails on `main`, or with the check removed on purpose, at the assertion
  on the refusal, with the line recorded in the plan's execution notes; it passes on the branch.
  Verifiable by: the three recorded failure lines.
- **D10.** T19 in `docs/threat-model.md` is no longer `open`; it cites the control, the tests, and
  what is not covered; `docs/tokenization.md` and `README.md` are updated; `scripts/check-threat-model.sh`
  exits 0.
  Verifiable by: the script's exit code and the diff of the three files.

## Not covered (to be written in the T19 row)

- Add, delete and fingerprint are not limited per caller: a caller can still delete or add cards
  for any merchant of the tenant (integrity, not disclosure).
- A caller whose list holds every merchant (for example the one application that serves all of
  them) still reads every card: the control limits each key, it does not split one application.
- Tenants that declare no caller (default above).
- No masking: an allowed read returns the full card number.
- A key is a bearer secret: whoever copies it reads what it allows. Keys change only by editing
  the configuration and restarting the vault.
- Refused reads return 403 rather than the 404 of a missing card, so a refused caller learns that
  the merchant id is guarded, not whether the card exists (the check runs before any lookup).

## Constraints

- No new dependency: SHA-256 from `ring`, which is already used. No hand-written cryptography.
- New test names avoid the `rehash_` and `rotation_` prefixes used by CI filters.
- Files changed in `src/` are only those the plan names, after the owner approves it.
