# Per-caller write control (threat T37): design

Date: 2026-11-24 (UTC). Branch: `feat/per-caller-write-control` (from `main`, `0725bc9`). Status:
decisions D-A (option A) and D-B (option B) taken by the owner on 2026-11-24. Plan to follow in
`docs/superpowers/plans/2026-11-24-per-caller-write-control.md`.

## Intent

Threat T37 in `docs/threat-model.md` reads "Any caller of a tenant can add or delete cards of any
merchant of that tenant" and is `open`. Ticket T2 (PR #12) added a per-caller check on reads only
(threat T19). This ticket extends the same check to add and delete, on both API versions, so that a
caller whose key lists merchant M1 can no longer store cards under M2 or delete M2's cards. The
control is proven by end-to-end tests that fail when it is removed. This is a study fork; see
`CLAUDE.md` for what may not be claimed about it.

Research: the owner's outside review of this ticket (2026-11-24, kept outside the repository).
Read on 2026-11-24: OWASP Authorization Cheat Sheet (deny by default, check on every request,
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html); OWASP API Security
2023, API1, whose example is a delete with no ownership check
(https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization); Basis
Theory, VGS and Stripe split read, write and delete permissions per key
(https://developers.basistheory.com/docs/concepts/access-controls,
https://docs.stripe.com/keys/restricted-api-keys); HashiCorp Vault denies by default
(https://developer.hashicorp.com/vault/docs/concepts/policies).

## Current state (read in the code on 2026-11-24)

- `authorize_read` (`src/custom_extractors.rs:144-175`) takes the tenant's `callers`
  (`src/config.rs:154-167`), the `x-vault-caller-key` header (`OptionalCallerKey`,
  `src/custom_extractors.rs:119`) and the merchant id. Empty `callers`: allowed. Missing or unknown
  key: `CallerKeyMissingOrUnknown` (401). Merchant not listed: `CallerNotAllowed` (403).
- It is called first in `retrieve_card_inner` (`src/routes/data.rs:257-261`) and
  `retrieve_data_inner` (`src/routes/routes_v2/data.rs:80-84`) only.
- With no check today:
  - `add_card` (`src/routes/data.rs:95`): validates, computes the dedup HMAC, looks up
    `hash_table`, then `find_or_create_entity` (which may insert a `merchant` row and its key),
    then inserts into `hash_table` and `locker`.
  - `delete_card` (`src/routes/data.rs:202`): loads the merchant's key, then
    `delete_locker(card_reference, merchant_id, customer_id)`; the SQL filter uses the merchant of
    the request, so the merchant checked is the one whose row is deleted.
  - `add_data` v2 (`src/routes/routes_v2/data.rs:140`): validates, `find_or_create_entity`, upsert
    into `vault`.
  - `delete_data` v2 (`src/routes/routes_v2/data.rs:23`): loads the entity's key, then
    `delete_from_vault(vault_id, entity_id)`.
- Each handler wraps its inner function in `audit::record`, so a refusal returned by the inner
  function writes its audit row with the error's status, as for reads.
- The merchant id is in the JSON body, which the `middleware` feature decrypts from a JWE before
  the handler runs; an axum extractor or route layer would have to read and parse the body again.
- Out of scope (reported only): `/entity`, `/key/transfer`, and the fingerprint routes, which read
  no stored card.

## Decision D-A (owner): is the check mandatory for every tenant?

**Taken by the owner on 2026-11-24: option A, deny by default.** The owner also approved changes
to `config/` and `demo/` for it.

- **Option A (chosen):** a tenant that declares no caller gets HTTP 401 (`Caller key missing or
  unknown`) on every read, add and delete, on both API versions. An unconfigured tenant is closed,
  not open, and the threat table no longer depends on a setting someone may forget.
  - `src/custom_extractors.rs`: the empty-`callers` branch refuses instead of allowing.
  - `demo/run.sh`: generates a random caller key at each run (as it already generates its other
    values with `openssl`), passes only its SHA-256 by environment variable, and sends the key in
    `x-vault-caller-key`. No caller key is committed.
  - `config/config.example.toml`: a commented example of a `callers` section.
    `config/development.toml` and `config/docker-configuration.toml` keep no caller, so they
    refuse every data call until one is declared; this is the intended effect.
  - `tests/vault_e2e.rs`: the harness declares one default caller, allowed for the merchants and
    entities the existing tests use, and sends its key, so existing tests keep their meaning.
  - `src/config.rs`: unchanged (the refusal happens at request time, not at start-up).
- **Option B (set aside):** keep the check optional and say so at the top of T19 and T37. Fewer
  files, but a misconfigured tenant stays open to reads and writes with no signal.
- Not changed by D-A: the fingerprint routes, `/entity` and `/key/transfer`, which stay outside
  the per-caller check (owner's scope).

## Decision D-B (owner): one merchant list for read and write, or separate rights?

**Taken by the owner on 2026-11-24: option B, separate rights per caller.**

- **Option A (set aside):** one merchant list grants read, add and delete alike. No change to the
  configuration's shape, but a caller meant only to read (a reporting tool) could also delete the
  cards of its merchants.
- **Option B (chosen):** each caller declares, beside its merchant list, which of `read`, `add` and
  `delete` it may do for those merchants. A reporting tool reads without deleting; a capture
  service adds without reading. This needs a change to `src/config.rs`, which the plan asks the
  owner to approve separately.

### How B is built (approaches, the builder's call)

1. **One `rights` field per caller (chosen):** `rights = "read,add,delete"`, comma-separated, with
   no spaces, applying to every merchant of the caller's list. One field, set by one environment
   variable in tests, like `merchants`.
2. One merchant list per right (`read_merchants`, `add_merchants`, `delete_merchants`): finer, but
   three lists to keep in step for the common case, and every existing caller must be rewritten.
3. Named roles (`reader`, `writer`): fewer words in the configuration, but "add without reading"
   needs a third role, and the meaning of each role lives in the code instead of the configuration.

Calls made for option 1 (the builder's, open to the owner's correction):

- **Absent `rights` means `read`.** That is exactly what a caller declared under T2 could do, so a
  configuration written for T2 keeps its meaning, and no caller gains a write right it was not
  given.
- **Each right stands alone.** `add` does not imply `read`, and `delete` implies neither: a
  refused right gets the 403 of a merchant not on the list. (Stripe's "write implies read" is set
  aside: here a write right is the one more likely to be given to an exposed service.)
- **An unknown word grants nothing** (for example `write`): the caller is refused, fail closed.
  It is not checked at start-up, so a typo shows up as 403s and in the audit log.
- **Same refusals as reads**, as the owner's brief asks: 401 `Caller key missing or unknown`, 403
  `Caller is not allowed to read this merchant's data`, both `code` `TE_00`. The 403 message names
  reading even for an add or a delete; the owner kept it so the T19 tests keep their exact bodies.
- **One check function for every operation.** `authorize_read` becomes
  `authorize_caller(callers, caller_key, merchant_id, right)`, with
  `enum CallerRight { Read, Add, Delete }` in `src/custom_extractors.rs`. Its existing unit tests
  keep their names (they test the read right).
- **Placed first in each inner function**, before validation, the dedup hash, any key lookup or
  creation (`find_or_create_entity` may insert a `merchant` row), any row read and any write, as
  for reads. A per-handler call is kept over a central axum extractor or route layer: the merchant
  is in the body, which the `middleware` feature decrypts before the handler, so a central check
  would parse the body a second time. Every one of the six routes is covered by an end-to-end test
  instead.

## Requirements

- **D1.** A caller's `rights` field lists `read`, `add` and `delete` (comma-separated, no
  spaces); absent, it means `read`; an unknown word grants nothing.
  Verifiable by: unit tests of `authorize_caller` (each right alone, absent field, unknown word,
  right granted for a merchant not on the list is still refused).
- **D2.** `/data/add`: a caller with `add` for merchant M1 stores a card for M1 (200); asking to
  store one for M2 gets 403 and the exact body; the counts of `locker`, `hash_table` and `merchant`
  rows are the same before and after the refusal; its audit row is
  `("locker_add", "failure", 403)`.
  Verifiable by: e2e test `caller_adds_only_for_its_merchants`.
- **D3.** `/data/delete`: a caller with `delete` for M1 asking to delete M2's existing card gets
  403 and the exact body; the counts of `locker` and `hash_table` are unchanged and M2's card is
  still read back by M2's caller; a reference that does not exist for M2 gets the same exact 403
  (the check runs before any lookup); its audit row is `("locker_delete", "failure", 403)`. Its
  own card M1 is deleted (200, then 404 on read).
  Verifiable by: e2e test `caller_deletes_only_its_merchants_cards`.
- **D4.** On `/data/add` and `/data/delete`, no `x-vault-caller-key` header, or an unknown key,
  gets 401 and the exact body, with the row counts unchanged and audit rows at 401.
  Verifiable by: e2e test `caller_without_a_valid_key_cannot_add_or_delete`.
- **D5.** `/api/v2/vault/add` and `/api/v2/vault/delete` apply D2 to D4 to `entity_id`, with the
  counts of `locker`, `hash_table` and `vault` unchanged after each refusal and audit rows
  `vault_add` and `vault_delete` at 401 or 403.
  Verifiable by: e2e tests `caller_adds_and_deletes_only_its_entities_through_v2` and
  `caller_without_a_valid_key_cannot_add_or_delete_through_v2`.
- **D6.** Rights are separate: a caller with `read` only for M1 reads (200) and gets 403 on add and
  delete; a caller with `add` only stores (200) and gets 403 on read and delete; a caller with
  `delete` only deletes (200) and gets 403 on read and add; on v1 and v2.
  Verifiable by: e2e test `caller_needs_the_right_for_each_operation`.
- **D7.** D-A: a tenant that declares no caller gets 401 and the exact body on read, add and
  delete, on v1 and v2, with the row counts unchanged.
  Verifiable by: e2e test `tenant_without_callers_refuses_every_data_call`, and the unit test
  `authorize_caller_refuses_every_call_without_callers`, which replaces
  `authorize_read_allows_any_read_without_callers`.
- **D8.** The check is the first statement of the six inner functions (`retrieve`, `add`, `delete`,
  v1 and v2), so a refusal loads no key, reads no row and writes nothing but its audit row.
  Verifiable by: the diff, the unchanged `merchant` count of D2 (no merchant row created) and the
  403 for a missing reference of D3.
- **D9.** Allowed callers work as before: the existing e2e tests pass unchanged in meaning, with a
  default caller declared by the test harness (all three rights, every merchant and entity the
  file uses); `make demo` prints `DEMO OK` with a caller key generated at each run.
  Verifiable by: the e2e run (36 existing + new tests, with `key_custodian`; the same without it)
  and the demo's last line.
- **D10.** Caller keys are generated at random by the tests and the demo and never printed; only
  their SHA-256 is configured; nothing is committed but code that generates them.
  Verifiable by: a scan of every kept output for card numbers and 64-character hex strings, count
  0, and `git diff main` holding no 64-character hex string.
- **D11.** Each new e2e test fails with the control removed (the four write calls taken out, and,
  for D7, the empty-callers branch allowing again), at the assertion on the refusal, with and
  without `key_custodian`; the lines are recorded in the plan.
  Verifiable by: the recorded failure lines.
- **D12.** T37 is `proven` with its tests; T19 no longer lists add, delete or tenants without
  callers under "Not covered"; `docs/tokenization.md` and `README.md` are updated;
  `scripts/check-threat-model.sh` exits 0 with `38 rows (18 proven, 6 not tested, 14 open)`; the
  counts of `GHSA` and `advisories` in the three files are 0.
  Verifiable by: the script's output and a count over the three files.

## Not covered (to be written in the T37 row)

- Fingerprint, `/entity` and `/key/transfer` are not limited per caller (owner's scope).
- A caller whose list holds every merchant with every right can still add and delete for all of
  them: the control limits each key, it does not split one application.
- A caller key is a bearer secret, changed only by editing the configuration and restarting.
- With `add`, a caller learns whether a card number it already knows is stored for a customer of
  its merchant (the duplicate check answers), and the existing card's reference.
- On v2, `add` includes overwriting an entry of a listed entity by its `vault_id`
  (`?mode=upsert`).
- The 403 message names reading for every operation (owner's choice, above).
- `docs/openapi/spec.yml`, `docs/openapi-v2/spec.yml` and the Postman collection do not document
  `x-vault-caller-key` (outside this ticket's files; reported).

## Constraints

- No new dependency, no hand-written cryptography (SHA-256 from `ring`, as in T2).
- New test names avoid the `rehash_` and `rotation_` prefixes used by CI filters.
- Files changed: those of the owner's brief, plus `config/config.example.toml`, `demo/run.sh`,
  `demo/README.md` (approved with D-A) and `src/config.rs` (D-B, approval asked with the plan).
