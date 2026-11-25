# Tests for controls already in the code (task T3: T12, T14, T15, T16, T17, T31): design

Date: 2026-11-25 (UTC). Branch: `test/t3-untested-controls` (from `main`, `e9beec2`). Plan:
`docs/superpowers/plans/2026-11-25-untested-controls.md`.

## Intent

Six rows of `docs/threat-model.md` have the status `not tested`: the control exists in the code, but
no test fails if it stops working. This task adds those tests, sees each one fail on a deliberate
breakage of its control and pass once the control is restored, and moves each row to `proven`. No
production code changes, unless a test reveals a real defect (then the work stops and the owner
decides). This is a study fork; see `CLAUDE.md` for what may not be claimed about it.

Outside review (2026-11-25, kept outside the repository): use oracles written by a third party
rather than the same code (RFC 9562 version and variant bits for UUID v7; negative JWE cases after
RFC 8725), cover every data route rather than a chosen few, keep each breakage as a replayable
patch, and do not call a row `proven` when its test never runs in CI.

## Current state (read in the code on 2026-11-25)

- T12: `src/domain/fingerprint.rs:21-22` builds an `HmacSha512` under the `key` of the request and
  hashes `data`. Routes: `/data/fingerprint`, `/cards/fingerprint`, `/api/v2/vault/fingerprint`
  (`src/routes/data.rs:342-353`), single or batch. Only the primitive is unit-tested.
- T14: with `key_custodian`, `GlobalAppState::new` starts with no tenant state
  (`src/tenant.rs:88-92`); `get_app_state_of_tenant` (`src/tenant.rs:133-143`) answers
  `CustodianLocked` (HTTP 401, `{"code":"TE_00","message":"Custodian is locked","data":null}`)
  until `/custodian/decrypt` inserts the state. Every data route resolves the tenant through
  `TenantStateResolver` (`src/custom_extractors.rs:21-33`).
- T15: `TenantStateResolver` refuses a missing header and calls `is_known_tenant`
  (`src/custom_extractors.rs:25-31`, `src/tenant.rs:145-150`): HTTP 400, `TE_03`,
  `Tenant error: Invalid x-tenant-id`. Behind it, an unknown tenant also has no state (401), so the
  test must tell the two refusals apart by their body.
- T16: with `middleware`, a layer over `/data`, `/cards`, `/api/v2/vault` and `/entity`
  (`src/app.rs:234-240`; `/custodian` and `/health` are added after it and stay in clear) reads a
  JWE body, decrypts it with the locker private key (RSA-OAEP-256), verifies the inner JWS with the
  tenant public key (RS256) (`src/middleware.rs:58-60`), signs the response with the locker key and
  encrypts it to the tenant key with RSA-OAEP and A256GCM (`src/middleware.rs:92-96`), except a
  signed-only response on `/api/v2/vault/fingerprint` when asked (`src/middleware.rs:38-45`,
  `src/middleware.rs:79-90`). Keys: `LOCKER__SECRETS__LOCKER_PRIVATE_KEY`,
  `LOCKER__TENANT_SECRETS__PUBLIC__PUBLIC_KEY`. With `key_custodian`, the keys are parsed at
  unlock. No CI job builds this feature for the end-to-end tests.
- T17: `LockerNew::new` (`src/storage/types.rs:178-180`) uses `generate_uuid`
  (`src/storage/utils.rs:8-10`, `Uuid::now_v7`) when the caller supplies no
  `requestor_card_reference`. (The doc comment above it still says "v4"; production code, left as
  is and reported.)
- T31: `deny.toml` and `.github/workflows/dependencies.yml` (cargo-deny on pull requests, `main`,
  weekly). No test reads either; cargo-deny is not installed locally.

## Decisions

- Technical choice: T12, T14, T15 and T17 are end-to-end tests in `tests/vault_e2e.rs`, with the
  existing harness (real PostgreSQL, real `locker` binary, harness caller key). Rejected: unit
  tests on the extractors, which would not prove that the routes use them.
- Technical choice: T16 is an end-to-end test in the same file under `#[cfg(feature =
  "middleware")]`, named `middleware_…` and run filtered on that prefix (the other tests send plain
  JSON and cannot pass under that feature), as the re-hash and rotation modes already are. The test
  client uses `josekit` directly, not the vault's `JWEncryption`, so that the request and response
  formats are checked by an independent encoder. Keys are two RSA 2048 pairs made at run time with
  the `rsa` dev-dependency, never printed. Rejected: a second test file with a copy of the harness.
- Technical choice: T31 is a test in a new file `tests/dependency_policy.rs` that reads `deny.toml`
  and the workflow as text and fails if the policy is weakened or the job stops running on pull
  requests, on `main` or weekly. It does not run cargo-deny: that the tool rejects each family was
  seen once in CI (row T31) and stays the evidence for that part. Rejected: a fixture run of
  cargo-deny (needs the tool and a CI line); a script in `scripts/` (needs the owner's agreement).
- Each breakage is written in the plan as a patch, with the failing line it produced, so that a
  reader can replay it; it is never committed.

## Requirements

- D1 (T15): a request with an unknown tenant id (`no-such-tenant`, `PUBLIC`, empty) or without the
  header is refused on every data route (v1 add, retrieve, delete, fingerprint under `/data` and
  `/cards`; v2 add, retrieve, delete, fingerprint; `/entity`) with HTTP 400 and the exact tenant
  error body, writes no row in `locker`, `hash_table`, `merchant`, `fingerprint`, `vault`, `entity`;
  with `key_custodian`, the custodian route refuses it too; the configured tenant still reads its
  card. Verifiable by: `unknown_tenant_is_refused_on_every_data_route` green, and red with
  `state.is_known_tenant(tenant_id)?;` removed from `src/custom_extractors.rs:31`.
- D2 (T14): with `key_custodian`, every data route of D1 answers HTTP 401 and the exact lock body
  before any key, with key 1 only, and with both keys before decrypt; no row is written; after
  decrypt, a card is stored and read back. Verifiable by: `data_routes_are_refused_before_unlock`
  green, and red with the tenant states built at start-up under `key_custodian`.
- D3 (T17): a generated card reference is 36 characters, parses as a UUID, has version bits 0111
  and variant bits 10, a 48-bit timestamp within 5 s of the add and no card number; three adds give three references, each stored as a `locker_id`; a supplied
  reference is kept. Verifiable by: `generated_card_reference_is_a_uuid_v7` green, and red with
  `generate_uuid` returning a 36-character id that is not a UUID v7.
- D4 (T12): on `/data/fingerprint`, single and batch, the same card under two caller keys gets two
  fingerprint ids; the same key twice the
  same id; another card another id; a batch with both keys returns the same two ids; the table
  holds one row per key and card; no response holds the card number. The test compares fingerprint
  ids only and computes no hash. Verifiable by: `fingerprint_differs_for_two_caller_keys` green, and red with the
  key ignored in `src/domain/fingerprint.rs:21`.
- D5 (T16): with `middleware` and `key_custodian`: a plain JSON add is refused and writes no row; a
  JWE add and retrieve succeed, their raw response bodies hold neither the card number nor
  `card_reference` and decrypt to the expected payload; asking for a signed-only response on
  retrieve still gets a JWE; a request signed with another key, a request with an altered tag, and
  a request encrypted with another algorithm are refused and write no row. Verifiable by: the
  `middleware_` tests green, and red with the response sent in clear and with the signed-only path
  check removed.
- D6 (T31): `deny.toml` checks every feature, lists every vulnerability exception with a reason
  and the expiry date, keeps the license list and the source rules; the workflow runs on pull
  requests, pushes to `main` and a weekly schedule, has no `continue-on-error`, and runs
  `cargo deny --locked check advisories licenses sources`. Verifiable by: the
  `dependency_policy` tests green, and red with `unknown-git = "allow"` and with the
  `pull_request` trigger removed.
- D7: each row moves to `proven` and cites its tests; the header list of end-to-end rows gains
  T12, T14, T15, T17 (and T16 with its command); shifted `file:line` are fixed; what a test does
  not cover stays in the row; `scripts/check-threat-model.sh` exits 0. T16 moves to `proven` only
  if the owner accepts a CI line that runs its tests; otherwise it stays `not tested` and its
  Evidence names the local test. Verifiable by: the script output.
- D8: README "Changes from the original" lists every changed file. Verifiable by:
  `git diff main --name-only` against the README entry.

## Out of scope

- Production code, configuration, migrations, `deny.toml`, workflows, scripts (a CI line for T16
  only after the owner's yes).
- Whether the "Dependencies" check is required before merging (a repository setting), and whether
  GitHub keeps the weekly schedule after 60 days without activity: noted in row T31, not tested.
- A demonstration of computing a fingerprint without its key (embargo until 2026-12-21).
