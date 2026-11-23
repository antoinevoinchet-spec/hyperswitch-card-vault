# Threat model table: design

Date: 2026-11-23. Branch: `chore/threat-model-table` (from `main`, `7d1bdfb`). Status: owner
decisions Q1 to Q3 taken; waiting for approval of the design.

## Intent

A visitor of this fork should be able to see, in about two minutes, which protections of the vault
are backed by a test, which test it is, and which limits are still open. The owner does not read
Rust, so every statement in the table must be checkable by a command, not by reading code.

The deliverable is a table, `docs/threat-model.md`, that links each threat to the attack it stands
for, the code that counters it, the evidence that this code works, and a status. A shell script,
`scripts/check-threat-model.sh`, checks mechanically that every cited test exists and every cited
`file:line` points to a real, non-empty line, so the table cannot quietly drift from the code.

This is a study fork; see `CLAUDE.md` for what may not be claimed about it. The table adds no feature,
no Rust test and no attack demonstration.

Research report reused: the owner's 2026-11-23 research note on the fork's next steps (idea I2,
"threat, demonstrated attack, fix, test"), kept outside the repository.

## Requirements

- **D1** A table in `docs/threat-model.md` with at least 12 rows and a status column whose values
  are only `proven`, `not tested` or `open`.
  Verifiable by: `scripts/check-threat-model.sh` (it fails on any other status value and on fewer
  than 12 rows).
- **D2** A row is `proven` only if its evidence cites at least one existing test name or one check
  printed by `make demo`. A protection without such evidence is `not tested`.
  Verifiable by: the script fails on a `proven` row without a test or demo check; human review of
  each `proven` row by a fresh reviewer.
- **D3** Every known limit listed by the owner has its own `open` row: caller-chosen reference not
  checked; no per-caller access rule or masking; custodian unlock before the database role is
  narrowed; old `hash_table` rows not converted; a master key change would change every
  duplicate-check hash; the master key must stay secret even with an external key manager;
  cross-merchant link in `hash_table`; small response-time difference when the card is already
  known.
  Verifiable by: `grep -c '| open |' docs/threat-model.md` is at least 8, and a row-by-row read.
- **D4** Every test name cited exists in `src/` or `tests/` as a function; every `file:line` or
  `file:start-end` cited exists and every cited line is non-empty; every quoted `make demo` check
  appears in `demo/run.sh`.
  Verifiable by: `scripts/check-threat-model.sh` exits 0 on the final table.
- **D5** The script exits non-zero on a copy of the table with an invented test name, and on a copy
  where a cited line is past the end of its file.
  Verifiable by: both runs shown in the final report, with their output.
- **D6** The row on the unkeyed duplicate-check hash describes the attack in prose only: no script,
  no command that replays it, no identifier of or link to the private report sent upstream.
  Verifiable by: `grep -c -i -E 'GHSA|advisories' docs/threat-model.md README.md` gives 0 for each
  file, and a read of that row.
- **D7** `README.md` links to `docs/threat-model.md`, and its "Changes from the original" list names
  every file changed on the branch.
  Verifiable by: `git diff --name-only main` compared with the list.
- **D8** No code changes: `src/`, `tests/`, `demo/`, migrations, `config/`, `Cargo.toml`,
  `Cargo.lock`, `LICENSE`, `.typos.toml`, `CLAUDE.md` untouched; in `.github/workflows/`, only the
  new job approved in Q2.
  Verifiable by: `git diff --name-only main -- src tests demo config migrations Cargo.toml
  Cargo.lock .github CLAUDE.md .typos.toml LICENSE` prints only `.github/workflows/CI-pr.yml`, and its diff adds one job and changes no existing line.
- **D9** Non-regression: `cargo test -j 4` passes with at least 38 tests, and `make demo` prints
  `DEMO OK`.
  Verifiable by: the last lines of both commands.

## Current state (read in the code on 2026-11-23)

- `docs/tokenization.md` already cites `file:line` and test names for most protections (sections
  "How the vault maps onto it" and "What the vault does not do"). The table reuses its wording and
  references, and `docs/tokenization.md` gets only a link to the table.
- Tests that back a protection: 11 unit tests in `src/audit.rs`, 13 in
  `src/crypto/hash_manager/managers/sha.rs`, 2 each in `aes.rs` and `jw.rs`, and 6 end-to-end tests
  in `tests/vault_e2e.rs` (run only with `--features key_custodian` and a database; in CI by the
  `End-to-end tests and demo against PostgreSQL` job).
- `make demo` prints six checks (`demo/run.sh:220-226`) and `DEMO OK` only if they all match.
- Gaps found while reading, which become `not tested` rows: per-merchant key separation (no test
  shows that one merchant's key cannot decrypt another merchant's card); data calls refused while
  the custodians have not unlocked the vault (`CustodianLocked`, `src/tenant.rs:142`); unknown tenant
  refused (`src/custom_extractors.rs:26-30`); the JWE envelope on the request path (only the
  `test_jwe` / `test_jws` primitives are tested); the generated `card_reference` being a random UUID
  (no test checks its form).
- The fingerprint route uses `HmacSha512::<1>`, which computes `HMAC(K, HMAC(K, x))` (see the keyed
  card hash design). Its tests (`test_key_not_equal`…) check the primitive, not the route.

## Approaches considered

1. **One table, one row per threat, with a checker script (chosen).** Every
   row carries its own evidence; the script makes the references self-checking. Cost: a wide table.
2. **Two tables, "protections" and "open limits".** Easier to read, but a limit and the protection it
   weakens end up far apart (for example the keyed hash and the master key that must stay secret).
3. **Prose page with inline references, like `docs/tokenization.md`.** Already exists; it does not
   give the two-minute overview the owner asked for, and a script cannot easily tell which test backs
   which claim.

## Table format (Q1 decided)

Columns, in this order:

| Column | Content |
|---|---|
| `ID` | `T1`, `T2`… stable, so the README and later tickets can cite a row. |
| `Threat` | What could go wrong, in one plain sentence. |
| `Attack` | How someone would try it, in prose. Never a command. |
| `Control` | What the code does about it, with `file:line` in backticks. `none` for an open row without a control. |
| `Evidence` | Test names in backticks, and/or a `make demo` check quoted exactly as printed, or the doc that describes the limit. |
| `Status` | `proven`, `not tested` or `open`. |

Rows are grouped by status: `proven`, then `not tested`, then `open`. A short header explains how to
re-run the evidence (`cargo test -j 4`, the end-to-end command, `make demo`) and the script.

## Rows (draft list, references fixed at implementation)

`proven`:

- T1 Card read from a stolen database copy: card data encrypted with AES-256-GCM before insert.
  Evidence: demo check on `locker` rows containing the card number in clear (0);
  `test_gcm_aes_256_encode_message`, `test_gcm_aes_256_decode_message`.
- T2 One custodian, or a wrong key, unlocks the vault: `custodian_steps_write_audit_rows` (wrong
  key 2, decrypt refused), `custodian_key_is_refused_when_audit_table_is_unwritable` (key 1 missing,
  decrypt refused).
- T3 A card leaves the vault without a trace: `retrieve_fails_closed_when_audit_table_is_unwritable`,
  `record_fails_closed_when_sink_fails`.
- T4 A custodian key is held without a trace: `custodian_key_is_refused_when_audit_table_is_unwritable`.
- T5 The audit log leaks the card number: `store_card_entry_never_contains_card_number`,
  `store_data_entry_never_contains_payload`, `audit_row_is_written_for_each_card_step`, demo check.
- T6 The audit log leaks a key: `custodian_steps_write_audit_rows` (no key in any row),
  `fingerprint_entry_has_no_payload`, demo check on generated key values (0).
- T7 A card-shaped id chosen by the caller reaches the log: `pending_redacts_card_shaped_ids`.
- T8 Free text or control characters injected into the log: `parse_request_id_rejects_non_uuid`,
  `pending_strips_control_characters`, `pending_truncates_long_ids`.
- T9 Card numbers recovered from `hash_table` by trying every candidate (the former unkeyed hash;
  attack in prose only, D6): keyed HMAC-SHA512, `stored_card_hash_is_not_a_plain_sha512`,
  `card_dedup_differs_from_plain_sha512_and_from_master_key`, `hmac_sha512_matches_rfc4231_case_2`.
- T10 The duplicate-check key is shared across tenants or equals another key: HKDF with a specific
  context; `card_dedup_two_master_keys_give_two_hashes`,
  `card_dedup_key_is_hkdf_of_master_key_with_context`, `card_dedup_context_is_versioned_and_specific`,
  `card_dedup_rejects_empty_master_key`.
- T11 The duplicate check stops working (one card, two rows): `same_card_for_two_merchants_shares_one_hash_row`,
  `card_dedup_same_card_same_key_gives_same_hash`.
- T12 The fingerprint can be computed without the caller's key, at the primitive level:
  `test_key_not_equal`, `test_key_equal`. The row says that the route itself is not tested.

`not tested`: T13 per-merchant key separation; T14 data calls while locked; T15 unknown tenant;
T16 JWE envelope on requests; T17 generated reference is a random UUID.

`open`: T18 to T25, the eight limits of D3. Two more from `demo/README.md` "Known limits":
T26 requests rejected before the handler leave no audit row; T27 for an add or a delete, the
database change has happened when the audit write fails.

## Checker script

`scripts/check-threat-model.sh [table.md]` (default `docs/threat-model.md`), POSIX tools only (`bash`,
`awk`, `grep`, `sed`, `wc`), so it runs on macOS and on the CI runner without installing anything.
For each table row (a line starting with `| T`):

1. the status cell is `proven`, `not tested` or `open`;
2. every backticked `path:N` or `path:N-M` names an existing file, `N ≤ M ≤` line count, and every
   line in the range is non-empty;
3. every backticked identifier made of lowercase letters, digits and underscores that contains an
   underscore is a test name: `grep -r -E "fn NAME\(" src tests` must find it;
4. every quoted demo check (text between `“demo:` markers, exact format fixed in the plan) is found
   with `grep -F` in `demo/run.sh`;
5. a `proven` row cites at least one test name or demo check;
6. the table has at least 12 rows.

It prints one line per failure (`T7: test not found: foo_bar`) and a summary per status, and exits 1
if anything failed. It reads no `.env` file and no configuration.

## Decisions for the owner

- **Q1** Columns of the table. Decided on 2026-11-23: the six columns above (`ID`, `Threat`,
  `Attack`, `Control`, `Evidence`, `Status`), preferred over a four-column variant that merged threat
  with attack and control with evidence.
- **Q2** Whether CI runs the script on every PR. Decided on 2026-11-23: yes, as a new job
  `Threat model references` in `.github/workflows/CI-pr.yml` that runs only the script (no Rust
  build); existing jobs unchanged. The exact lines are shown to the owner before they are written.
- **Q3** Whether to install `cargo-mutants` and report a mutation score for `sha.rs` and `audit.rs`.
  Decided on 2026-11-23: not in this ticket, but to be done later (see "Later work"). Reason: the
  tests that best protect `src/audit.rs` need PostgreSQL, which a plain mutation run would not
  start, so the published score would be misleadingly low.

## Calls made by the builder

- Rows grouped by status rather than by component, so the reader sees what is proven first.
- A row that a test proves only at the primitive level says so in its threat text (T12).
- `docs/tokenization.md` keeps its own references; the script checks only the table (checking the
  whole doc is a later option).

## Later work (decided, not in this ticket)

- Mutation score with `cargo-mutants` on `src/crypto/hash_manager/managers/sha.rs` and
  `src/audit.rs` (owner decision Q3), with the end-to-end tests running against PostgreSQL so that
  they count, `-j 1` on the 8 GB Mac. Each surviving mutant becomes an `open` row of the table.
- I6 (scope of the duplicate check), as already ordered by the owner.

## Non-goals

No new test, no attack script, no refactoring, no wording that `CLAUDE.md` forbids, no change to `CLAUDE.md` or
`.typos.toml`.
