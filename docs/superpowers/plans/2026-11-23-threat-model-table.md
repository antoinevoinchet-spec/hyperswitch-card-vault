# Threat Model Table Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish `docs/threat-model.md`, a table linking each threat to its attack, control, evidence
and status, kept true by `scripts/check-threat-model.sh` locally and in CI.

**Architecture:** One Markdown table (six columns, rows `T1`…), one dependency-free Bash checker that
parses the table rows and checks every cited test, `file:line` and demo check against the repository,
and one new CI job that runs the checker. No Rust code changes.

**Tech Stack:** Markdown, Bash 3.2-compatible shell (`awk`, `grep`, `sed`), GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-23-threat-model-table-design.md`

## Global Constraints

- Everything written to the repository is in English; Markdown words must pass `typos` (CI job
  `Spell check`): write whole words, separate `grep` options (`-i -n -E`).
- No wording forbidden by the third rule of `CLAUDE.md`, not even negated or quoted, in files,
  commit messages, PR title or PR body. The search pattern for it is typed in the shell only, never
  written in a repository file, so the search over added lines stays meaningful.
- No `GHSA` and no `advisories` in `docs/threat-model.md` or `README.md`; the unkeyed-hash attack is
  prose only, with no command that replays it.
- Statuses: exactly `proven`, `not tested`, `open`. A row is `proven` only with an existing test
  name or a `make demo` check as evidence.
- Do not touch `src/`, `tests/`, `demo/`, `migrations/`, `config/`, `Cargo.toml`, `Cargo.lock`,
  `LICENSE`, `.env`, `.typos.toml`, `CLAUDE.md`; in `.github/workflows/CI-pr.yml`, only add the job
  of Task 4.
- Never read or print `.env*`, a key or the `master_key`.
- `cargo` commands are prefixed by `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"`
  and use `-j 4`.
- Every `gh pr` or `gh issue` command that writes passes `-R antoinevoinchet-spec/hyperswitch-card-vault`.
  The only command aimed at `juspay/hyperswitch-card-vault` is the read-only `gh pr list` that the
  owner's completion criteria require (Task 7 step 5).
- Commit after each verified task; `git status` before each commit; messages in English, ending with
  the session's attribution lines.

## Review Focus

1. A non-test function cited as a test (the helper `store_card_for` in `tests/vault_e2e.rs`): the
   checker must reject it, since only a function under `#[test]` or `#[tokio::test]` counts (Task 1,
   case `helper`).
2. A pipe character inside a cell shifts the columns, so the status is read from the wrong cell: the
   checker fails on a row that does not have exactly six cells (Task 1, case `pipe`).
3. A reversed or zero range (`src/audit.rs:20-10`, `src/audit.rs:0`): rejected (Task 1, case
   `range`).
4. A cited line that exists but is blank: rejected (Task 1, case `blank`).
5. A malformed row ID (`| T 5 |`) that would silently skip every check of its row: any table line
   that is neither the header, the separator nor a `T<n>` row fails (Task 1, case `bad-id`).

---

### Task 1: Checker script, seen failing first

**Covers:** D1, D2, D4, D5, D6

**Files:**
- Create: `scripts/check-threat-model.sh` (executable)
- Fixtures (not committed): `$SCRATCH/tm/*.md`, where `$SCRATCH` is the session scratchpad

**Interfaces:**
- Produces: `scripts/check-threat-model.sh [TABLE]`, `TABLE` defaulting to `docs/threat-model.md`,
  run from the repository root. Exit 0 and a last line
  `OK: <n> rows (<p> proven, <t> not tested, <o> open)`; exit 1 after one line per failure,
  formatted `<ID>: <reason>` (or `table: <reason>`), then `FAILED: <k> problem(s)`.

**Rules the script enforces.** A table line is any line starting with `|`. The first two (header and
separator) are skipped; every other one must be a row matching `^\| T[0-9]+ \|`. Cells split on `|`.

1. every table line after the separator is a `T<n>` row;
2. each row has exactly six cells: `ID | Threat | Attack | Control | Evidence | Status`;
3. IDs are unique;
4. the Status cell, trimmed, is `proven`, `not tested` or `open`;
5. in any cell, every backticked `path:N` or `path:N-M` (path made of `[A-Za-z0-9_./-]`): the file
   exists, `1 ≤ N ≤ M ≤` the file's line count (counted with `awk 'END{print NR}'`), and lines N and
   M contain a non-space character (blank lines inside a cited block are normal and allowed);
6. the Control cell is `none` or holds at least one backticked `path:N`;
7. in the Evidence cell, every backticked word matching `^[a-z][a-z0-9]*_[a-z0-9_]+$` is a test: a
   line `fn <name>(` within the three lines that follow `#[test]` or `#[tokio::test]` in `src/` or
   `tests/`; table and field names in Evidence are written without backticks;
8. in the Evidence cell, every `demo check "<label>"` has `<label>:` found by `grep -F` in
   `demo/run.sh`;
9. a `proven` row has at least one test name or demo check in Evidence; an `open` row has at least
   one backticked `path:N` in Evidence (the doc lines that describe the limit);
10. the Attack cell holds no backtick (prose only, never a command);
11. at least 12 rows;
12. the table file contains neither `GHSA` nor `advisories` (case-insensitive).

- [ ] **Step 1: Write the fixtures**

First check each range used below with `sed -n 'Np;Mp'` (both ends non-empty). In `$SCRATCH/tm/`,
write `good.md` with two valid `proven` rows (tests
`record_fails_closed_when_sink_fails` and `pending_redacts_card_shaped_ids`, refs `src/audit.rs:213`
and `src/audit.rs:66-96`, one demo check `"audit rows containing the card number"`) plus ten `open`
rows with Control `none` and evidence `docs/tokenization.md:102-136`, so it has 12 rows. Then one
copy per bad case, each changing a single thing in `good.md`:

| Fixture | Change | Expected line |
|---|---|---|
| `fake-test.md` | test name `record_never_fails_closed` | `T1: test not found: record_never_fails_closed` |
| `past-end.md` | `src/audit.rs:9999` | `T1: line past end of file: src/audit.rs:9999` |
| `helper.md` | test name `store_card_for` | `T1: test not found: store_card_for` |
| `pipe.md` | a `\|` inside the Threat cell | `T1: expected 6 cells, found 7` |
| `range.md` | `src/audit.rs:20-10` | `T1: bad range: src/audit.rs:20-10` |
| `blank.md` | `src/audit.rs:6` (empty line) | `T1: empty line: src/audit.rs:6` |
| `bad-id.md` | row ID `T 1` | `table: not a T<n> row: \| T 1 \|…` |
| `status.md` | status `done` | `T1: bad status: done` |
| `bare-proven.md` | a `proven` row with no test and no demo check | `T1: proven without a test or demo check` |
| `no-control.md` | Control cell `see code` | `T1: control cites no file:line` |
| `attack-code.md` | a backtick in the Attack cell | `T1: attack must be prose, no code` |
| `demo.md` | demo check `"rows that never existed"` | `T1: demo check not found: rows that never existed` |
| `short.md` | only 11 rows | `table: 11 rows, at least 12 expected` |
| `embargo.md` | the word `advisories` in a cell | `table: forbidden reference to a private report` |

- [ ] **Step 2: Write a stub that accepts everything, and watch the bad fixtures pass**

The stub prints `OK` and exits 0. Run the loop of step 4.
Expected: every fixture exits 0. This shows that the fixtures, not the script, carry the expected
failures (the red state).

- [ ] **Step 3: Write `scripts/check-threat-model.sh`**

`#!/usr/bin/env bash`, `set -u`, no associative arrays and no `mapfile` (macOS ships Bash 3.2). A
header comment lists the twelve rules. Keep it under about 180 lines.

- [ ] **Step 4: Run every fixture**

Run: `for f in "$SCRATCH"/tm/*.md; do echo "== $(basename "$f")"; ./scripts/check-threat-model.sh "$f"; echo "exit $?"; done`
Expected: `good.md` exit 0 with `OK: 12 rows (2 proven, 0 not tested, 10 open)`; every other fixture
exit 1 with its expected line from the table above.

- [ ] **Step 5: Commit** (the design is already committed on this branch)

Run first: `git branch --show-current` → `chore/threat-model-table`.

```bash
git add scripts/check-threat-model.sh docs/superpowers/plans/2026-11-23-threat-model-table.md
git commit -m "chore: add checker for the threat model table"
```

### Task 2: The table

**Covers:** D1, D2, D3, D4, D6

**Files:**
- Create: `docs/threat-model.md`
- Modify: `docs/tokenization.md` (one sentence after the intro, linking `threat-model.md`; no other
  change). Done first, so the lines the table cites in it do not move afterwards: the checker would
  not notice a shift to another non-empty line.

**Interfaces:**
- Consumes: `scripts/check-threat-model.sh` (Task 1).
- Produces: rows `T1`…`T27` in the order of the design (`proven`, then `not tested`, then `open`);
  Task 3 links to the page.

- [ ] **Step 0: Add the link sentence to `docs/tokenization.md`**, before any row cites that file.

- [ ] **Step 1: Write the page header**

Title `# Threat model`, then a short paragraph: study fork, see `CLAUDE.md`; what each column means;
how to re-run the evidence:
`cargo test -j 4` (unit tests);
`VAULT_TEST_DATABASE_URL=<admin URL> VAULT_TEST_REQUIRE_DB=1 cargo test -j 4 --features key_custodian --test vault_e2e`
(end-to-end tests, otherwise skipped; run in CI by the job `End-to-end tests and demo against
PostgreSQL`); `make demo`; and `scripts/check-threat-model.sh`. Note that the checker proves that
references exist, not that they say what the row claims, which a reader checks by opening them.

- [ ] **Step 2: Write rows T1 to T27**

Rows as listed in the design, section "Rows". For each `Control`, find the exact line with
`grep -n` and cite it as `path:N` or `path:N-M`; reuse the references of `docs/tokenization.md` after
checking that each still points to the described code. Evidence: test names in backticks, demo
checks as `demo check "<label>"` followed by the expected value in prose, doc lines in backticks.
T9 (unkeyed hash) describes the attack in prose only. T12 is `not tested` (owner's rule: a
protection whose own path has no test is not proven): it cites `test_key_not_equal` and
`test_key_equal` and says they test the primitive, not the route. Before writing T18 to T25, find
each of the eight limits with `grep -n` in `docs/tokenization.md` and `demo/README.md`; a limit
described in neither cites the code line that creates it. T13 to T17 cite their control and say what test is missing. T18 to
T27 cite the doc lines that describe them.

- [ ] **Step 3: Run the checker on the table**

Run: `./scripts/check-threat-model.sh; echo "exit $?"`
Then `grep -c '| open |' docs/threat-model.md` → at least 8.
Expected: exit 0, `OK: 27 rows (11 proven, 6 not tested, 10 open)` (counts may move if a row
changes status for a reason stated in the final report).

- [ ] **Step 4: Prove the checker on copies of the real table**

Copy `docs/threat-model.md` twice into `$SCRATCH/tm-real/`: in one, replace a cited test name with
`record_never_fails_closed`; in the other, replace one cited line number with `9999`. Run the
checker on both.
Expected: exit 1 for each, with the matching `test not found` / `line past end of file` line. Keep
both outputs for the final report.

- [ ] **Step 5: Commit**

```bash
git add docs/threat-model.md
git commit -m "docs: add threat model table with evidence for each row"
```

### Task 3: Link from README

**Covers:** D6, D7

**Files:**
- Modify: `README.md` ("Demo" section: one sentence linking `docs/threat-model.md`; "Changes from
  the original": a new group "Threat model table" listing, with full paths, `docs/threat-model.md`,
  `scripts/check-threat-model.sh`, `.github/workflows/CI-pr.yml` (new job; added only once Task 4 is
  approved), `docs/tokenization.md` (link), the design and the plan)

- [ ] **Step 1: Edit `README.md`**
- [ ] **Step 2:** `git diff -U0 main -- docs/tokenization.md` → only the sentence added in Task 2
  step 0; `./scripts/check-threat-model.sh` → exit 0.
- [ ] **Step 3:** `grep -c -i -E 'GHSA|advisories' README.md docs/threat-model.md` → `0` for each.
- [ ] **Step 4: Commit** `docs: link the threat model table from README`

### Task 4: CI job (owner approval of the exact lines first)

**Covers:** D4, D8 (owner decision Q2)

**Files:**
- Modify: `.github/workflows/CI-pr.yml` (append one job after `typos`, before `integration-db`)
- Modify: `README.md` (add the `.github/workflows/CI-pr.yml` line to the "Threat model table" group)

- [ ] **Step 1: Show the owner DOING / EXPECT / IF WRONG and these lines, and wait for yes**

`actions/checkout@v7` is the version every existing job of `CI-pr.yml` uses (read on 2026-11-23).

```yaml
  threat-model:
    name: Threat model references
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v7

      - name: Check the threat model table
        run: ./scripts/check-threat-model.sh
```

If the owner says no: skip this task; the README does not list the CI file.

- [ ] **Step 2: Insert the job and the README line, then check that nothing was removed**

Run: `git diff --numstat main -- .github/workflows/CI-pr.yml`
Expected: `10	0	.github/workflows/CI-pr.yml` (nine job lines plus one blank separator line, 0
removed).

- [ ] **Step 3: Commit** `ci: run the threat model checker on pull requests`

### Task 5: Fresh review

**Covers:** D2, D3, D6

- [ ] **Step 1:** In parallel: a fresh subagent (`model: opus`), allowed to read the repository, gets
  the owner's request word for word, `docs/threat-model.md`, the checker, the note that T2 to T6 rest
  on end-to-end tests that run only with a database, the instruction to open every test cited by a
  `proven` row and say whether it checks the row's claim, and the criteria "each `proven` row is really proven by
  the cited test; each `open` limit of the request has its row; no replayable attack in T9", and
  returns only the gaps that change the result; and `second-avis --reserve 50` on the same diff.
- [ ] **Step 2:** Fix what holds up, then run Task 6 in full (whether or not anything changed).
  Commit `docs: address review of the threat model table` if files changed.

### Task 6: Final checks (re-run in full after any later change)

**Covers:** D7, D8, D9

- [ ] **Step 1:** `cargo test -j 4` → exit 0, at least 38 passed (sum of the `test result:` lines).
- [ ] **Step 2:** End-to-end tests for real: start a throwaway PostgreSQL cluster in `$SCRATCH`
  (`initdb`, `pg_ctl -o "-p 54330 -k $SCRATCH/pg"`), then run the end-to-end command of Task 2 step 1
  with `VAULT_TEST_DATABASE_URL=postgres://$USER@localhost:54330/postgres` and
  `VAULT_TEST_REQUIRE_DB=1` → `6 passed`; stop and delete the cluster. If it cannot run, say so in
  the final report: `proven` rows T2 to T6 then rest on the CI run only.
- [ ] **Step 3:** `make demo` → last line `DEMO OK`.
- [ ] **Step 4:** `./scripts/check-threat-model.sh` → exit 0.
- [ ] **Step 5:** `git diff --name-only main -- src tests demo config migrations Cargo.toml Cargo.lock .github CLAUDE.md .typos.toml LICENSE`
  → only `.github/workflows/CI-pr.yml` (nothing if Task 4 was refused).
- [ ] **Step 6:** README lists every changed file:
  `grep -c -F 'docs/threat-model.md' README.md` → at least 1, and
  `for f in $(git diff --name-only main | grep -v '^README.md$'); do grep -q -F "$f" README.md || echo "MISSING $f"; done` → no output.
- [ ] **Step 7:** Forbidden wording (pattern typed in the shell from the third rule of `CLAUDE.md`)
  on the lines added by `git diff main`, and on `git log main..HEAD --format=%B` → 0 each.
  `grep -c -i -E 'GHSA|advisories' docs/threat-model.md README.md` → `0` each.
- [ ] **Step 8:** Spelling: `typos` is not installed on this Mac and installing it needs the
  owner's approval, so the spelling is checked only by the CI job `Spell check`; say so in the
  report.
- [ ] **Step 9:** `git status --porcelain` → empty.

### Task 7: Push, PR, merge (each with owner approval)

**Covers:** D4, D8, D9 (the same checks, run by CI on the PR)

- [ ] **Step 1:** `git remote get-url origin` → the `antoinevoinchet-spec/hyperswitch-card-vault`
  URL. Draft the PR title and body; run the forbidden-wording search of Task 6 step 7 on them → 0.
- [ ] **Step 2:** Show DOING / EXPECT / IF WRONG with the title and body, wait for yes, then
  `git push -u origin chore/threat-model-table` and
  `gh pr create -R antoinevoinchet-spec/hyperswitch-card-vault --base main --head chore/threat-model-table --title … --body …`.
- [ ] **Step 3:** `gh pr checks <n> -R antoinevoinchet-spec/hyperswitch-card-vault --watch` → all
  `pass` (7 jobs), or report the failing step and message as is. A failure caused by the original
  code is reported to the owner before any fix.
- [ ] **Step 4:** Show DOING / EXPECT / IF WRONG, wait for yes, then
  `gh pr merge <n> -R antoinevoinchet-spec/hyperswitch-card-vault --merge` (no `--delete-branch`).
- [ ] **Step 5:** `gh pr list -R juspay/hyperswitch-card-vault --author antoinevoinchet-spec --state all`
  (read-only, owner's criterion) → no line. Then `git switch main && git pull --ff-only`,
  `git diff chore/threat-model-table main --stat` → empty (the merged tree is the one that passed
  Task 6), and `git status --porcelain` → empty.
