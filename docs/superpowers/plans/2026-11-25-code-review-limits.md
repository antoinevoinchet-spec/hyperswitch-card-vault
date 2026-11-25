# Open limits found while reviewing the code (task T20): plan

Design: `docs/superpowers/specs/2026-11-25-code-review-limits-design.md`. Branch:
`chore/t20-code-review-limits`.

## Global Constraints

- Only `docs/threat-model.md`, `README.md` ("Changes from the original" only) and
  `docs/superpowers/` change.
- Every cited line is read on this branch before it is cited; `src/` is unchanged since the review.
- Rows cite `path:line` only and never copy a value from a configuration file.
- Attacks are prose, never a command; no backtick in the Attack cell.
- Rows describe the behaviour read in the code: no "by design", no "should", no fix.
- After each edit: `scripts/check-threat-model.sh` exits 0.
- One logical change per commit, `git status` before each.

### Task 1: new open rows T41 to T49
**Couvre:** D1, D3, D4

Append the nine rows after T40, each with the lines listed in the private note and read again in
the code. Run the checker (49 rows, 25 open) and `grep -c '^| T4[1-9] |' docs/threat-model.md`
(9). Commit.

### Task 2: additions to T16, T19, T29, T37 and T38
**Couvre:** D2, D3, D4

Edit the five rows only, from the private note; the T38 addition refers to T13 instead of
repeating it; the T16 addition completes its existing sentence on compressed bodies (unbounded
inflation before the signature check) instead of adding a second one. Use "card expiry date" in T37
and "lifetime (TTL)" in T49. Run the checker and `git diff main -- docs/threat-model.md` (T16, T19,
T29, T37, T38 changed, no other existing row). Commit.

### Task 3: README entry
**Couvre:** D5, D4

Add the entry under "Changes from the original". Run the checker. Commit.

### Task 4: reviews before "ready"
**Couvre:** D1, D2, D3, D4, D5, D6

1. Compare the private note with the diff, line by line (D6).
1b. Leak check on `git diff main` (design, plan, table, README): a case-insensitive search for the
   checker's rule-12 words, the review report's folder name, the reviewed commit and the word
   embargo finds nothing; a search for compliance, certification, audit or production-readiness
   claims finds none (D4); `git check-ignore -v` confirms the private note's folder is ignored.
2. `security-review` on the branch.
3. A fresh Opus reviewer, run locally, given the owner's request, the private note, the diff and
   these criteria.
4. `second-avis --reserve 50` given the diff of the tracked files only: no request text, no private
   note, no path to the review.
5. Apply confirmed remarks, rerun the checker, commit.
