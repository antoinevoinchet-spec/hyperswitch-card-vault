# Open limits found while reviewing the code (task T20): design

## Goal

Record in the threat model the limits found in a review of the code that the table does not yet
describe. Documents only: no change to the vault, its tests or its configuration. Each limit is
checked in the code of `main` (commit `6a3f637`) before it is written; nothing is copied from the
review's own text.

## Scope

- In: `docs/threat-model.md`, `README.md` ("Changes from the original"), this design and its plan.
- Out: any code fix (each becomes a later task, chosen by the owner).
- No compliance wording, and none of the words the checker refuses (its rule 12).

## Approach

One new `open` row per cause, not per report: two limits with one cause share a row. A limit that
belongs to an existing row is added to that row's "Not covered" list or to its control text, and
refers to the row that already states the rest instead of repeating it. Each new row cites the
lines that show the limit, as the checker requires for `open` rows. Rows describe the behaviour
read in the code only: no "by design", no "should", no fix.

The disposition of every reviewed item (new row, addition, already stated, or left to a later task,
with the lines read) is kept in a private note in a folder that git ignores, never committed.

Choice: rows grouped by cause; rejected: one row per reported item, which would repeat the same
control (for example the custodian routes) in several rows.

## Requirements

- D1. New open rows, each with threat, attack in prose, control (`none: …` with the lines read) and
  evidence (the same lines): T41 `/entity` callable without a caller key; T42 custodian routes
  unauthenticated and in clear without TLS; T43 with the external key manager, a merchant not yet
  transferred gets a new key; T44 `/key/transfer` callable without a caller key, unbounded batch;
  T45 HTTP method used as a metric label; T46 deep health check holds main-pool connections on a
  fixed key; T47 one delete rate limit for every tenant, spent before the caller check; T48
  application log holds caller references and card-derived hashes; T49 an add answered with an
  earlier row without checking its lifetime (TTL) or its card.
  Checked by: `grep -c '^| T4[1-9] |' docs/threat-model.md` prints 9, and each row's cited lines
  show the limit when opened.
- D2. Additions to existing rows: T16 (a compressed body is inflated without a size bound before the
  signature check, read in the JOSE library's code); T19 (caller key outside the JWE envelope, in
  clear without TLS); T29 (the kept hash row also serves someone who holds the master key); T37 (an
  upsert by a caller with the `add` right only writes the audit row of an add; an add tells whether
  the stored name and card expiry date match); T38 (merchant keys are wrapped with empty associated data too,
  referring to T13).
  Checked by: `git diff main -- docs/threat-model.md` shows these five rows changed and no other
  existing row changed.
- D3. The table stays valid. Checked by: `scripts/check-threat-model.sh` exits 0 and prints 49 rows
  (24 proven, 0 not tested, 25 open).
- D4. No forbidden wording. Checked by: the checker passes (rule 12), and a search of the diff for
  compliance, certification, audit or production-readiness claims finds none.
- D5. `README.md` lists the change under "Changes from the original". Checked by: the diff of
  `README.md` adds one entry naming `docs/threat-model.md`, this design and its plan.
- D6. Every reviewed item has a disposition in the private note, and every "new row" or "addition"
  there is found in the diff. Checked by: a line-by-line comparison of the note with the diff,
  before the reviews.
