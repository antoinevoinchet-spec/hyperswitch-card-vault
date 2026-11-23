#!/usr/bin/env bash
# Checks that every reference in the threat model table points to something real.
#
# Usage: scripts/check-threat-model.sh [TABLE]   (default: docs/threat-model.md)
#
# A table line is a line starting with "|". The first two (header and separator) are skipped. Rules:
#  1. every other table line is a row whose ID is "T<n>";
#  2. each row has exactly six cells: ID | Threat | Attack | Control | Evidence | Status;
#  3. IDs are unique;
#  4. the status is "proven", "not tested" or "open";
#  5. every backticked `path:N` or `path:N-M` names an existing file, 1 <= N <= M <= its line count,
#     and lines N and M are not blank (blank lines inside a cited block are allowed);
#  6. the Control cell is "none" or cites at least one `path:N`;
#  7. every backticked snake_case word in the Evidence cell is a test: a "fn <name>(" within the
#     three lines after #[test] or #[tokio::test] in src/ or tests/;
#  8. every `demo check "<label>"` in the Evidence cell is printed by demo/run.sh as "<label>:";
#  9. a "proven" row cites a test or a demo check; an "open" row cites the doc or code lines that
#     describe it;
# 10. the Attack cell holds no backtick: attacks are described in prose, never as a command;
# 11. the table has at least 12 rows;
# 12. the file contains no reference to the private report sent upstream.
#
# It proves that references exist, not that they say what the row claims. It reads no secret.
set -u

table=${1:-docs/threat-model.md}
case $table in
  /*) ;;
  *) table="$PWD/$table" ;;
esac
cd "$(dirname "$0")/.." || exit 2

if [ ! -f "$table" ]; then
  echo "table: file not found: $table"
  exit 2
fi

fails=0
fail() {
  echo "$1: $2"
  fails=$((fails + 1))
}

trim() {
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# Names of every test function, one per line.
tests=$(grep -r -h -A3 -E '#\[(tokio::)?test' src tests | grep -o -E 'fn [a-z0-9_]+\(' |
  sed -e 's/^fn //' -e 's/($//' | sort -u)

# Rule 5 for one cell; prints nothing, records failures for row $1.
check_refs() {
  local id=$1 cell=$2 ref path nums n m total
  while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    path=${ref%%:*}
    nums=${ref#*:}
    n=${nums%-*}
    m=${nums#*-}
    if [ ! -f "$path" ]; then
      fail "$id" "file not found: $ref"
      continue
    fi
    total=$(awk 'END { print NR }' "$path")
    if [ "$n" -lt 1 ] || [ "$n" -gt "$m" ]; then
      fail "$id" "bad range: $ref"
    elif [ "$m" -gt "$total" ]; then
      fail "$id" "line past end of file: $ref"
    elif ! sed -n "${n}p" "$path" | grep -q '[^[:space:]]' ||
      ! sed -n "${m}p" "$path" | grep -q '[^[:space:]]'; then
      fail "$id" "empty line: $ref"
    fi
  done <<<"$(printf '%s\n' "$cell" | grep -o -E '`[A-Za-z0-9_./-]+:[0-9]+(-[0-9]+)?`' | tr -d '`')"
}

has_ref() {
  printf '%s\n' "$1" | grep -q -E '`[A-Za-z0-9_./-]+:[0-9]+(-[0-9]+)?`'
}

rows=0
proven=0
untested=0
open=0
seen=" "
index=0

while IFS= read -r line; do
  case $line in
    '|'*) ;;
    *) continue ;;
  esac
  index=$((index + 1))
  [ "$index" -le 2 ] && continue

  if ! printf '%s\n' "$line" | grep -q -E '^\| T[0-9]+ \|'; then
    fail table "not a T<n> row: $(printf '%s' "$line" | cut -c 1-40)…"
    continue
  fi
  rows=$((rows + 1))

  cells=$(printf '%s\n' "$line" | awk -F'|' '{ print NF - 2 }')
  id=$(printf '%s\n' "$line" | awk -F'|' '{ print $2 }' | trim)
  if [ "$cells" -ne 6 ]; then
    fail "$id" "expected 6 cells, found $cells"
    continue
  fi

  case $seen in
    *" $id "*) fail "$id" "duplicate ID" ;;
  esac
  seen="$seen$id "

  cell() { printf '%s\n' "$line" | awk -F'|' -v i="$1" '{ print $(i + 1) }' | trim; }
  attack=$(cell 3)
  control=$(cell 4)
  evidence=$(cell 5)
  status=$(cell 6)

  case $status in
    proven) proven=$((proven + 1)) ;;
    "not tested") untested=$((untested + 1)) ;;
    open) open=$((open + 1)) ;;
    *) fail "$id" "bad status: $status" ;;
  esac

  check_refs "$id" "$line"

  if [ "$control" != none ] && ! has_ref "$control"; then
    fail "$id" "control cites no file:line"
  fi

  case $attack in
    *'`'*) fail "$id" "attack must be prose, no code" ;;
  esac

  found=0
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    if printf '%s\n' "$tests" | grep -q -x -F -- "$name"; then
      found=$((found + 1))
    else
      fail "$id" "test not found: $name"
    fi
  done <<<"$(printf '%s\n' "$evidence" | grep -o -E '`[a-z][a-z0-9]*_[a-z0-9_]+`' | tr -d '`')"

  while IFS= read -r label; do
    [ -n "$label" ] || continue
    if grep -q -F -- "$label:" demo/run.sh; then
      found=$((found + 1))
    else
      fail "$id" "demo check not found: $label"
    fi
  done <<<"$(printf '%s\n' "$evidence" | grep -o -E 'demo check "[^"]+"' |
    sed -e 's/^demo check "//' -e 's/"$//')"

  if [ "$status" = proven ] && [ "$found" -eq 0 ]; then
    fail "$id" "proven without a test or demo check"
  fi
  if [ "$status" = open ] && ! has_ref "$evidence"; then
    fail "$id" "open without the doc or code lines that describe it"
  fi
done <"$table"

if [ "$rows" -lt 12 ]; then
  fail table "$rows rows, at least 12 expected"
fi

if grep -q -i -E 'GHSA|advisories' "$table"; then
  fail table "forbidden reference to a private report"
fi

if [ "$fails" -gt 0 ]; then
  echo "FAILED: $fails problem(s)"
  exit 1
fi
echo "OK: $rows rows ($proven proven, $untested not tested, $open open)"
