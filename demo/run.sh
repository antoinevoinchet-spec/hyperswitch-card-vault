#!/usr/bin/env bash
# One-command demo of the vault: two custodians unlock it, then a test card is stored, read,
# fingerprinted and deleted. Every step's audit row is printed at the end.
# See demo/README.md and docs/superpowers/specs/2026-11-23-demo-and-ci-db-design.md (E1).
#
# Environment (all optional):
#   DEMO_DATABASE_URL  an existing empty PostgreSQL database (used in CI); otherwise a throwaway
#                      local cluster is created and removed
#   DEMO_PG_PORT       port of the throwaway cluster (default 54329)
#   DEMO_VAULT_PORT    port of the vault (default 3011)
#   PG_BIN             directory of initdb, pg_ctl and psql
set -euo pipefail

cd "$(dirname "$0")/.."

# Public test card number: never a real card.
CARD=4111111111111111
TENANT=public
MERCHANT=demo-merchant
CUSTOMER=demo-customer
VAULT_PORT=${DEMO_VAULT_PORT:-3011}
PG_PORT=${DEMO_PG_PORT:-54329}
BASE="http://127.0.0.1:${VAULT_PORT}"

if ! command -v cargo >/dev/null 2>&1; then
  export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
fi
if [ -z "${PG_BIN:-}" ]; then
  if command -v pg_ctl >/dev/null 2>&1; then
    PG_BIN=$(dirname "$(command -v pg_ctl)")
  else
    PG_BIN=/opt/homebrew/opt/postgresql@14/bin
  fi
fi
PSQL="psql"
if [ -x "$PG_BIN/psql" ]; then PSQL="$PG_BIN/psql"; fi
for tool in cargo curl jq openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done

TMP=$(mktemp -d)
OWN_CLUSTER=false
LOCKER_PID=""

cleanup() {
  if [ -n "$LOCKER_PID" ]; then
    kill "$LOCKER_PID" 2>/dev/null || true
    wait "$LOCKER_PID" 2>/dev/null || true
  fi
  if [ "$OWN_CLUSTER" = true ]; then
    "$PG_BIN/pg_ctl" -D "$TMP/pg" -m fast stop >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Everything printed from here is also kept in $TMP/out, for the key check at the end.
exec > >(tee "$TMP/out") 2>&1

title() { printf '\n=== %s\n' "$*"; }

title "Build (debug profile, feature key_custodian)"
cargo build -j 4 --quiet --features key_custodian --bin locker --bin utils

title "Database"
if [ -n "${DEMO_DATABASE_URL:-}" ]; then
  DB_URL=$DEMO_DATABASE_URL
  rest=${DB_URL#*://}
  creds=${rest%%@*}
  hostpart=${rest#*@}
  DB_USER=${creds%%:*}
  if [ "$creds" != "$DB_USER" ]; then DB_PASS=${creds#*:}; else DB_PASS=unused; fi
  hostport=${hostpart%%/*}
  DB_NAME=${hostpart#*/}
  DB_NAME=${DB_NAME%%\?*}
  DB_HOST=${hostport%%:*}
  if [ "$hostport" != "$DB_HOST" ]; then DB_PORT=${hostport#*:}; else DB_PORT=5432; fi
  echo "Using the database given in DEMO_DATABASE_URL (${DB_HOST}:${DB_PORT}/${DB_NAME})."
else
  OWN_CLUSTER=true
  "$PG_BIN/initdb" -D "$TMP/pg" -U demo --auth=trust -E UTF8 >/dev/null
  "$PG_BIN/pg_ctl" -D "$TMP/pg" -w -l "$TMP/pg.log" \
    -o "-p ${PG_PORT} -k '' -c listen_addresses=127.0.0.1" start >/dev/null
  DB_USER=demo DB_PASS=unused DB_HOST=127.0.0.1 DB_PORT=$PG_PORT DB_NAME=vault_demo
  "$PSQL" -X -q -h 127.0.0.1 -p "$PG_PORT" -U demo -d postgres -c "CREATE DATABASE vault_demo"
  DB_URL="postgres://demo@127.0.0.1:${PG_PORT}/vault_demo"
  echo "Throwaway PostgreSQL cluster started on 127.0.0.1:${PG_PORT}; it is removed at the end."
fi

sql() { "$PSQL" -X -q -v ON_ERROR_STOP=1 -d "$DB_URL" "$@"; }
for migration in migrations/*/; do
  if [ -f "${migration}up.sql" ]; then sql -f "${migration}up.sql" >/dev/null; fi
done
echo "Migrations applied, including the audit_log table."

title "Throwaway keys"
# utils prints the encrypted master key and the two custodian keys; they stay in variables and are
# never printed. The wrong key has the right shape (16 bytes as hex) so it reaches the handler.
KEYS=$(target/debug/utils master-key)
MASTER_KEY=$(printf '%s\n' "$KEYS" | sed -n 's/^master key: *//p')
KEY1=$(printf '%s\n' "$KEYS" | sed -n 's/^key 1: *//p')
KEY2=$(printf '%s\n' "$KEYS" | sed -n 's/^key 2: *//p')
WRONG_KEY2=$(openssl rand -hex 16)
unset KEYS
echo "Generated an encrypted master key and its two custodian keys (not shown)."

title "Start the vault"
LOCKER__SERVER__PORT=$VAULT_PORT \
LOCKER__DATABASE__HOST=$DB_HOST \
LOCKER__DATABASE__PORT=$DB_PORT \
LOCKER__DATABASE__USERNAME=$DB_USER \
LOCKER__DATABASE__PASSWORD=$DB_PASS \
LOCKER__DATABASE__DBNAME=$DB_NAME \
LOCKER__TENANT_SECRETS__PUBLIC__MASTER_KEY=$MASTER_KEY \
  target/debug/locker >"$TMP/locker.log" 2>&1 &
LOCKER_PID=$!
for _ in $(seq 1 240); do
  if curl -fs "$BASE/health" >/dev/null 2>&1; then break; fi
  sleep 0.25
done
curl -fs "$BASE/health" >/dev/null || { echo "the vault did not start" >&2; exit 1; }
echo "Vault listening on $BASE (locked until both custodians have sent their key)."

# step <n> <expected status, or "error"> <title> <explanation> <path> <body> [shown body]
# The body goes to curl through stdin, so keys never appear in the process list.
step() {
  local n=$1 expected=$2 name=$3 explanation=$4 path=$5 body=$6 shown=${7:-$6}
  local status
  title "Step ${n}: ${name}"
  echo "$explanation"
  echo "  request : POST ${path} $(printf '%s' "$shown" | jq -c .)"
  status=$(printf '%s' "$body" | curl -s -o "$TMP/body" -w '%{http_code}' -X POST \
    -H 'content-type: application/json' -H "x-tenant-id: ${TENANT}" \
    --data-binary @- "${BASE}${path}")
  echo "  status  : ${status}"
  echo "  response: $(jq -c . "$TMP/body" 2>/dev/null || cat "$TMP/body")"
  if { [ "$expected" = error ] && [ "$status" = 200 ]; } ||
     { [ "$expected" != error ] && [ "$status" != "$expected" ]; }; then
    echo "FAILED: step ${n} expected ${expected}, got ${status}" >&2
    exit 1
  fi
}

key_body() { jq -cn --arg key "$1" '{key: $key}'; }
HIDDEN='{"key":"<hidden>"}'

step 1 200 "custodian 1 sends key 1" \
  "The vault starts locked: its master key is stored encrypted. Custodian 1 sends the first key. The audit row is written before the key is kept." \
  /custodian/key1 "$(key_body "$KEY1")" "$HIDDEN"
step 2 200 "custodian 2 sends a WRONG key 2" \
  "A wrong key of the right shape is accepted for now: the vault cannot tell until it tries to decrypt." \
  /custodian/key2 "$(key_body "$WRONG_KEY2")" "$HIDDEN"
step 3 error "unlock attempt fails" \
  "The two keys together do not decrypt the master key, so the vault stays locked. The failure gets its own audit row." \
  /custodian/decrypt '{}'
step 4 200 "custodian 2 sends the right key 2" \
  "Key 1 is still held from step 1 (see Known limits in demo/README.md); key 2 is replaced." \
  /custodian/key2 "$(key_body "$KEY2")" "$HIDDEN"
step 5 200 "unlock succeeds" \
  "Key 1 + key 2 decrypt the master key. The audit row is written before the vault is opened." \
  /custodian/decrypt '{}'

STORE_BODY=$(jq -cn --arg m "$MERCHANT" --arg c "$CUSTOMER" --arg n "$CARD" \
  '{merchant_id: $m, merchant_customer_id: $c, card: {card_number: $n}}')
step 6 200 "store the test card" \
  "The card is encrypted with the merchant's key (itself encrypted with the master key) and stored. The vault returns a random reference instead of the card." \
  /data/add "$STORE_BODY"
REFERENCE=$(jq -r '.payload.card_reference' "$TMP/body")

LOCKER_ROWS=$(sql -At -c "SELECT count(*) FROM locker")
LOCKER_HITS=$(sql -At -c "SELECT count(*) FROM locker WHERE position(convert_to('${CARD}', 'UTF8') in enc_data) > 0")
echo "  check   : rows in the locker table: ${LOCKER_ROWS}; rows whose stored bytes contain the card number: ${LOCKER_HITS}"

REF_BODY=$(jq -cn --arg m "$MERCHANT" --arg c "$CUSTOMER" --arg r "$REFERENCE" \
  '{merchant_id: $m, merchant_customer_id: $c, card_reference: $r}')
step 7 200 "read the card back with its reference" \
  "The vault decrypts the stored row and returns the card. The audit row records the reference, never the card." \
  /data/retrieve "$REF_BODY"

FP_BODY=$(jq -cn --arg d "$CARD" --arg k "demo-fingerprint-key" '{data: $d, key: $k}')
FP_SHOWN=$(jq -cn --arg d "$CARD" '{data: $d, key: "<hidden>"}')
step 8 200 "fingerprint the card" \
  "The vault returns a fingerprint id: the same card and key always give the same id, and the id does not reveal the card." \
  /cards/fingerprint "$FP_BODY" "$FP_SHOWN"
step 9 200 "delete the card" \
  "The stored row is removed." \
  /data/delete "$REF_BODY"
step 10 error "read after delete" \
  "The reference no longer points to anything. The failed read is recorded too." \
  /data/retrieve "$REF_BODY"

title "Audit log (table audit_log, UTC)"
sql -P pager=off -c "SELECT to_char(created_at, 'HH24:MI:SS.MS') AS created_at_utc, operation, merchant_id, customer_id, resource_id, outcome, status_code, error_type FROM audit_log ORDER BY created_at, audit_id"
AUDIT_ROWS=$(sql -At -c "SELECT count(*) FROM audit_log")
AUDIT_HITS=$(sql -At -c "SELECT count(*) FROM audit_log WHERE audit_log::text LIKE '%${CARD}%'")
LOG_HITS=$(grep -cF "$CARD" "$TMP/locker.log" || true)
KEY_HITS=0
for value in "$KEY1" "$KEY2" "$WRONG_KEY2" "$MASTER_KEY"; do
  hits=$(grep -cF "$value" "$TMP/out" || true)
  KEY_HITS=$((KEY_HITS + hits))
done

title "Checks"
echo "audit rows written by the journey: ${AUDIT_ROWS} (expected 10)"
echo "audit rows containing the card number: ${AUDIT_HITS} (expected 0)"
echo "locker rows while the card was stored: ${LOCKER_ROWS} (expected at least 1); of them, containing the card number in clear: ${LOCKER_HITS} (expected 0)"
echo "server log lines containing the card number: ${LOG_HITS} (measured, see demo/README.md)"
echo "generated key values found in this output: ${KEY_HITS} (expected 0)"

if [ "$AUDIT_ROWS" -ne 10 ] || [ "$AUDIT_HITS" -ne 0 ] || [ "$LOCKER_ROWS" -lt 1 ] ||
   [ "$LOCKER_HITS" -ne 0 ] || [ "$KEY_HITS" -ne 0 ]; then
  echo "DEMO FAILED: a check did not match" >&2
  exit 1
fi
echo "DEMO OK"
