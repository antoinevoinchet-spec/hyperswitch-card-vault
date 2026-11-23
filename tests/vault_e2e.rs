//! End-to-end tests against a real PostgreSQL.
//!
//! Each test creates its own database from `VAULT_TEST_DATABASE_URL` (an admin connection URL),
//! applies the migrations, starts the real `locker` binary and talks to it over HTTP. Without the
//! variable, each test prints that it was skipped and passes, so `cargo test` keeps working without a
//! database. See `docs/superpowers/specs/2026-11-23-demo-and-ci-db-design.md` (E6).
#![cfg(feature = "key_custodian")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The `QueryableByName` derive expands to `field: field` initialisers that clippy flags.
#![allow(clippy::redundant_field_names)]

use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

use diesel::{
    Connection, PgConnection, QueryableByName, RunQueryDsl, connection::SimpleConnection,
};
use hyperswitch_card_vault::crypto::{
    encryption_manager::{encryption_interface::Encryption, managers::aes::GcmAes256},
    hash_manager::{hash_interface::Encode, managers::sha::CardDedupHmac},
};
use hyperswitch_masking::Secret;

const CARD_NUMBER: &str = "4111111111111111";
const MERCHANT: &str = "demo-merchant";
const CUSTOMER: &str = "demo-customer";

fn admin_url() -> Option<String> {
    let url = std::env::var("VAULT_TEST_DATABASE_URL").ok();
    if url.is_none() {
        // The CI job that provides a database sets this, so a missing URL fails there instead of
        // skipping every test.
        assert!(
            std::env::var_os("VAULT_TEST_REQUIRE_DB").is_none(),
            "VAULT_TEST_REQUIRE_DB is set but VAULT_TEST_DATABASE_URL is not"
        );
        println!("skipped: VAULT_TEST_DATABASE_URL not set");
    }
    url
}

/// A throwaway database with every migration applied, dropped when the value goes out of scope.
struct TestDb {
    name: String,
    url: reqwest::Url,
    admin: String,
}

#[derive(QueryableByName, Debug)]
struct AuditRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    operation: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    outcome: String,
    #[diesel(sql_type = diesel::sql_types::SmallInt)]
    status_code: i16,
    #[diesel(sql_type = diesel::sql_types::Text)]
    text: String,
}

#[derive(QueryableByName, Debug)]
struct HashRow {
    #[diesel(sql_type = diesel::sql_types::Binary)]
    data_hash: Vec<u8>,
}

#[derive(QueryableByName, Debug)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

#[derive(QueryableByName, Debug)]
struct LockerHashRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    merchant_id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    hash_id: String,
}

impl TestDb {
    fn create(admin: &str) -> Self {
        let name = format!("vault_test_{}", uuid::Uuid::now_v7().simple());
        let mut admin_conn = PgConnection::establish(admin).expect("admin connection");
        admin_conn
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .expect("create database");

        let mut url = reqwest::Url::parse(admin).expect("admin URL");
        url.set_path(&format!("/{name}"));

        let mut conn = PgConnection::establish(url.as_str()).expect("test database connection");
        let mut migrations: Vec<_> = std::fs::read_dir("migrations")
            .expect("migrations directory")
            .map(|entry| entry.expect("migration entry").path())
            .filter(|path| path.join("up.sql").exists())
            .collect();
        migrations.sort();
        for migration in migrations {
            let sql = std::fs::read_to_string(migration.join("up.sql")).expect("read up.sql");
            conn.batch_execute(&sql)
                .unwrap_or_else(|_| panic!("apply {}", migration.display()));
        }

        Self {
            name,
            url,
            admin: admin.to_string(),
        }
    }

    fn connection(&self) -> PgConnection {
        PgConnection::establish(self.url.as_str()).expect("test database connection")
    }

    fn exec(&self, sql: &str) {
        self.connection().batch_execute(sql).expect("execute SQL");
    }

    fn data_hashes(&self) -> Vec<Vec<u8>> {
        diesel::sql_query("SELECT data_hash FROM hash_table")
            .load::<HashRow>(&mut self.connection())
            .expect("read hash_table")
            .into_iter()
            .map(|row| row.data_hash)
            .collect()
    }

    /// Number of rows in `table` (`hash_table` or `locker`) of this test's own database.
    fn count(&self, table: &str) -> i64 {
        diesel::sql_query(format!("SELECT count(*) AS n FROM {table}"))
            .get_result::<CountRow>(&mut self.connection())
            .expect("count rows")
            .n
    }

    /// `(merchant_id, hash_id)` of every `locker` row, in insertion order.
    fn locker_hash_ids(&self) -> Vec<(String, String)> {
        diesel::sql_query("SELECT merchant_id, hash_id FROM locker ORDER BY id")
            .load::<LockerHashRow>(&mut self.connection())
            .expect("read locker")
            .into_iter()
            .map(|row| (row.merchant_id, row.hash_id))
            .collect()
    }

    fn audit_rows(&self) -> Vec<AuditRow> {
        diesel::sql_query(
            "SELECT operation, outcome, status_code, audit_log::text AS text \
             FROM audit_log ORDER BY created_at, audit_id",
        )
        .load(&mut self.connection())
        .expect("read audit_log")
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        if let Ok(mut conn) = PgConnection::establish(&self.admin) {
            let _ = conn.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ));
        }
    }
}

/// Throwaway custodian keys, generated by the `utils` binary. Never printed.
struct Keys {
    master_key: String,
    key1: String,
    key2: String,
}

impl Keys {
    fn generate() -> Self {
        let output = Command::new(env!("CARGO_BIN_EXE_utils"))
            .arg("master-key")
            .output()
            .expect("run utils master-key");
        assert!(output.status.success(), "utils master-key failed");
        let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
        let value = |prefix: &str| {
            stdout
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
                .map(|value| value.trim().to_string())
                .unwrap_or_else(|| panic!("utils output has no `{prefix}` line"))
        };
        Self {
            master_key: value("master key:"),
            key1: value("key 1:"),
            key2: value("key 2:"),
        }
    }
}

/// The `locker` binary running against a test database, killed when the value goes out of scope.
struct Vault {
    child: Child,
    base: String,
    client: reqwest::Client,
    log: std::path::PathBuf,
}

/// Replaces runs of 32 or more hex characters (key-shaped values) before a log line is printed.
fn redact_hex(line: &str) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for c in line.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_hexdigit() {
            run.push(c);
            continue;
        }
        if run.len() >= 32 {
            out.push_str("<hex>");
        } else {
            out.push_str(&run);
        }
        run.clear();
        out.push(c);
    }
    out.pop();
    out
}

impl Vault {
    async fn start(db: &TestDb, master_key: &str) -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind a free port")
            .local_addr()
            .expect("local address")
            .port();
        let host = db.url.host_str().expect("database host").to_string();
        let db_port = db.url.port().unwrap_or(5432).to_string();
        let password = db.url.password().unwrap_or("unused").to_string();

        let log = std::env::temp_dir().join(format!("vault_e2e_{}.log", uuid::Uuid::now_v7()));
        let log_file = std::fs::File::create(&log).expect("create locker log");
        let child = Command::new(env!("CARGO_BIN_EXE_locker"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env("LOCKER__SERVER__PORT", port.to_string())
            .env("LOCKER__DATABASE__HOST", host)
            .env("LOCKER__DATABASE__PORT", db_port)
            .env("LOCKER__DATABASE__USERNAME", db.url.username())
            .env("LOCKER__DATABASE__PASSWORD", password)
            .env("LOCKER__DATABASE__DBNAME", &db.name)
            .env("LOCKER__TENANT_SECRETS__PUBLIC__MASTER_KEY", master_key)
            .stdout(Stdio::from(log_file.try_clone().expect("clone log handle")))
            .stderr(Stdio::from(log_file))
            .spawn()
            .expect("start locker");

        let vault = Self {
            child,
            base: format!("http://127.0.0.1:{port}"),
            client: reqwest::Client::new(),
            log,
        };

        for _ in 0..240 {
            if let Ok(response) = vault
                .client
                .get(format!("{}/health", vault.base))
                .send()
                .await
                && response.status().is_success()
            {
                return vault;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("locker did not become healthy within 60 s");
    }

    async fn post(&self, path: &str, body: serde_json::Value) -> (u16, String) {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .header("x-tenant-id", "public")
            .json(&body)
            .send()
            .await
            .expect("send request");
        let status = response.status().as_u16();
        (status, response.text().await.expect("response body"))
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // On failure, show only the vault's error lines, with key-shaped values masked.
        if std::thread::panicking()
            && let Ok(content) = std::fs::read_to_string(&self.log)
        {
            for line in content
                .lines()
                .filter(|line| line.contains("ERROR"))
                .take(20)
            {
                println!("locker: {}", redact_hex(line));
            }
        }
        let _ = std::fs::remove_file(&self.log);
    }
}

async fn unlock(vault: &Vault, keys: &Keys) {
    let (status, _) = vault
        .post("/custodian/key1", serde_json::json!({ "key": keys.key1 }))
        .await;
    assert_eq!(status, 200, "key1");
    let (status, _) = vault
        .post("/custodian/key2", serde_json::json!({ "key": keys.key2 }))
        .await;
    assert_eq!(status, 200, "key2");
    let (status, _) = vault
        .post("/custodian/decrypt", serde_json::json!({}))
        .await;
    assert_eq!(status, 200, "decrypt");
}

/// Stores `card_number` for `merchant` and `customer` and returns the parsed `/data/add` response.
async fn store_card_as(
    vault: &Vault,
    merchant: &str,
    customer: &str,
    card_number: &str,
) -> serde_json::Value {
    let (status, body) = vault
        .post(
            "/data/add",
            serde_json::json!({
                "merchant_id": merchant,
                "merchant_customer_id": customer,
                "card": { "card_number": card_number }
            }),
        )
        .await;
    assert_eq!(status, 200, "add card");
    serde_json::from_str(&body).expect("add response JSON")
}

/// Stores the test card for `merchant` and returns the parsed `/data/add` response.
async fn store_card_for(vault: &Vault, merchant: &str) -> serde_json::Value {
    store_card_as(vault, merchant, CUSTOMER, CARD_NUMBER).await
}

async fn store_card(vault: &Vault) -> String {
    store_card_for(vault, MERCHANT).await["payload"]["card_reference"]
        .as_str()
        .expect("card_reference")
        .to_string()
}

fn card_request(card_reference: &str) -> serde_json::Value {
    serde_json::json!({
        "merchant_id": MERCHANT,
        "merchant_customer_id": CUSTOMER,
        "card_reference": card_reference
    })
}

#[tokio::test]
async fn audit_row_is_written_for_each_card_step() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;

    let reference = store_card(&vault).await;
    let (status, _) = vault.post("/data/retrieve", card_request(&reference)).await;
    assert_eq!(status, 200, "retrieve");
    let (status, _) = vault.post("/data/delete", card_request(&reference)).await;
    assert_eq!(status, 200, "delete");

    let rows = db.audit_rows();
    let card_rows: Vec<_> = rows
        .iter()
        .filter(|row| row.operation.starts_with("locker_"))
        .map(|row| {
            (
                row.operation.as_str(),
                row.outcome.as_str(),
                row.status_code,
            )
        })
        .collect();
    assert_eq!(
        card_rows,
        [
            ("locker_add", "success", 200),
            ("locker_retrieve", "success", 200),
            ("locker_delete", "success", 200),
        ]
    );
    assert!(rows.iter().all(|row| !row.text.contains(CARD_NUMBER)));
}

#[tokio::test]
async fn retrieve_fails_closed_when_audit_table_is_unwritable() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    let reference = store_card(&vault).await;

    db.exec("ALTER TABLE audit_log RENAME TO audit_log_blocked");
    let (status, body) = vault.post("/data/retrieve", card_request(&reference)).await;
    db.exec("ALTER TABLE audit_log_blocked RENAME TO audit_log");

    assert_eq!(status, 500);
    assert!(
        body.contains("audit_log"),
        "the 500 must come from the audit write"
    );
    assert!(!body.contains(CARD_NUMBER));
    assert!(!body.contains("card_number"));
}

async fn send_key(vault: &Vault, step: &str, key: &str) -> u16 {
    vault
        .post(
            &format!("/custodian/{step}"),
            serde_json::json!({ "key": key }),
        )
        .await
        .0
}

fn custodian_rows(db: &TestDb) -> Vec<(String, String, i16)> {
    db.audit_rows()
        .into_iter()
        .filter(|row| row.operation.starts_with("custodian_"))
        .map(|row| (row.operation, row.outcome, row.status_code))
        .collect()
}

#[tokio::test]
async fn custodian_steps_write_audit_rows() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    // A wrong key of the right shape (16 bytes as hex) reaches the handler.
    let wrong_key2 = uuid::Uuid::now_v7().simple().to_string();

    assert_eq!(send_key(&vault, "key1", &keys.key1).await, 200);
    assert_eq!(send_key(&vault, "key1", &keys.key1).await, 200);
    assert_eq!(send_key(&vault, "key2", &wrong_key2).await, 200);
    let (status, _) = vault
        .post("/custodian/decrypt", serde_json::json!({}))
        .await;
    assert_ne!(status, 200, "decrypt with a wrong key");
    assert_eq!(send_key(&vault, "key2", &keys.key2).await, 200);
    let (status, _) = vault
        .post("/custodian/decrypt", serde_json::json!({}))
        .await;
    assert_eq!(status, 200, "decrypt with the right keys");

    let rows = custodian_rows(&db);
    let summary: Vec<_> = rows
        .iter()
        .map(|(operation, outcome, status)| (operation.as_str(), outcome.as_str(), *status == 200))
        .collect();
    assert_eq!(
        summary,
        [
            ("custodian_key1", "success", true),
            ("custodian_key1", "success", true),
            ("custodian_key2", "success", true),
            ("custodian_decrypt", "failure", false),
            ("custodian_key2", "success", true),
            ("custodian_decrypt", "success", true),
        ]
    );
    for row in db.audit_rows() {
        for secret in [&keys.key1, &keys.key2, &keys.master_key, &wrong_key2] {
            assert!(
                !row.text.contains(secret.as_str()),
                "a key reached audit_log"
            );
        }
    }
}

#[tokio::test]
async fn custodian_key_is_refused_when_audit_table_is_unwritable() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;

    db.exec("ALTER TABLE audit_log RENAME TO audit_log_blocked");
    let key1_status = send_key(&vault, "key1", &keys.key1).await;
    db.exec("ALTER TABLE audit_log_blocked RENAME TO audit_log");
    assert_eq!(
        key1_status, 500,
        "key1 must be refused without its audit row"
    );

    assert_eq!(send_key(&vault, "key2", &keys.key2).await, 200);
    let (status, _) = vault
        .post("/custodian/decrypt", serde_json::json!({}))
        .await;
    assert_ne!(status, 200, "key1 was not kept, so decrypt must fail");

    let rows = custodian_rows(&db);
    let summary: Vec<_> = rows
        .iter()
        .map(|(operation, outcome, _)| (operation.as_str(), outcome.as_str()))
        .collect();
    assert_eq!(
        summary,
        [
            ("custodian_key2", "success"),
            ("custodian_decrypt", "failure"),
        ]
    );
}

#[tokio::test]
async fn same_card_for_two_merchants_gets_two_hash_rows() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;

    store_card_for(&vault, MERCHANT).await;
    store_card_for(&vault, "demo-merchant-2").await;
    // Same merchant and same customer as the first call.
    let again = store_card_for(&vault, MERCHANT).await;

    assert_eq!(
        db.count("hash_table"),
        2,
        "one duplicate-check row per merchant and customer"
    );
    assert_eq!(again["payload"]["duplication_check"], "duplicated");
    let rows = db.locker_hash_ids();
    assert_eq!(rows.len(), 2, "the duplicate add stores no third copy");
    assert_eq!(rows[0].0, MERCHANT);
    assert_eq!(rows[1].0, "demo-merchant-2");
    assert_ne!(
        rows[0].1, rows[1].1,
        "a database reader can link the two merchants through hash_id"
    );
}

/// Change in `(hash_table, locker)` row counts caused by one add.
async fn rows_added_by(
    db: &TestDb,
    vault: &Vault,
    merchant: &str,
    customer: &str,
    card_number: &str,
) -> (i64, i64) {
    let before = (db.count("hash_table"), db.count("locker"));
    let response = store_card_as(vault, merchant, customer, card_number).await;
    assert!(
        response["payload"]["duplication_check"].is_null(),
        "no duplication_check for {merchant}/{customer}"
    );
    (
        db.count("hash_table") - before.0,
        db.count("locker") - before.1,
    )
}

#[tokio::test]
async fn card_known_to_others_takes_the_new_card_path() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;

    // Each pair changes one fact: the card is new to the tenant, or known only to someone else.
    // The "hash found" branch inserts no hash_table row, so equal changes mean it did not run.
    // Public test card numbers, one per pair.
    // Pair 1, card A: new card, then the same card for another merchant only.
    let card_a = "5555555555554444";
    let new_a = rows_added_by(&db, &vault, MERCHANT, CUSTOMER, card_a).await;
    let other_merchant = rows_added_by(&db, &vault, "demo-merchant-2", CUSTOMER, card_a).await;
    // Pair 2, card B: new card, then the same card for another customer of the same merchant only.
    let card_b = "4012888888881881";
    let new_b = rows_added_by(&db, &vault, MERCHANT, CUSTOMER, card_b).await;
    let other_customer = rows_added_by(&db, &vault, MERCHANT, "demo-customer-2", card_b).await;

    assert_eq!(
        (new_a, new_b),
        ((1, 1), (1, 1)),
        "a new card adds one row to each table"
    );
    // Both pairs are compared at once, so a failure shows each of them.
    assert_eq!(
        [
            ("pair 1, other merchant", other_merchant),
            ("pair 2, other customer", other_customer)
        ],
        [
            ("pair 1, other merchant", new_a),
            ("pair 2, other customer", new_b)
        ],
        "a card known only to someone else takes another path than a new card"
    );
}

/// The master key as the custodians unlock it (AES-GCM under key 1 + key 2). Never printed.
fn unlocked_master_key(keys: &Keys) -> Vec<u8> {
    let custodian_key = hex::decode(format!("{}{}", keys.key1, keys.key2)).expect("custodian key");
    GcmAes256::new(custodian_key)
        .decrypt(hex::decode(&keys.master_key).expect("encrypted master key"))
        .expect("decrypt master key")
}

#[tokio::test]
async fn tenant_wide_v1_hash_row_is_not_matched() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;

    // The value an older deployment stored for this card: HKDF-SHA512 of the master key with the
    // tenant-wide `v1` context, then one HMAC-SHA512 of the JSON-serialised number.
    let master_key = unlocked_master_key(&keys);
    let v1_key: ring::hmac::Key = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA512, &[])
        .extract(&master_key)
        .expand(
            &[b"hyperswitch-card-vault/card-dedup/v1"],
            ring::hmac::HMAC_SHA512,
        )
        .expect("expand v1 key")
        .into();
    let v1_hash = ring::hmac::sign(&v1_key, format!("\"{CARD_NUMBER}\"").as_bytes());
    db.exec(&format!(
        "INSERT INTO hash_table (hash_id, data_hash) VALUES ('legacy-v1', decode('{}', 'hex'))",
        hex::encode(v1_hash.as_ref())
    ));

    let response = store_card_for(&vault, MERCHANT).await;
    assert!(response["payload"]["duplication_check"].is_null());
    assert_eq!(
        db.count("hash_table"),
        2,
        "the v1 row was matched instead of a new scoped row"
    );
    let rows = db.locker_hash_ids();
    assert_eq!(rows.len(), 1);
    assert_ne!(rows[0].1, "legacy-v1", "the new card reuses the v1 hash_id");
}

#[tokio::test]
async fn stored_card_hash_is_not_a_plain_sha512() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    store_card(&vault).await;

    let sha512 = |data: &[u8]| {
        ring::digest::digest(&ring::digest::SHA512, data)
            .as_ref()
            .to_vec()
    };
    let hashes = db.data_hashes();
    assert_eq!(hashes.len(), 1);
    let stored = &hashes[0];
    assert_eq!(stored.len(), 64, "full HMAC-SHA512, not truncated");
    assert!(
        *stored != sha512(CARD_NUMBER.as_bytes()),
        "stored hash is the plain SHA-512 of the card number"
    );
    // The bytes the unkeyed version hashed: the JSON-serialised number, between double quotes.
    let hashed_bytes = format!("\"{CARD_NUMBER}\"");
    assert!(
        *stored != sha512(hashed_bytes.as_bytes()),
        "stored hash is the plain SHA-512 of the JSON-serialised card number"
    );

    // Recompute the expected keyed hash: unlock the master key as the custodians do (AES-GCM under
    // key 1 + key 2), then HMAC under the derived key. Values stay in memory and are never printed.
    let custodian_key = hex::decode(format!("{}{}", keys.key1, keys.key2)).expect("custodian key");
    let master_key = GcmAes256::new(custodian_key)
        .decrypt(hex::decode(&keys.master_key).expect("encrypted master key"))
        .expect("decrypt master key");
    let expected = CardDedupHmac::from_master_key(&Secret::new(master_key), MERCHANT, CUSTOMER)
        .expect("derive dedup key")
        .encode(hashed_bytes.into_bytes())
        .expect("keyed hash");
    assert!(
        *stored == expected,
        "stored hash is not the HMAC-SHA512 under the derived key"
    );
}
