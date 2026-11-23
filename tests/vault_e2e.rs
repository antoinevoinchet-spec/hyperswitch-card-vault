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
    Connection, OptionalExtension, PgConnection, QueryableByName, RunQueryDsl,
    connection::SimpleConnection,
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

#[derive(QueryableByName, Debug)]
struct LockerRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    locker_id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    merchant_id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    customer_id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    hash_id: String,
}

#[derive(QueryableByName, Debug)]
struct TextRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    text: String,
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

    /// Every `locker` row, ordered by card reference.
    fn locker_rows(&self) -> Vec<LockerRow> {
        diesel::sql_query(
            "SELECT locker_id, merchant_id, customer_id, hash_id FROM locker ORDER BY locker_id",
        )
        .load(&mut self.connection())
        .expect("read locker")
    }

    /// Every column of every `locker` and `hash_table` row, as text, in a stable order.
    fn snapshot(&self) -> (Vec<String>, Vec<String>) {
        let rows = |sql: &str| -> Vec<String> {
            diesel::sql_query(sql)
                .load::<TextRow>(&mut self.connection())
                .expect("snapshot")
                .into_iter()
                .map(|row| row.text)
                .collect()
        };
        (
            rows("SELECT t::text AS text FROM locker t ORDER BY locker_id"),
            rows("SELECT t::text AS text FROM hash_table t ORDER BY hash_id"),
        )
    }

    /// `data_hash` of the `hash_table` row with this `hash_id`, if any.
    fn hash_of(&self, hash_id: &str) -> Option<Vec<u8>> {
        diesel::sql_query("SELECT data_hash FROM hash_table WHERE hash_id = $1")
            .bind::<diesel::sql_types::Text, _>(hash_id)
            .get_result::<HashRow>(&mut self.connection())
            .optional()
            .expect("read hash_table")
            .map(|row| row.data_hash)
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

    // What a database reader would compare: no two locker rows share a hash id, neither across
    // merchants (pair 1) nor across customers of one merchant (pair 2).
    let hash_ids: std::collections::BTreeSet<String> = db
        .locker_hash_ids()
        .into_iter()
        .map(|(_, hash_id)| hash_id)
        .collect();
    assert_eq!(
        hash_ids.len(),
        4,
        "two locker rows share a hash id, which links their owners"
    );
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

// Re-hash job (`utils rehash`), see `docs/superpowers/specs/2026-11-23-rehash-job-design.md`.
// The vault is stopped around each run, as the design recommends, so its cache never serves a row
// that the test or the job changed. Values that must never appear in an output are checked
// without being printed.

const MERCHANT_2: &str = "demo-merchant-2";
const CUSTOMER_2: &str = "demo-customer-2";
const ENC_DATA: &str = "opaque-test-value";

fn card_data() -> serde_json::Value {
    serde_json::json!({ "card": { "card_number": CARD_NUMBER } })
}

/// Stores `data` (`{"card": ...}` or `{"enc_card_data": ...}`) under a fixed card reference.
async fn store_card_with_ref(
    vault: &Vault,
    merchant: &str,
    customer: &str,
    data: serde_json::Value,
    reference: &str,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "merchant_id": merchant,
        "merchant_customer_id": customer,
        "requestor_card_reference": reference,
    });
    body.as_object_mut()
        .expect("body object")
        .extend(data.as_object().expect("data object").clone());
    let (status, body) = vault.post("/data/add", body).await;
    assert_eq!(status, 200, "add card {reference}");
    serde_json::from_str(&body).expect("add response JSON")
}

/// Runs `utils rehash` against the test database, the custodian keys on standard input. Returns
/// the exit code and the joined standard output and error. Stops the command after 120 s.
fn run_rehash(db: &TestDb, keys: &Keys, key2: &str, args: &[&str]) -> (i32, String) {
    use std::io::{Read, Write};

    let host = db.url.host_str().expect("database host").to_string();
    let db_port = db.url.port().unwrap_or(5432).to_string();
    let password = db.url.password().unwrap_or("unused").to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_utils"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["rehash", "--tenant", "public", "--batch-size", "2"])
        .args(args)
        .env("LOCKER__DATABASE__HOST", host)
        .env("LOCKER__DATABASE__PORT", db_port)
        .env("LOCKER__DATABASE__USERNAME", db.url.username())
        .env("LOCKER__DATABASE__PASSWORD", password)
        .env("LOCKER__DATABASE__DBNAME", &db.name)
        .env(
            "LOCKER__TENANT_SECRETS__PUBLIC__MASTER_KEY",
            &keys.master_key,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start utils rehash");
    // A command that does not read its input closes the pipe; that is not an error here.
    let _ = child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{}\n{key2}\n", keys.key1).as_bytes());

    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for utils rehash") {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("rehash timed out");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut output = String::new();
    child
        .stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut output)
        .expect("read stdout");
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut output)
        .expect("read stderr");
    (status.code().unwrap_or(-1), output)
}

/// The `v2` hash `/data/add` stores for `hashed` (a card number or an `enc_card_data` string):
/// `get_hash` hashes the JSON-serialised string under the scoped key.
fn expected_hash(master_key: &[u8], merchant: &str, customer: &str, hashed: &str) -> Vec<u8> {
    CardDedupHmac::from_master_key(&Secret::new(master_key.to_vec()), merchant, customer)
        .expect("derive dedup key")
        .encode(serde_json::to_vec(hashed).expect("serialise"))
        .expect("keyed hash")
}

/// The tenant-wide `v1` value an older deployment stored for `hashed`.
fn v1_hash(master_key: &[u8], hashed: &str) -> Vec<u8> {
    let key: ring::hmac::Key = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA512, &[])
        .extract(master_key)
        .expand(
            &[b"hyperswitch-card-vault/card-dedup/v1"],
            ring::hmac::HMAC_SHA512,
        )
        .expect("expand v1 key")
        .into();
    ring::hmac::sign(&key, &serde_json::to_vec(hashed).expect("serialise"))
        .as_ref()
        .to_vec()
}

fn random_bytes(len: usize) -> Vec<u8> {
    use ring::rand::SecureRandom;
    let mut bytes = vec![0_u8; len];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("random bytes");
    bytes
}

fn insert_hash_row(db: &TestDb, hash_id: &str, data_hash: &[u8], created_at: &str) {
    db.exec(&format!(
        "INSERT INTO hash_table (hash_id, data_hash, created_at) \
         VALUES ('{hash_id}', decode('{}', 'hex'), {created_at})",
        hex::encode(data_hash)
    ));
}

/// Turns the stored rows into what a deployment from before I6 left: every `hash_table` row is
/// replaced, each group's `locker` rows cite one tenant-wide `v1` row, and one unused old row is
/// added.
fn seed_v1(db: &TestDb, master_key: &[u8], groups: &[(&str, &str, &[&str])]) {
    db.exec("DELETE FROM hash_table");
    for (hash_id, hashed, references) in groups {
        insert_hash_row(db, hash_id, &v1_hash(master_key, hashed), "'2000-01-01'");
        for reference in *references {
            db.exec(&format!(
                "UPDATE locker SET hash_id = '{hash_id}' WHERE locker_id = '{reference}'"
            ));
        }
    }
    insert_hash_row(db, "orphan-v1", &random_bytes(64), "'2000-01-01'");
}

/// Data set "first": the test card for (M1, C1), (M2, C1) and (M1, C2), and an `enc_card_data`
/// value for (M1, C1), all with `v1` hash rows. Returns the unlocked master key.
async fn seed_first(db: &TestDb, vault: &Vault, keys: &Keys) -> Vec<u8> {
    store_card_with_ref(vault, MERCHANT, CUSTOMER, card_data(), "ref-m1-c1").await;
    store_card_with_ref(vault, MERCHANT_2, CUSTOMER, card_data(), "ref-m2-c1").await;
    store_card_with_ref(vault, MERCHANT, CUSTOMER_2, card_data(), "ref-m1-c2").await;
    store_card_with_ref(
        vault,
        MERCHANT,
        CUSTOMER,
        serde_json::json!({ "enc_card_data": ENC_DATA }),
        "ref-enc",
    )
    .await;
    let master_key = unlocked_master_key(keys);
    seed_v1(
        db,
        &master_key,
        &[
            (
                "legacy-v1",
                CARD_NUMBER,
                &["ref-m1-c1", "ref-m2-c1", "ref-m1-c2"],
            ),
            ("legacy-enc", ENC_DATA, &["ref-enc"]),
        ],
    );
    master_key
}

/// Values that must never appear in an output or an audit row: card data, every hash in the
/// database or expected, and every key.
fn secrets(db: &TestDb, keys: &Keys, master_key: &[u8]) -> Vec<String> {
    let mut values = vec![
        CARD_NUMBER.to_string(),
        ENC_DATA.to_string(),
        keys.master_key.clone(),
        keys.key1.clone(),
        keys.key2.clone(),
        hex::encode(master_key),
    ];
    values.extend(db.data_hashes().iter().map(hex::encode));
    for merchant in [MERCHANT, MERCHANT_2] {
        for customer in [CUSTOMER, CUSTOMER_2] {
            for hashed in [CARD_NUMBER, ENC_DATA] {
                values.push(hex::encode(expected_hash(
                    master_key, merchant, customer, hashed,
                )));
            }
        }
    }
    values
}

/// Fails if `text` contains one of `secrets`, naming only its position.
fn assert_no_secret(text: &str, secrets: &[String]) {
    for (index, secret) in secrets.iter().enumerate() {
        assert!(
            !text.contains(secret.as_str()),
            "protected value #{index} found in the output"
        );
    }
}

fn hashed_value_of(locker_id: &str) -> &'static str {
    if locker_id == "ref-enc" {
        ENC_DATA
    } else {
        CARD_NUMBER
    }
}

#[tokio::test]
async fn rehash_moves_v1_rows_to_scoped_hashes() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    let master_key = seed_first(&db, &vault, &keys).await;
    drop(vault);

    let (code, output) = run_rehash(&db, &keys, &keys.key2, &[]);
    assert_eq!(code, 0, "rehash failed");
    assert!(output.contains("examined: 4"), "every row examined once");
    assert!(output.contains("moved: 4"), "every row moved");

    let rows = db.locker_rows();
    assert_eq!(rows.len(), 4);
    for row in &rows {
        let expected = expected_hash(
            &master_key,
            &row.merchant_id,
            &row.customer_id,
            hashed_value_of(&row.locker_id),
        );
        assert!(
            db.hash_of(&row.hash_id) == Some(expected),
            "{} does not cite its v2 hash",
            row.locker_id
        );
    }
    let hash_ids: std::collections::BTreeSet<_> = rows.iter().map(|row| &row.hash_id).collect();
    assert_eq!(hash_ids.len(), 4, "two locker rows still share a hash id");
    for old in ["legacy-v1", "legacy-enc", "orphan-v1"] {
        assert!(db.hash_of(old).is_none(), "{old} is still in hash_table");
    }
    assert_eq!(db.count("hash_table"), 4);
    assert_no_secret(&output, &secrets(&db, &keys, &master_key));

    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    let again = store_card_as(&vault, MERCHANT, CUSTOMER, CARD_NUMBER).await;
    assert_eq!(again["payload"]["duplication_check"], "duplicated");
    assert_eq!(db.count("locker"), 4, "the duplicate add stored a copy");
}

#[tokio::test]
async fn rehash_detaches_the_older_duplicate() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "ref-old").await;
    let master_key = unlocked_master_key(&keys);
    seed_v1(
        &db,
        &master_key,
        &[("legacy-v1", CARD_NUMBER, &["ref-old"])],
    );
    drop(vault);

    // Before the job: the same merchant and customer add the card again, and it is missed (T28).
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    let before = store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "ref-new").await;
    assert!(before["payload"]["duplication_check"].is_null());
    drop(vault);

    let (code, _) = run_rehash(&db, &keys, &keys.key2, &[]);
    assert_eq!(code, 0, "rehash failed");

    let rows = db.locker_rows();
    let row = |reference: &str| {
        rows.iter()
            .find(|row| row.locker_id == reference)
            .unwrap_or_else(|| panic!("{reference} is gone"))
    };
    let (old, new) = (row("ref-old"), row("ref-new"));
    assert!(
        db.hash_of(&new.hash_id)
            == Some(expected_hash(&master_key, MERCHANT, CUSTOMER, CARD_NUMBER)),
        "the newer copy does not cite its v2 hash"
    );
    assert_ne!(old.hash_id, new.hash_id);
    assert!(
        db.hash_of(&old.hash_id).is_none(),
        "the older copy is not detached"
    );
    assert!(
        db.hash_of("legacy-v1").is_none(),
        "legacy-v1 is still in hash_table"
    );

    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    for reference in ["ref-old", "ref-new"] {
        let (status, body) = vault.post("/data/retrieve", card_request(reference)).await;
        assert_eq!(status, 200, "retrieve {reference}");
        assert!(
            body.contains(CARD_NUMBER),
            "{reference} no longer returns the card"
        );
    }
    let again = store_card_as(&vault, MERCHANT, CUSTOMER, CARD_NUMBER).await;
    assert_eq!(again["payload"]["duplication_check"], "duplicated");
    assert_eq!(db.count("locker"), 2);
}

#[tokio::test]
async fn rehash_twice_changes_nothing() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "ref-old").await;
    store_card_with_ref(&vault, MERCHANT_2, CUSTOMER, card_data(), "ref-m2-c1").await;
    let master_key = unlocked_master_key(&keys);
    seed_v1(
        &db,
        &master_key,
        &[("legacy-v1", CARD_NUMBER, &["ref-old", "ref-m2-c1"])],
    );
    drop(vault);
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "ref-new").await;
    drop(vault);

    let (code, _) = run_rehash(&db, &keys, &keys.key2, &[]);
    assert_eq!(code, 0, "first rehash failed");
    // Older than the clean-up margin, so the second run's clean-up sees rows it must keep.
    db.exec("UPDATE hash_table SET created_at = '2000-01-01'");
    let before = db.snapshot();
    let audit_before = db.audit_rows().len();

    let (code, output) = run_rehash(&db, &keys, &keys.key2, &[]);
    assert_eq!(code, 0, "second rehash failed");
    assert!(db.snapshot() == before, "the second run changed a row");
    let new_rows: Vec<_> = db
        .audit_rows()
        .into_iter()
        .skip(audit_before)
        .map(|row| (row.operation, row.outcome, row.status_code))
        .collect();
    assert_eq!(
        new_rows,
        [("rehash_run".to_string(), "success".to_string(), 200)]
    );
    for line in ["moved: 0", "duplicates: 0", "removed hash rows: 0"] {
        assert!(output.contains(line), "second run output lacks `{line}`");
    }
}

#[tokio::test]
async fn rehash_resumed_after_interruption_matches_a_full_run() {
    let Some(admin) = admin_url() else { return };
    let keys = Keys::generate();
    let full = TestDb::create(&admin);
    let resumed = TestDb::create(&admin);
    let mut master_key = Vec::new();
    for db in [&full, &resumed] {
        let vault = Vault::start(db, &keys.master_key).await;
        unlock(&vault, &keys).await;
        master_key = seed_first(db, &vault, &keys).await;
    }

    let (code, _) = run_rehash(&full, &keys, &keys.key2, &[]);
    assert_eq!(code, 0, "full rehash failed");

    // Stopped after one row: legacy-v1 is still cited by two rows, so it must still exist.
    let (code, output) = run_rehash(&resumed, &keys, &keys.key2, &["--max-rows", "1"]);
    assert_eq!(code, 2, "an interrupted run must exit 2");
    assert!(output.contains("complete: no"));
    assert!(
        resumed.hash_of("legacy-v1").is_some(),
        "legacy-v1 deleted while still cited"
    );
    // Crash after the insert of a new hash row, before the move.
    insert_hash_row(
        &resumed,
        "crash-insert",
        &expected_hash(&master_key, MERCHANT_2, CUSTOMER, CARD_NUMBER),
        "now()",
    );
    // Crash after the move, before the old row is deleted.
    insert_hash_row(
        &resumed,
        "crash-move",
        &expected_hash(&master_key, MERCHANT, CUSTOMER, ENC_DATA),
        "now()",
    );
    resumed.exec("UPDATE locker SET hash_id = 'crash-move' WHERE locker_id = 'ref-enc'");

    let (code, output) = run_rehash(&resumed, &keys, &keys.key2, &[]);
    assert_eq!(code, 0, "resumed rehash failed");
    assert!(output.contains("complete: yes"));

    let full_rows = full.locker_rows();
    let resumed_rows = resumed.locker_rows();
    assert_eq!(full_rows.len(), resumed_rows.len());
    for (a, b) in full_rows.iter().zip(&resumed_rows) {
        assert_eq!(a.locker_id, b.locker_id);
        assert!(
            full.hash_of(&a.hash_id) == resumed.hash_of(&b.hash_id),
            "{} differs between the full and the resumed run",
            a.locker_id
        );
    }
    assert_eq!(full.count("hash_table"), resumed.count("hash_table"));
}

#[tokio::test]
async fn rehash_audit_rows_hold_no_card_or_key() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    let master_key = seed_first(&db, &vault, &keys).await;
    drop(vault);

    let (code, _) = run_rehash(&db, &keys, &keys.key2, &[]);
    assert_eq!(code, 0, "rehash failed");

    let rows = db.audit_rows();
    let rehash: Vec<_> = rows
        .iter()
        .filter(|row| row.operation.starts_with("rehash_"))
        .map(|row| {
            (
                row.operation.as_str(),
                row.outcome.as_str(),
                row.status_code,
            )
        })
        .collect();
    assert_eq!(
        rehash,
        [
            ("rehash_row", "success", 200),
            ("rehash_row", "success", 200),
            ("rehash_row", "success", 200),
            ("rehash_row", "success", 200),
            ("rehash_run", "success", 200),
        ]
    );
    let secrets = secrets(&db, &keys, &master_key);
    for row in &rows {
        assert_no_secret(&row.text, &secrets);
    }
}

#[tokio::test]
async fn rehash_stops_when_audit_table_is_unwritable() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    let master_key = seed_first(&db, &vault, &keys).await;
    drop(vault);
    let before = db.snapshot();

    db.exec("ALTER TABLE audit_log RENAME TO audit_log_blocked");
    let (code, output) = run_rehash(&db, &keys, &keys.key2, &[]);
    db.exec("ALTER TABLE audit_log_blocked RENAME TO audit_log");

    assert_eq!(code, 1, "rehash must fail without its audit rows");
    assert!(
        output.contains("rehash failed"),
        "not the re-hash command's own error"
    );
    assert!(
        db.snapshot() == before,
        "a row changed without its audit entry"
    );
    assert_no_secret(&output, &secrets(&db, &keys, &master_key));
}

#[tokio::test]
async fn rehash_converges_rows_hashed_under_another_master_key() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "ref-m1-c1").await;
    store_card_with_ref(&vault, MERCHANT_2, CUSTOMER, card_data(), "ref-m2-c1").await;
    drop(vault);
    // What a change of master key would leave: hashes under the same derivation, another key.
    let other_key = random_bytes(32);
    for row in db.locker_rows() {
        db.exec(&format!(
            "UPDATE hash_table SET data_hash = decode('{}', 'hex') WHERE hash_id = '{}'",
            hex::encode(expected_hash(
                &other_key,
                &row.merchant_id,
                &row.customer_id,
                CARD_NUMBER
            )),
            row.hash_id
        ));
    }

    let (code, _) = run_rehash(&db, &keys, &keys.key2, &[]);
    assert_eq!(code, 0, "rehash failed");
    let master_key = unlocked_master_key(&keys);
    for row in db.locker_rows() {
        assert!(
            db.hash_of(&row.hash_id)
                == Some(expected_hash(
                    &master_key,
                    &row.merchant_id,
                    &row.customer_id,
                    CARD_NUMBER
                )),
            "{} still cites a hash under the other key",
            row.locker_id
        );
    }
    assert_eq!(db.count("hash_table"), 2);

    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    let again = store_card_as(&vault, MERCHANT, CUSTOMER, CARD_NUMBER).await;
    assert_eq!(again["payload"]["duplication_check"], "duplicated");
}

#[tokio::test]
async fn rehash_on_an_empty_tenant_changes_nothing() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    insert_hash_row(&db, "orphan-v1", &random_bytes(64), "'2000-01-01'");
    insert_hash_row(&db, "fresh", &random_bytes(64), "now()");

    let (code, output) = run_rehash(&db, &keys, &keys.key2, &[]);
    assert_eq!(code, 0, "rehash failed");
    assert!(output.contains("examined: 0"));
    assert!(
        db.hash_of("orphan-v1").is_none(),
        "an old unused row was kept"
    );
    assert!(
        db.hash_of("fresh").is_some(),
        "a row younger than the margin was deleted"
    );
}

#[tokio::test]
async fn rehash_refuses_wrong_custodian_keys() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    let master_key = seed_first(&db, &vault, &keys).await;
    drop(vault);
    let before = db.snapshot();
    // A wrong key of the right shape (16 bytes as hex).
    let wrong_key2 = uuid::Uuid::now_v7().simple().to_string();

    let (code, output) = run_rehash(&db, &keys, &wrong_key2, &[]);
    assert_eq!(code, 1, "rehash must refuse a wrong custodian key");
    assert!(
        output.contains("rehash failed"),
        "not the re-hash command's own error"
    );
    assert!(db.snapshot() == before, "a row changed with a wrong key");
    let mut secrets = secrets(&db, &keys, &master_key);
    secrets.push(wrong_key2);
    assert_no_secret(&output, &secrets);
}
