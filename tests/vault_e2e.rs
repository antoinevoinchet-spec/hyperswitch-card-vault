//! End-to-end tests against a real PostgreSQL.
//!
//! Each test creates its own database from `VAULT_TEST_DATABASE_URL` (an admin connection URL),
//! applies the migrations, starts the real `locker` binary and talks to it over HTTP. Without the
//! variable, each test prints that it was skipped and passes, so `cargo test` keeps working without a
//! database. See `docs/superpowers/specs/2026-11-23-demo-and-ci-db-design.md` (E6).
//!
//! The file builds with and without the `key_custodian` feature. Without it, the vault and `utils`
//! read the master key from the configuration and need no unlock; the custodian-only tests are left
//! out. See `docs/superpowers/specs/2026-11-23-hygiene-ci-design.md`.
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

/// Throwaway custodian keys, generated by the `utils` binary. Never printed. `master_key` is the
/// value given to the vault and to `utils`: encrypted under the custodian keys with the
/// `key_custodian` feature, the raw key (hex) without it.
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
        let keys = Self {
            master_key: value("master key:"),
            key1: value("key 1:"),
            key2: value("key 2:"),
        };
        #[cfg(not(feature = "key_custodian"))]
        {
            // Without custodians, an operator configures the master key itself.
            let raw = decrypt_master_key(&keys);
            Self {
                master_key: hex::encode(raw),
                ..keys
            }
        }
        #[cfg(feature = "key_custodian")]
        keys
    }
}

/// The master key as the custodians unlock it (AES-GCM under key 1 + key 2). Never printed.
fn decrypt_master_key(keys: &Keys) -> Vec<u8> {
    let custodian_key = hex::decode(format!("{}{}", keys.key1, keys.key2)).expect("custodian key");
    GcmAes256::new(custodian_key)
        .decrypt(hex::decode(&keys.master_key).expect("encrypted master key"))
        .expect("decrypt master key")
}

/// The `locker` binary running against a test database, killed when the value goes out of scope.
struct Vault {
    child: Child,
    base: String,
    client: reqwest::Client,
    log: std::path::PathBuf,
    /// The key `post` sends in `x-vault-caller-key`: the harness caller's, when it is declared.
    caller_key: Option<String>,
}

/// Every merchant and entity id the tests of this file use through `post`.
const HARNESS_MERCHANTS: &str = "demo-merchant,demo-merchant-2,demo-merchant-3,merchant-no-card,legacy-merchant,no-such-merchant";

/// The test harness's own caller, `harness`: a random key (never printed) and its SHA-256, with
/// every right for `HARNESS_MERCHANTS`. Every tenant must declare callers (T37, decision D-A), so
/// the vault is started with this caller beside any caller a test declares.
static HARNESS_CALLER: std::sync::LazyLock<(String, String)> = std::sync::LazyLock::new(caller_key);

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
        Self::start_with_env(db, master_key, &[]).await
    }

    /// Starts the vault with `extra` environment variables added, and the harness caller.
    async fn start_with_env(db: &TestDb, master_key: &str, extra: &[(&str, &str)]) -> Self {
        let (key, key_hash) = &*HARNESS_CALLER;
        let mut env = vec![
            (
                "LOCKER__TENANT_SECRETS__PUBLIC__CALLERS__HARNESS__KEY_HASH",
                key_hash.as_str(),
            ),
            (
                "LOCKER__TENANT_SECRETS__PUBLIC__CALLERS__HARNESS__MERCHANTS",
                HARNESS_MERCHANTS,
            ),
            (
                "LOCKER__TENANT_SECRETS__PUBLIC__CALLERS__HARNESS__RIGHTS",
                "read,add,delete",
            ),
        ];
        env.extend_from_slice(extra);
        Self::start_inner(db, master_key, &env, Some(key.clone())).await
    }

    /// Starts the vault with no caller declared for the tenant (decision D-A).
    async fn start_without_callers(db: &TestDb, master_key: &str) -> Self {
        Self::start_inner(db, master_key, &[], None).await
    }

    async fn start_inner(
        db: &TestDb,
        master_key: &str,
        extra: &[(&str, &str)],
        caller_key: Option<String>,
    ) -> Self {
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
            .envs(extra.iter().copied())
            .stdout(Stdio::from(log_file.try_clone().expect("clone log handle")))
            .stderr(Stdio::from(log_file))
            .spawn()
            .expect("start locker");

        let vault = Self {
            child,
            base: format!("http://127.0.0.1:{port}"),
            client: reqwest::Client::new(),
            log,
            caller_key,
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

    /// Posts `body` with the harness caller's key, when the vault declares that caller.
    async fn post(&self, path: &str, body: serde_json::Value) -> (u16, String) {
        let key = self.caller_key.clone();
        self.post_with_key(path, body, key.as_deref()).await
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

/// Sends both custodian keys and unlocks the vault. Without `key_custodian`, the vault is unlocked
/// at start-up and there is nothing to send.
#[cfg(not(feature = "key_custodian"))]
async fn unlock(vault: &Vault, keys: &Keys) {
    let _ = (vault, keys);
}

#[cfg(feature = "key_custodian")]
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

#[cfg(feature = "key_custodian")]
async fn send_key(vault: &Vault, step: &str, key: &str) -> u16 {
    vault
        .post(
            &format!("/custodian/{step}"),
            serde_json::json!({ "key": key }),
        )
        .await
        .0
}

#[cfg(feature = "key_custodian")]
fn custodian_rows(db: &TestDb) -> Vec<(String, String, i16)> {
    db.audit_rows()
        .into_iter()
        .filter(|row| row.operation.starts_with("custodian_"))
        .map(|row| (row.operation, row.outcome, row.status_code))
        .collect()
}

#[cfg(feature = "key_custodian")]
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

#[cfg(feature = "key_custodian")]
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

/// The master key as the vault uses it once unlocked: decrypted by the custodian keys with the
/// `key_custodian` feature, taken as configured without it. Never printed.
fn unlocked_master_key(keys: &Keys) -> Vec<u8> {
    #[cfg(feature = "key_custodian")]
    {
        decrypt_master_key(keys)
    }
    #[cfg(not(feature = "key_custodian"))]
    {
        hex::decode(&keys.master_key).expect("configured master key")
    }
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

    // Recompute the expected keyed hash: the master key as the vault uses it, then HMAC under the
    // derived key. Values stay in memory and are never printed.
    let master_key = unlocked_master_key(&keys);
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
        .args(["rehash", "--tenant", "public"])
        // Two rows per batch, so every data set spans several batches, unless the test sets it.
        .args(if args.contains(&"--batch-size") {
            &[][..]
        } else {
            &["--batch-size", "2"][..]
        })
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
        // Updated in reverse order, so the rows' physical order differs from their id order and
        // only the job's ordering makes the cursor see every row.
        &[
            ("legacy-enc", ENC_DATA, &["ref-enc"]),
            (
                "legacy-v1",
                CARD_NUMBER,
                &["ref-m1-c2", "ref-m2-c1", "ref-m1-c1"],
            ),
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
    // Built before the run, while the old hash values are still in the database.
    let secrets = secrets(&db, &keys, &master_key);
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
    assert_no_secret(&output, &secrets);

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
    // The same card reference for another merchant: only the merchant and customer tell the rows apart.
    store_card_with_ref(&vault, MERCHANT_2, CUSTOMER, card_data(), "ref-old").await;
    let master_key = unlocked_master_key(&keys);
    seed_v1(
        &db,
        &master_key,
        &[("legacy-v1", CARD_NUMBER, &["ref-old"])],
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
        [
            ("rehash_cleanup".to_string(), "success".to_string(), 200),
            ("rehash_run".to_string(), "success".to_string(), 200)
        ]
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
        "(now() AT TIME ZONE 'utc')",
    );
    // Crash after the move, before the old row is deleted.
    insert_hash_row(
        &resumed,
        "crash-move",
        &expected_hash(&master_key, MERCHANT, CUSTOMER, ENC_DATA),
        "(now() AT TIME ZONE 'utc')",
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
    // Built before the run, while the old hash values are still in the database.
    let secrets = secrets(&db, &keys, &master_key);
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
            ("rehash_cleanup", "success", 200),
            ("rehash_run", "success", 200),
        ]
    );
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
    insert_hash_row(
        &db,
        "fresh",
        &random_bytes(64),
        "(now() AT TIME ZONE 'utc')",
    );

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

#[cfg(feature = "key_custodian")]
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

#[tokio::test]
async fn rehash_cleanup_stops_when_audit_table_is_unwritable() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    // No card at all: the final clean-up is the only change the run would make.
    insert_hash_row(&db, "orphan-v1", &random_bytes(64), "'2000-01-01'");

    db.exec("ALTER TABLE audit_log RENAME TO audit_log_blocked");
    let (code, output) = run_rehash(&db, &keys, &keys.key2, &[]);
    db.exec("ALTER TABLE audit_log_blocked RENAME TO audit_log");

    assert_eq!(code, 1, "rehash must fail without its audit rows");
    assert!(
        output.contains("rehash failed"),
        "not the re-hash command's own error"
    );
    assert!(
        db.hash_of("orphan-v1").is_some(),
        "the clean-up deleted a row without its audit entry"
    );
}

#[tokio::test]
async fn rehash_refuses_a_batch_size_of_zero() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    seed_first(&db, &vault, &keys).await;
    drop(vault);
    let before = db.snapshot();

    let (code, output) = run_rehash(&db, &keys, &keys.key2, &["--batch-size", "0"]);
    assert_eq!(code, 1, "a batch size of 0 must be refused");
    assert!(
        output.contains("rehash failed"),
        "not the re-hash command's own error"
    );
    assert!(
        db.snapshot() == before,
        "a row changed although the run was refused"
    );
}

/// Under `kv`, every storage call of the re-hash job refuses to run: the job must stop before any
/// change. No vault is started (built with `kv`, it needs a Redis); the one unused, old hash row is
/// what a working job would delete in its clean-up.
#[cfg(feature = "kv")]
#[tokio::test]
async fn rehash_refuses_to_run_with_kv() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    insert_hash_row(&db, "orphan-v1", &random_bytes(64), "'2000-01-01'");
    let before = db.snapshot();

    let (code, output) = run_rehash(&db, &keys, &keys.key2, &[]);

    assert_eq!(code, 1, "rehash must refuse to run under kv");
    // The first storage call, the read of the locker rows, refuses with this error kind.
    assert!(
        output.contains("rehash failed: RetrieveDataFailed"),
        "not the refusal of the job's first storage call"
    );
    assert!(db.snapshot() == before, "a row changed under kv");
    let rehash: Vec<_> = db
        .audit_rows()
        .into_iter()
        .filter(|row| row.operation.starts_with("rehash_"))
        .map(|row| (row.operation, row.outcome))
        .collect();
    assert_eq!(
        rehash,
        [("rehash_run".to_string(), "failure".to_string())],
        "the job itself must run and record its refusal, with no clean-up entry"
    );
}

#[tokio::test]
async fn rehash_keeps_the_newer_copy_after_a_key_change() {
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
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "ref-new").await;
    drop(vault);
    // Then a change of master key: neither copy holds the current hash any more.
    let other_key = random_bytes(32);
    let new_hash_id = db
        .locker_rows()
        .into_iter()
        .find(|row| row.locker_id == "ref-new")
        .expect("ref-new")
        .hash_id;
    db.exec(&format!(
        "UPDATE hash_table SET data_hash = decode('{}', 'hex') WHERE hash_id = '{new_hash_id}'",
        hex::encode(expected_hash(&other_key, MERCHANT, CUSTOMER, CARD_NUMBER))
    ));

    let (code, _) = run_rehash(&db, &keys, &keys.key2, &[]);
    assert_eq!(code, 0, "rehash failed");
    let rows = db.locker_rows();
    let row = |reference: &str| {
        rows.iter()
            .find(|row| row.locker_id == reference)
            .unwrap_or_else(|| panic!("{reference} is gone"))
    };
    assert!(
        db.hash_of(&row("ref-new").hash_id)
            == Some(expected_hash(&master_key, MERCHANT, CUSTOMER, CARD_NUMBER)),
        "the newer copy does not hold the current hash"
    );
    assert!(
        db.hash_of(&row("ref-old").hash_id).is_none(),
        "the older copy is not the detached one"
    );

    let (code, output) = run_rehash(&db, &keys, &keys.key2, &[]);
    assert_eq!(code, 0, "second rehash failed");
    assert!(output.contains("moved: 0") && output.contains("duplicates: 0"));
}

// Master key rotation (`utils rotate-master-key`), see
// `docs/superpowers/specs/2026-11-23-master-key-rotation-design.md`. The vault is stopped around
// each run. Key bytes are compared with `assert!` so that a failure never prints a key.

const MERCHANT_3: &str = "demo-merchant-3";
/// A second public test card number, so that two merchants' cards cannot be mistaken for each other.
const CARD_2: &str = "5555555555554444";
const MERCHANT_NO_CARD: &str = "merchant-no-card";

#[derive(QueryableByName, Debug)]
struct MerchantRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    merchant_id: String,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    enc_key: Vec<u8>,
}

#[derive(QueryableByName, Debug)]
struct LockerDataRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    locker_id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    merchant_id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    customer_id: String,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    enc_data: Vec<u8>,
    #[diesel(sql_type = diesel::sql_types::Text)]
    hash_id: String,
}

fn card_data_with(number: &str) -> serde_json::Value {
    serde_json::json!({ "card": { "card_number": number } })
}

/// Fails unless `body`, a `/data/retrieve` response, returns exactly `expected` as the card number.
fn assert_card_number(body: &str, expected: &str, reference: &str) {
    let response: serde_json::Value = serde_json::from_str(body).expect("retrieve JSON");
    assert!(
        response["payload"]["card"]["card_number"].as_str() == Some(expected),
        "{reference} does not return its own card number"
    );
}

/// `(merchant_id, enc_key)` of every `merchant` row, ordered by merchant id.
fn merchant_rows(db: &TestDb) -> Vec<(String, Vec<u8>)> {
    diesel::sql_query("SELECT merchant_id, enc_key FROM merchant ORDER BY merchant_id")
        .load::<MerchantRow>(&mut db.connection())
        .expect("read merchant")
        .into_iter()
        .map(|row| (row.merchant_id, row.enc_key))
        .collect()
}

/// Every column of every `merchant` row, as text, in a stable order.
fn merchant_snapshot(db: &TestDb) -> Vec<String> {
    diesel::sql_query("SELECT t::text AS text FROM merchant t ORDER BY merchant_id")
        .load::<TextRow>(&mut db.connection())
        .expect("snapshot merchant")
        .into_iter()
        .map(|row| row.text)
        .collect()
}

/// `locker`, `hash_table` and `merchant` snapshots together.
fn full_snapshot(db: &TestDb) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (locker, hashes) = db.snapshot();
    (locker, hashes, merchant_snapshot(db))
}

fn locker_data(db: &TestDb) -> Vec<LockerDataRow> {
    diesel::sql_query(
        "SELECT locker_id, merchant_id, customer_id, enc_data, hash_id FROM locker \
         ORDER BY merchant_id, customer_id, locker_id",
    )
    .load(&mut db.connection())
    .expect("read locker")
}

/// The plaintext of `blob` under `key`, if `key` opens it (AES-GCM tag checked).
fn opens(key: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    GcmAes256::new(key.to_vec()).decrypt(blob.to_vec()).ok()
}

fn wrap(key: &[u8], plain: &[u8]) -> Vec<u8> {
    GcmAes256::new(key.to_vec())
        .encrypt(plain.to_vec())
        .expect("encrypt")
}

/// Merchant key of each row, opened with `key` (every row must open). Never printed.
fn merchant_keys(db: &TestDb, key: &[u8]) -> std::collections::BTreeMap<String, Vec<u8>> {
    merchant_rows(db)
        .into_iter()
        .map(|(id, blob)| {
            let dek = opens(key, &blob).unwrap_or_else(|| panic!("{id} does not open"));
            (id, dek)
        })
        .collect()
}

/// Standard input of the command: former then new custodian keys with `key_custodian`, the new
/// raw key (hex) without it.
fn rotation_input(former: &Keys, new: &Keys) -> String {
    #[cfg(feature = "key_custodian")]
    {
        format!(
            "{}\n{}\n{}\n{}\n{}\n",
            former.key1, former.key2, new.master_key, new.key1, new.key2
        )
    }
    #[cfg(not(feature = "key_custodian"))]
    {
        let _ = former;
        format!("{}\n", new.master_key)
    }
}

/// Runs `utils rotate-master-key` with the former master key in the configuration and `stdin` on
/// standard input. Returns the exit code and the joined standard output and error.
fn run_rotation(db: &TestDb, former: &Keys, stdin: &str, args: &[&str]) -> (i32, String) {
    use std::io::{Read, Write};

    let host = db.url.host_str().expect("database host").to_string();
    let db_port = db.url.port().unwrap_or(5432).to_string();
    let password = db.url.password().unwrap_or("unused").to_string();
    let mut command = Command::new(env!("CARGO_BIN_EXE_utils"));
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["rotate-master-key", "--tenant", "public"])
        .args(if args.contains(&"--batch-size") {
            &[][..]
        } else {
            &["--batch-size", "2"][..]
        })
        .args(args)
        .env("LOCKER__DATABASE__HOST", host)
        .env("LOCKER__DATABASE__PORT", db_port)
        .env("LOCKER__DATABASE__USERNAME", db.url.username())
        .env("LOCKER__DATABASE__PASSWORD", password)
        .env("LOCKER__DATABASE__DBNAME", &db.name)
        .env(
            "LOCKER__TENANT_SECRETS__PUBLIC__MASTER_KEY",
            &former.master_key,
        );
    #[cfg(feature = "external_key_manager")]
    if let Ok(url) = std::env::var("VAULT_TEST_KEY_MANAGER_URL") {
        command
            .env("LOCKER__EXTERNAL_KEY_MANAGER__MODE", "enabled")
            .env("LOCKER__EXTERNAL_KEY_MANAGER__URL", url);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start utils rotate-master-key");
    let _ = child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes());

    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for utils") {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("rotation timed out");
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

/// Values that must never appear in an output or an audit row: `secrets` for both key sets, both
/// raw master keys, every merchant key and every `enc_key` value in the database now, every hash.
fn rotation_secrets(db: &TestDb, former: &Keys, new: &Keys) -> Vec<String> {
    let former_raw = unlocked_master_key(former);
    let new_raw = unlocked_master_key(new);
    let mut values = secrets(db, former, &former_raw);
    values.extend(secrets(db, new, &new_raw));
    values.push(CARD_2.to_string());
    for (_, blob) in merchant_rows(db) {
        values.push(hex::encode(&blob));
        for key in [&former_raw, &new_raw] {
            if let Some(dek) = opens(key, &blob) {
                values.push(hex::encode(dek));
            }
        }
    }
    values
}

fn rotation_audit(db: &TestDb) -> Vec<(String, String, i16)> {
    db.audit_rows()
        .into_iter()
        .filter(|row| row.operation.starts_with("master_key_rotation_"))
        .map(|row| (row.operation, row.outcome, row.status_code))
        .collect()
}

/// The test card for `MERCHANT` (`ref-m1`), `CARD_2` for `MERCHANT_2` (`ref-m2`), and
/// `MERCHANT_NO_CARD` created by `POST /entity` with no card.
async fn seed_rotation(vault: &Vault) {
    store_card_with_ref(vault, MERCHANT, CUSTOMER, card_data(), "ref-m1").await;
    store_card_with_ref(
        vault,
        MERCHANT_2,
        CUSTOMER,
        card_data_with(CARD_2),
        "ref-m2",
    )
    .await;
    let (status, _) = vault
        .post(
            "/entity",
            serde_json::json!({ "entity_id": MERCHANT_NO_CARD }),
        )
        .await;
    assert_eq!(status, 200, "create entity");
}

fn retrieve_request(merchant: &str, reference: &str) -> serde_json::Value {
    serde_json::json!({
        "merchant_id": merchant,
        "merchant_customer_id": CUSTOMER,
        "card_reference": reference
    })
}

#[tokio::test]
async fn rotation_cards_read_back_for_two_merchants() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let (former, new) = (Keys::generate(), Keys::generate());
    let vault = Vault::start(&db, &former.master_key).await;
    unlock(&vault, &former).await;
    seed_rotation(&vault).await;
    drop(vault);
    let before = merchant_keys(&db, &unlocked_master_key(&former));
    assert_eq!(before.len(), 3, "three merchant rows");

    let (code, output) = run_rotation(&db, &former, &rotation_input(&former, &new), &[]);
    assert_eq!(code, 0, "rotation failed");
    assert!(
        output.contains("rewritten: 3"),
        "every merchant row rewritten"
    );

    let vault = Vault::start(&db, &new.master_key).await;
    unlock(&vault, &new).await;
    for (merchant, reference, number) in [
        (MERCHANT, "ref-m1", CARD_NUMBER),
        (MERCHANT_2, "ref-m2", CARD_2),
    ] {
        let (status, body) = vault
            .post("/data/retrieve", retrieve_request(merchant, reference))
            .await;
        assert_eq!(status, 200, "retrieve {reference}");
        assert_card_number(&body, number, reference);
    }
    let new_raw = unlocked_master_key(&new);
    for (merchant_id, blob) in merchant_rows(&db) {
        assert!(
            opens(&new_raw, &blob).as_ref() == before.get(&merchant_id),
            "{merchant_id} does not hold its merchant key under the new master key"
        );
    }
}

#[tokio::test]
async fn rotation_former_key_opens_no_merchant_row() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let (former, new) = (Keys::generate(), Keys::generate());
    let vault = Vault::start(&db, &former.master_key).await;
    unlock(&vault, &former).await;
    seed_rotation(&vault).await;
    drop(vault);

    let (code, _) = run_rotation(&db, &former, &rotation_input(&former, &new), &[]);
    assert_eq!(code, 0, "rotation failed");

    let (former_raw, new_raw) = (unlocked_master_key(&former), unlocked_master_key(&new));
    let rows = merchant_rows(&db);
    assert_eq!(rows.len(), 3);
    for (merchant_id, blob) in rows {
        assert!(
            opens(&former_raw, &blob).is_none(),
            "{merchant_id} still opens under the former master key"
        );
        assert!(
            opens(&new_raw, &blob).is_some(),
            "{merchant_id} does not open under the new master key"
        );
    }
}

#[tokio::test]
async fn rotation_keeps_duplicate_detection() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let (former, new) = (Keys::generate(), Keys::generate());
    let vault = Vault::start(&db, &former.master_key).await;
    unlock(&vault, &former).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "ref-m1").await;
    drop(vault);

    let (code, _) = run_rotation(&db, &former, &rotation_input(&former, &new), &[]);
    assert_eq!(code, 0, "rotation failed");

    let new_raw = unlocked_master_key(&new);
    let vault = Vault::start(&db, &new.master_key).await;
    unlock(&vault, &new).await;
    let again = store_card_as(&vault, MERCHANT, CUSTOMER, CARD_NUMBER).await;
    assert_eq!(again["payload"]["duplication_check"], "duplicated");
    assert_eq!(db.count("locker"), 1, "the duplicate add stored a copy");
    for row in db.locker_rows() {
        assert!(
            db.hash_of(&row.hash_id)
                == Some(expected_hash(
                    &new_raw,
                    &row.merchant_id,
                    &row.customer_id,
                    CARD_NUMBER
                )),
            "{} does not cite its hash under the new key",
            row.locker_id
        );
    }
    drop(vault);

    // The check the operator runs once the configuration holds the new key.
    let (code, output) = run_rehash(&db, &new, &new.key2, &[]);
    assert_eq!(code, 0, "rehash with the new key failed");
    assert!(output.contains("moved: 0"), "rehash still had rows to move");
}

/// State of one database after a rotation, comparable across databases (the ciphertexts differ,
/// since each encryption draws a random nonce): for each merchant, which key opens its row and
/// whether its merchant key is unchanged; for each card, whether its data is byte for byte
/// unchanged and whether it cites its hash under the new key; the number of hash rows.
fn canonical(
    db: &TestDb,
    former_raw: &[u8],
    new_raw: &[u8],
    deks: &std::collections::BTreeMap<String, Vec<u8>>,
    cards: &std::collections::BTreeMap<String, Vec<u8>>,
) -> Vec<String> {
    let mut state: Vec<String> = merchant_rows(db)
        .into_iter()
        .map(|(id, blob)| {
            format!(
                "{id} new={} former={} same_key={}",
                opens(new_raw, &blob).is_some(),
                opens(former_raw, &blob).is_some(),
                opens(new_raw, &blob).as_ref() == deks.get(&id)
            )
        })
        .collect();
    for row in locker_data(db) {
        let expected = expected_hash(new_raw, &row.merchant_id, &row.customer_id, CARD_NUMBER);
        state.push(format!(
            "{}/{}/{} same_data={} hash_ok={}",
            row.merchant_id,
            row.customer_id,
            row.locker_id,
            cards.get(&row.locker_id) == Some(&row.enc_data),
            db.hash_of(&row.hash_id) == Some(expected)
        ));
    }
    state.push(format!("hash rows={}", db.count("hash_table")));
    state
}

#[tokio::test]
async fn rotation_resumed_after_interruption_matches_a_full_run() {
    let Some(admin) = admin_url() else { return };
    let (former, new) = (Keys::generate(), Keys::generate());
    let (former_raw, new_raw) = (unlocked_master_key(&former), unlocked_master_key(&new));
    let full = TestDb::create(&admin);
    let resumed = TestDb::create(&admin);
    let crashed = TestDb::create(&admin);
    let mut before = Vec::new();
    for db in [&full, &resumed, &crashed] {
        let vault = Vault::start(db, &former.master_key).await;
        unlock(&vault, &former).await;
        store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "ref-m1").await;
        store_card_with_ref(&vault, MERCHANT_2, CUSTOMER, card_data(), "ref-m2").await;
        store_card_with_ref(&vault, MERCHANT_3, CUSTOMER, card_data(), "ref-m3").await;
        store_card_with_ref(&vault, MERCHANT, CUSTOMER_2, card_data(), "ref-m1-c2").await;
        drop(vault);
        let cards = locker_data(db)
            .into_iter()
            .map(|row| (row.locker_id, row.enc_data))
            .collect();
        before.push((merchant_keys(db, &former_raw), cards));
    }
    let input = rotation_input(&former, &new);

    let (code, _) = run_rotation(&full, &former, &input, &[]);
    assert_eq!(code, 0, "full rotation failed");

    // Stopped between rows: one merchant row rewritten, the hash step not run.
    let (code, output) = run_rotation(&resumed, &former, &input, &["--max-rows", "1"]);
    assert_eq!(code, 2, "an interrupted run must exit 2");
    assert!(output.contains("rewritten: 1") && output.contains("complete: no"));
    // Started again from that mixed state, with no help: it progresses.
    let (code, output) = run_rotation(&resumed, &former, &input, &["--max-rows", "1"]);
    assert_eq!(code, 2, "the second interrupted run must exit 2");
    assert!(
        output.contains("rewritten: 1") && output.contains("already under the new key: 1"),
        "the second run did not progress from the mixed state"
    );
    // Run again from that mixed state, with no help, until it finishes.
    let (code, output) = run_rotation(&resumed, &former, &input, &[]);
    assert_eq!(code, 0, "resumed rotation failed");
    assert!(
        output.contains("rewritten: 1")
            && output.contains("already under the new key: 2")
            && output.contains("complete: yes"),
        "the resumed run did not finish the last row"
    );

    // A run killed after its last merchant row, before the hash step: every row is under the new
    // key, written here by the test, and the hashes are still those of the former key.
    for (merchant_id, blob) in merchant_rows(&crashed) {
        let dek = opens(&former_raw, &blob).expect("row under the former key");
        crashed.exec(&format!(
            "UPDATE merchant SET enc_key = decode('{}', 'hex') WHERE merchant_id = '{merchant_id}'",
            hex::encode(wrap(&new_raw, &dek))
        ));
    }
    let (code, output) = run_rotation(&crashed, &former, &input, &[]);
    assert_eq!(
        code, 0,
        "rotation after a crash before the hash step failed"
    );
    assert!(output.contains("already under the new key: 3") && output.contains("complete: yes"));

    let state_full = canonical(&full, &former_raw, &new_raw, &before[0].0, &before[0].1);
    let state_resumed = canonical(&resumed, &former_raw, &new_raw, &before[1].0, &before[1].1);
    let state_crashed = canonical(&crashed, &former_raw, &new_raw, &before[2].0, &before[2].1);
    let wrong = [
        "new=false",
        "former=true",
        "same_key=false",
        "same_data=false",
        "hash_ok=false",
    ];
    assert!(
        state_full
            .iter()
            .all(|line| wrong.iter().all(|bad| !line.contains(bad))),
        "the full run did not reach the expected state: {state_full:?}"
    );
    assert_eq!(state_full, state_resumed, "resumed run");
    assert_eq!(
        state_full, state_crashed,
        "run after a crash before the hash step"
    );

    // Run again after a complete rotation: nothing changes.
    let snapshot = full_snapshot(&full);
    let (code, output) = run_rotation(&full, &former, &input, &[]);
    assert_eq!(code, 0, "a run after a complete rotation failed");
    assert!(output.contains("already under the new key: 3"));
    assert!(
        full_snapshot(&full) == snapshot,
        "a run after a complete rotation changed a row"
    );
}

#[cfg(feature = "key_custodian")]
#[tokio::test]
async fn rotation_refuses_wrong_custodian_keys() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let (former, new, other) = (Keys::generate(), Keys::generate(), Keys::generate());
    let vault = Vault::start(&db, &former.master_key).await;
    unlock(&vault, &former).await;
    seed_rotation(&vault).await;
    drop(vault);
    let before = full_snapshot(&db);
    // A wrong key of the right shape (16 bytes as hex).
    let wrong = uuid::Uuid::now_v7().simple().to_string();
    let mut secrets = rotation_secrets(&db, &former, &new);
    secrets.extend(rotation_secrets(&db, &former, &other));
    secrets.push(wrong.clone());

    let line = |k1: &str, k2: &str, enc: &str, n1: &str, n2: &str| {
        format!("{k1}\n{k2}\n{enc}\n{n1}\n{n2}\n")
    };
    let cases = [
        (
            "wrong former key 2",
            line(&former.key1, &wrong, &new.master_key, &new.key1, &new.key2),
        ),
        (
            "wrong new key 2",
            line(
                &former.key1,
                &former.key2,
                &new.master_key,
                &new.key1,
                &wrong,
            ),
        ),
        (
            "new encrypted key of another generation",
            line(
                &former.key1,
                &former.key2,
                &other.master_key,
                &new.key1,
                &new.key2,
            ),
        ),
        (
            "four lines",
            format!(
                "{}\n{}\n{}\n{}\n",
                former.key1, former.key2, new.master_key, new.key1
            ),
        ),
    ];
    for (case, input) in cases {
        let runs_before = rotation_audit(&db).len();
        let (code, output) = run_rotation(&db, &former, &input, &[]);
        assert_eq!(code, 1, "{case}: must be refused");
        assert!(
            output.contains("rotation failed: DecryptingKeysFailed"),
            "{case}: not the refusal of the custodian keys"
        );
        assert!(full_snapshot(&db) == before, "{case}: a row changed");
        let audit = rotation_audit(&db);
        assert_eq!(audit.len(), runs_before + 1, "{case}: no run entry");
        assert_eq!(
            (audit[runs_before].0.as_str(), audit[runs_before].1.as_str()),
            ("master_key_rotation_run", "failure"),
            "{case}"
        );
        assert_no_secret(&output, &secrets);
        for row in db.audit_rows() {
            assert_no_secret(&row.text, &secrets);
        }
    }
}

#[tokio::test]
async fn rotation_refuses_the_same_master_key() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let former = Keys::generate();
    let vault = Vault::start(&db, &former.master_key).await;
    unlock(&vault, &former).await;
    seed_rotation(&vault).await;
    drop(vault);
    let before = full_snapshot(&db);

    let mut cases = vec![("same keys", rotation_input(&former, &former))];
    #[cfg(feature = "key_custodian")]
    {
        // The same master key wrapped under other custodian keys: a change of custodian keys only.
        let other = Keys::generate();
        let custodian = hex::decode(format!("{}{}", other.key1, other.key2)).expect("hex");
        let rewrapped = hex::encode(wrap(&custodian, &unlocked_master_key(&former)));
        cases.push((
            "same master key, other custodian keys",
            format!(
                "{}\n{}\n{rewrapped}\n{}\n{}\n",
                former.key1, former.key2, other.key1, other.key2
            ),
        ));
    }
    #[cfg(not(feature = "key_custodian"))]
    cases.push((
        "raw key of 31 bytes",
        format!("{}\n", hex::encode(random_bytes(31))),
    ));

    for (case, input) in cases {
        let (code, output) = run_rotation(&db, &former, &input, &[]);
        assert_eq!(code, 1, "{case}: must be refused");
        assert!(
            output.contains("rotation failed: ValidationError"),
            "{case}: not the refusal of the new key"
        );
        assert!(full_snapshot(&db) == before, "{case}: a row changed");
    }
}

#[tokio::test]
async fn rotation_refuses_a_row_under_a_third_key() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let (former, new) = (Keys::generate(), Keys::generate());
    let vault = Vault::start(&db, &former.master_key).await;
    unlock(&vault, &former).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "ref-m1").await;
    store_card_with_ref(&vault, MERCHANT_2, CUSTOMER, card_data(), "ref-m2").await;
    drop(vault);
    // Last in id order, so the rows before it would already be rewritten without the pre-check.
    db.exec(&format!(
        "INSERT INTO merchant (merchant_id, enc_key, created_at) \
         VALUES ('merchant-third', decode('{}', 'hex'), (now() AT TIME ZONE 'utc'))",
        hex::encode(wrap(&random_bytes(32), &random_bytes(32)))
    ));
    let before = full_snapshot(&db);

    let (code, output) = run_rotation(&db, &former, &rotation_input(&former, &new), &[]);
    assert_eq!(code, 1, "a row under a third key must stop the run");
    assert!(
        output.contains("rotation failed: MerchantKeyError"),
        "not the refusal of the pre-check"
    );
    assert!(full_snapshot(&db) == before, "a row changed");
}

#[tokio::test]
async fn rotation_audit_and_output_hold_no_key() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let (former, new) = (Keys::generate(), Keys::generate());
    let vault = Vault::start(&db, &former.master_key).await;
    unlock(&vault, &former).await;
    seed_rotation(&vault).await;
    drop(vault);
    let mut secrets = rotation_secrets(&db, &former, &new);

    let (code, output) = run_rotation(&db, &former, &rotation_input(&former, &new), &[]);
    assert_eq!(code, 0, "rotation failed");
    secrets.extend(rotation_secrets(&db, &former, &new));

    let summary: Vec<_> = rotation_audit(&db)
        .iter()
        .map(|(operation, outcome, status)| (operation.clone(), outcome.clone(), *status))
        .collect();
    let row = || {
        (
            "master_key_rotation_row".to_string(),
            "success".to_string(),
            200,
        )
    };
    assert_eq!(
        summary,
        [
            row(),
            row(),
            row(),
            (
                "master_key_rotation_run".to_string(),
                "success".to_string(),
                200
            )
        ]
    );
    for row in db.audit_rows() {
        assert_no_secret(&row.text, &secrets);
    }
    assert_no_secret(&output, &secrets);
}

#[tokio::test]
async fn rotation_stops_when_audit_table_is_unwritable() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let (former, new) = (Keys::generate(), Keys::generate());
    let vault = Vault::start(&db, &former.master_key).await;
    unlock(&vault, &former).await;
    seed_rotation(&vault).await;
    drop(vault);
    let before = full_snapshot(&db);

    db.exec("ALTER TABLE audit_log RENAME TO audit_log_blocked");
    let (code, output) = run_rotation(&db, &former, &rotation_input(&former, &new), &[]);
    db.exec("ALTER TABLE audit_log_blocked RENAME TO audit_log");

    assert_eq!(code, 1, "the rotation must fail without its audit rows");
    assert!(
        output.contains("rotation failed"),
        "not the command's own error"
    );
    assert!(
        full_snapshot(&db) == before,
        "a row changed without its audit entry"
    );
}

#[tokio::test]
async fn rotation_on_an_empty_tenant_succeeds() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let (former, new) = (Keys::generate(), Keys::generate());

    let (code, output) = run_rotation(&db, &former, &rotation_input(&former, &new), &[]);
    assert_eq!(code, 0, "rotation of an empty tenant failed");
    for line in ["merchant rows: 0", "hash examined: 0", "complete: yes"] {
        assert!(output.contains(line), "output lacks `{line}`");
    }
}

#[tokio::test]
async fn rotation_refuses_a_batch_size_of_zero() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let (former, new) = (Keys::generate(), Keys::generate());
    let vault = Vault::start(&db, &former.master_key).await;
    unlock(&vault, &former).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "ref-m1").await;
    drop(vault);
    let before = full_snapshot(&db);

    let (code, output) = run_rotation(
        &db,
        &former,
        &rotation_input(&former, &new),
        &["--batch-size", "0"],
    );
    assert_eq!(code, 1, "a batch size of 0 must be refused");
    assert!(output.contains("rotation failed: ValidationError"));
    assert!(full_snapshot(&db) == before, "a row changed");
}

/// Under `kv`, the pre-check's read of the locker rows refuses before any merchant row is written.
/// No vault is started (built with `kv`, it needs a Redis).
#[cfg(feature = "kv")]
#[tokio::test]
async fn rotation_refuses_to_run_with_kv() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let (former, new) = (Keys::generate(), Keys::generate());
    db.exec(&format!(
        "INSERT INTO merchant (merchant_id, enc_key, created_at) \
         VALUES ('{MERCHANT}', decode('{}', 'hex'), (now() AT TIME ZONE 'utc'))",
        hex::encode(wrap(&unlocked_master_key(&former), &random_bytes(32)))
    ));
    let before = full_snapshot(&db);

    let (code, output) = run_rotation(&db, &former, &rotation_input(&former, &new), &[]);
    assert_eq!(code, 1, "the rotation must refuse to run under kv");
    assert!(
        output.contains("rotation failed: RetrieveDataFailed"),
        "not the refusal of the locker read"
    );
    assert!(full_snapshot(&db) == before, "a row changed under kv");
    let audit: Vec<_> = rotation_audit(&db)
        .into_iter()
        .map(|(operation, outcome, _)| (operation, outcome))
        .collect();
    assert_eq!(
        audit,
        [("master_key_rotation_run".to_string(), "failure".to_string())]
    );
}

/// Against Juspay's Hyperswitch Encryption Service, reached at `VAULT_TEST_KEY_MANAGER_URL`. Cards
/// are encrypted by the service; the master key still wraps a merchant row waiting for
/// `/key/transfer` and still keys the duplicate-check hash.
#[cfg(feature = "external_key_manager")]
#[tokio::test]
async fn rotation_with_external_key_manager() {
    let Some(admin) = admin_url() else { return };
    let Ok(url) = std::env::var("VAULT_TEST_KEY_MANAGER_URL") else {
        assert!(
            std::env::var_os("VAULT_TEST_REQUIRE_DB").is_none(),
            "VAULT_TEST_REQUIRE_DB is set but VAULT_TEST_KEY_MANAGER_URL is not"
        );
        println!("skipped: VAULT_TEST_KEY_MANAGER_URL not set");
        return;
    };
    let env = [
        ("LOCKER__EXTERNAL_KEY_MANAGER__MODE", "enabled"),
        ("LOCKER__EXTERNAL_KEY_MANAGER__URL", url.as_str()),
    ];
    let db = TestDb::create(&admin);
    let (former, new) = (Keys::generate(), Keys::generate());
    let (former_raw, new_raw) = (unlocked_master_key(&former), unlocked_master_key(&new));
    let vault = Vault::start_with_env(&db, &former.master_key, &env).await;
    unlock(&vault, &former).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "ref-m1").await;
    store_card_with_ref(
        &vault,
        MERCHANT_2,
        CUSTOMER,
        card_data_with(CARD_2),
        "ref-m2",
    )
    .await;
    drop(vault);
    // A merchant key an older deployment left, waiting for `/key/transfer`.
    db.exec(&format!(
        "INSERT INTO merchant (merchant_id, enc_key, created_at) \
         VALUES ('legacy-merchant', decode('{}', 'hex'), (now() AT TIME ZONE 'utc'))",
        hex::encode(wrap(&former_raw, &random_bytes(32)))
    ));

    let (code, _) = run_rotation(&db, &former, &rotation_input(&former, &new), &[]);
    assert_eq!(code, 0, "rotation failed");

    let legacy = merchant_rows(&db)
        .into_iter()
        .find(|(id, _)| id == "legacy-merchant")
        .expect("legacy-merchant")
        .1;
    assert!(
        opens(&new_raw, &legacy).is_some() && opens(&former_raw, &legacy).is_none(),
        "the merchant row waiting for transfer is not under the new key only"
    );

    let vault = Vault::start_with_env(&db, &new.master_key, &env).await;
    unlock(&vault, &new).await;
    for (merchant, reference, number) in [
        (MERCHANT, "ref-m1", CARD_NUMBER),
        (MERCHANT_2, "ref-m2", CARD_2),
    ] {
        let (status, body) = vault
            .post("/data/retrieve", retrieve_request(merchant, reference))
            .await;
        assert_eq!(status, 200, "retrieve {reference}");
        assert_card_number(&body, number, reference);
    }
    let again = store_card_as(&vault, MERCHANT, CUSTOMER, CARD_NUMBER).await;
    assert_eq!(again["payload"]["duplication_check"], "duplicated");
    let (status, body) = vault
        .post("/key/transfer", serde_json::json!({ "limit": 10 }))
        .await;
    assert_eq!(status, 200, "key transfer");
    let transferred: serde_json::Value = serde_json::from_str(&body).expect("transfer JSON");
    assert_eq!(transferred["total_transferred"], 1);
}

/// Threat T13, write side: each merchant's data key opens every card row of that merchant and no
/// row of another merchant; the master key opens none. Failure messages name references and
/// merchants only.
#[tokio::test]
async fn each_merchant_key_opens_only_its_own_cards() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    // CARD_NUMBER is held by two merchants; the other numbers by one merchant only.
    let cards = [
        (MERCHANT, "iso-m1-a", CARD_NUMBER),
        (MERCHANT, "iso-m1-b", CARD_2),
        (MERCHANT_2, "iso-m2-a", CARD_NUMBER),
        (MERCHANT_3, "iso-m3-a", "4012888888881881"),
    ];
    for (merchant, reference, number) in cards {
        store_card_with_ref(
            &vault,
            merchant,
            CUSTOMER,
            card_data_with(number),
            reference,
        )
        .await;
    }
    drop(vault);

    let master = unlocked_master_key(&keys);
    let deks = merchant_keys(&db, &master);
    let rows = locker_data(&db);

    // D1: every stored card is there, under its own merchant.
    assert_eq!(deks.len(), 3, "three merchant keys");
    assert_eq!(rows.len(), cards.len(), "locker row count");
    for merchant in [MERCHANT, MERCHANT_2, MERCHANT_3] {
        let expected = cards.iter().filter(|card| card.0 == merchant).count();
        let stored = rows
            .iter()
            .filter(|row| row.merchant_id == merchant)
            .count();
        assert_eq!(stored, expected, "{merchant} row count");
    }

    // D2: each merchant's key opens its own rows to the card number it stored.
    for row in &rows {
        let (_, _, number) = cards
            .iter()
            .find(|card| card.0 == row.merchant_id && card.1 == row.locker_id)
            .expect("row stored by this test");
        let plain = deks
            .get(&row.merchant_id)
            .and_then(|key| opens(key, &row.enc_data));
        // The plaintext is the stored JSON, `{"CardData": {"card_number": ...}}`.
        let stored =
            plain.and_then(|plain| serde_json::from_slice::<serde_json::Value>(&plain).ok());
        assert!(
            stored
                .is_some_and(|stored| stored["CardData"]["card_number"].as_str() == Some(*number)),
            "{} of {} does not open to its card under its own merchant key",
            row.locker_id,
            row.merchant_id
        );
    }

    // D3: exactly one key opens each row, its own merchant's.
    let mut openers: Vec<(&str, &[u8])> = deks
        .iter()
        .map(|(merchant, key)| (merchant.as_str(), key.as_slice()))
        .collect();
    openers.push(("master key", master.as_slice()));
    let mut isolated = true;
    let mut matrix = String::new();
    for row in &rows {
        let (open, refuse): (Vec<_>, Vec<_>) = openers
            .iter()
            .partition(|(_, key)| opens(key, &row.enc_data).is_some());
        let open: Vec<&str> = open.iter().map(|(name, _)| *name).collect();
        let refuse: Vec<&str> = refuse.iter().map(|(name, _)| *name).collect();
        isolated &= open == [row.merchant_id.as_str()];
        matrix.push_str(&format!(
            "{} of {}: OPENS {open:?} REFUSES {refuse:?}\n",
            row.locker_id, row.merchant_id
        ));
    }
    assert!(
        isolated,
        "a card row opens under another key than its merchant's:\n{matrix}"
    );
}

/// Threat T13, read side: a card row copied in the database from one merchant to another is not
/// returned to the second merchant, because the vault decrypts with the requesting merchant's key.
#[tokio::test]
async fn card_moved_to_another_merchant_is_not_returned() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    store_card_with_ref(
        &vault,
        MERCHANT,
        CUSTOMER,
        card_data_with(CARD_NUMBER),
        "iso-a",
    )
    .await;
    store_card_with_ref(
        &vault,
        MERCHANT_2,
        CUSTOMER,
        card_data_with(CARD_2),
        "iso-b",
    )
    .await;

    // Positive control: merchant 2 reads its own card through the same route.
    let (status, body) = vault
        .post("/data/retrieve", retrieve_request(MERCHANT_2, "iso-b"))
        .await;
    assert_eq!(status, 200, "merchant 2 reads its own card");
    assert_card_number(&body, CARD_2, "iso-b");

    // Copy merchant 1's row under merchant 2, unchanged except merchant and reference.
    db.exec(&format!(
        "INSERT INTO locker \
         (locker_id, merchant_id, customer_id, enc_data, hash_id, created_at, ttl, updated_by) \
         SELECT 'iso-moved', '{MERCHANT_2}', customer_id, enc_data, hash_id, created_at, ttl, \
         updated_by FROM locker WHERE merchant_id = '{MERCHANT}' AND locker_id = 'iso-a'"
    ));
    assert_eq!(db.count("locker"), 3, "row copied");

    let (status, body) = vault
        .post("/data/retrieve", retrieve_request(MERCHANT_2, "iso-moved"))
        .await;
    // The refusal must come from decryption under merchant 2's key (400, crypto error), not from a
    // lookup that missed the row (404).
    let refused = status == 400 && body.contains("encrypting/decrypting");
    let leaked = [CARD_NUMBER, CARD_2]
        .iter()
        .any(|number| body.contains(number));
    assert!(
        refused && !leaked,
        "a card copied from {MERCHANT} is not refused by decryption for {MERCHANT_2} \
         (status {status}, decryption refusal {refused}, card number in body {leaked})"
    );
    assert_no_secret(&body, &[CARD_NUMBER.to_string(), CARD_2.to_string()]);
}

// Per-caller read control (T19), see
// `docs/superpowers/specs/2026-11-24-per-caller-read-control-design.md`. Caller keys are generated
// here and never printed; the configuration receives only their SHA-256. Assertion messages never
// print a response body.

const NOT_ALLOWED: &str = "Caller is not allowed to read this merchant's data";
const KEY_REFUSED: &str = "Caller key missing or unknown";

/// A random caller key (hex) and the lower-case hex SHA-256 the configuration holds for it.
fn caller_key() -> (String, String) {
    let key = hex::encode(random_bytes(32));
    let hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, key.as_bytes()));
    (key, hash)
}

/// Starts the vault with one caller, `reader`, allowed to read `merchants` (comma-separated).
async fn start_with_caller(db: &TestDb, keys: &Keys, key_hash: &str, merchants: &str) -> Vault {
    Vault::start_with_env(
        db,
        &keys.master_key,
        &[
            (
                "LOCKER__TENANT_SECRETS__PUBLIC__CALLERS__READER__KEY_HASH",
                key_hash,
            ),
            (
                "LOCKER__TENANT_SECRETS__PUBLIC__CALLERS__READER__MERCHANTS",
                merchants,
            ),
        ],
    )
    .await
}

impl Vault {
    /// Like `post`, with `x-vault-caller-key` set when `key` is given.
    async fn post_with_key(
        &self,
        path: &str,
        body: serde_json::Value,
        key: Option<&str>,
    ) -> (u16, String) {
        let mut request = self
            .client
            .post(format!("{}{path}", self.base))
            .header("x-tenant-id", "public")
            .json(&body);
        if let Some(key) = key {
            request = request.header("x-vault-caller-key", key);
        }
        let response = request.send().await.expect("send request");
        let status = response.status().as_u16();
        (status, response.text().await.expect("response body"))
    }
}

/// Fails unless the response is exactly the refusal `message` with `status`, holding no card number.
fn assert_refusal(status: u16, body: &str, expected_status: u16, message: &str, what: &str) {
    assert_eq!(status, expected_status, "{what}: status");
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    assert!(
        parsed == serde_json::json!({ "code": "TE_00", "message": message, "data": null }),
        "{what}: the body is not the expected refusal"
    );
    assert!(
        !body.contains(CARD_NUMBER) && !body.contains(CARD_2),
        "{what}: card number in the refusal body"
    );
}

/// `(operation, outcome, status_code)` of the audit rows of `operation`, in order.
fn audit_of(db: &TestDb, operation: &str) -> Vec<(String, String, i16)> {
    db.audit_rows()
        .into_iter()
        .filter(|row| row.operation == operation)
        .map(|row| (row.operation, row.outcome, row.status_code))
        .collect()
}

fn audit_holds_no_card(db: &TestDb) -> bool {
    db.audit_rows()
        .iter()
        .all(|row| !row.text.contains(CARD_NUMBER) && !row.text.contains(CARD_2))
}

#[tokio::test]
async fn caller_reads_only_its_merchants_cards() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let (key, key_hash) = caller_key();
    let vault = start_with_caller(&db, &keys, &key_hash, MERCHANT).await;
    unlock(&vault, &keys).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "own-card").await;
    store_card_with_ref(
        &vault,
        MERCHANT_2,
        CUSTOMER,
        card_data_with(CARD_2),
        "other-card",
    )
    .await;

    for path in ["/data/retrieve", "/cards/retrieve"] {
        let (status, body) = vault
            .post_with_key(path, retrieve_request(MERCHANT, "own-card"), Some(&key))
            .await;
        assert_eq!(
            status, 200,
            "{path}: the caller reads its own merchant's card"
        );
        assert_card_number(&body, CARD_NUMBER, "own-card");

        // The other merchant's card exists, with its correct reference and customer.
        let (status, body) = vault
            .post_with_key(path, retrieve_request(MERCHANT_2, "other-card"), Some(&key))
            .await;
        assert_refusal(status, &body, 403, NOT_ALLOWED, path);
    }

    // A reference that does not exist gets the same refusal, not a 404: the check runs first.
    let (status, body) = vault
        .post_with_key(
            "/data/retrieve",
            retrieve_request(MERCHANT_2, "no-such-card"),
            Some(&key),
        )
        .await;
    assert_refusal(
        status,
        &body,
        403,
        NOT_ALLOWED,
        "missing card of another merchant",
    );

    let expected: Vec<(String, String, i16)> = [
        ("success", 200),
        ("failure", 403),
        ("success", 200),
        ("failure", 403),
        ("failure", 403),
    ]
    .iter()
    .map(|(outcome, code)| ("locker_retrieve".to_string(), outcome.to_string(), *code))
    .collect();
    assert!(
        audit_of(&db, "locker_retrieve") == expected,
        "the audit rows of the reads differ from the expected outcomes"
    );
    assert!(audit_holds_no_card(&db), "card number in an audit row");
}

#[tokio::test]
async fn caller_without_a_valid_key_is_refused() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let (_key, key_hash) = caller_key();
    let (unknown_key, _) = caller_key();
    let vault = start_with_caller(&db, &keys, &key_hash, MERCHANT).await;
    unlock(&vault, &keys).await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "own-card").await;

    let (status, body) = vault
        .post_with_key(
            "/data/retrieve",
            retrieve_request(MERCHANT, "own-card"),
            None,
        )
        .await;
    assert_refusal(status, &body, 401, KEY_REFUSED, "no key");

    let (status, body) = vault
        .post_with_key(
            "/data/retrieve",
            retrieve_request(MERCHANT, "own-card"),
            Some(&unknown_key),
        )
        .await;
    assert_refusal(status, &body, 401, KEY_REFUSED, "unknown key");

    let (status, body) = vault
        .post_with_key(
            "/data/retrieve",
            retrieve_request("no-such-merchant", "no-such-card"),
            None,
        )
        .await;
    assert_refusal(status, &body, 401, KEY_REFUSED, "no key, unknown merchant");

    let refused = (
        "locker_retrieve".to_string(),
        "failure".to_string(),
        401_i16,
    );
    assert!(
        audit_of(&db, "locker_retrieve") == vec![refused.clone(), refused.clone(), refused],
        "the audit rows of the refused reads differ from three 401 failures"
    );
    assert!(audit_holds_no_card(&db), "card number in an audit row");
}

#[tokio::test]
async fn caller_reads_only_its_entities_through_v2() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let (key, key_hash) = caller_key();
    let vault = start_with_caller(&db, &keys, &key_hash, MERCHANT).await;
    unlock(&vault, &keys).await;

    for (entity, number) in [(MERCHANT, CARD_NUMBER), (MERCHANT_2, CARD_2)] {
        let (status, _) = vault
            .post(
                "/api/v2/vault/add",
                serde_json::json!({
                    "entity_id": entity,
                    "vault_id": "v2-card",
                    "data": { "card_number": number },
                    "ttl": null
                }),
            )
            .await;
        assert_eq!(status, 200, "v2 add for {entity}");
    }

    let request = |entity: &str| serde_json::json!({ "entity_id": entity, "vault_id": "v2-card" });
    let (status, body) = vault
        .post_with_key("/api/v2/vault/retrieve", request(MERCHANT), Some(&key))
        .await;
    assert_eq!(status, 200, "the caller reads its own entity's data");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("v2 retrieve JSON");
    assert!(
        parsed["data"]["card_number"].as_str() == Some(CARD_NUMBER),
        "v2 read does not return the stored data"
    );

    let (status, body) = vault
        .post_with_key("/api/v2/vault/retrieve", request(MERCHANT_2), Some(&key))
        .await;
    assert_refusal(status, &body, 403, NOT_ALLOWED, "v2 other entity");

    let expected = vec![
        ("vault_retrieve".to_string(), "success".to_string(), 200_i16),
        ("vault_retrieve".to_string(), "failure".to_string(), 403_i16),
    ];
    assert!(
        audit_of(&db, "vault_retrieve") == expected,
        "the audit rows of the v2 reads differ from the expected outcomes"
    );
    assert!(audit_holds_no_card(&db), "card number in an audit row");
}

// Per-caller write control (T37), see
// `docs/superpowers/specs/2026-11-24-per-caller-write-control-design.md`. Same rules as above: keys
// generated here and never printed, no response body in an assertion message.

/// One caller declared by a test: its name, the SHA-256 of its key, its merchants and, if given,
/// its rights (absent: the default, `read`).
type CallerSpec<'a> = (&'a str, &'a str, &'a str, Option<&'a str>);

/// Starts the vault with `callers` (beside the harness caller) and unlocks it.
async fn start_with_callers(db: &TestDb, keys: &Keys, callers: &[CallerSpec<'_>]) -> Vault {
    let mut names = Vec::new();
    for (name, key_hash, merchants, rights) in callers {
        let prefix = format!(
            "LOCKER__TENANT_SECRETS__PUBLIC__CALLERS__{}__",
            name.to_uppercase()
        );
        names.push((format!("{prefix}KEY_HASH"), key_hash.to_string()));
        names.push((format!("{prefix}MERCHANTS"), merchants.to_string()));
        if let Some(rights) = rights {
            names.push((format!("{prefix}RIGHTS"), rights.to_string()));
        }
    }
    let env: Vec<(&str, &str)> = names
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let vault = Vault::start_with_env(db, &keys.master_key, &env).await;
    unlock(&vault, keys).await;
    vault
}

/// Rows of `locker`, `hash_table`, `vault` and `merchant`, each with an MD5 of its whole content,
/// so that a refusal that changes a row without adding or removing one is seen too.
fn row_counts(db: &TestDb) -> [(i64, String); 4] {
    ["locker", "hash_table", "vault", "merchant"].map(|table| {
        let digest = diesel::sql_query(format!(
            "SELECT md5(coalesce(string_agg(t::text, '|' ORDER BY t::text), '')) AS text FROM {table} t"
        ))
        .get_result::<TextRow>(&mut db.connection())
        .expect("table digest")
        .text;
        (db.count(table), digest)
    })
}

/// Number of audit rows of `operation` with a failure and `code`.
fn refusals_in_audit(db: &TestDb, operation: &str, code: i16) -> usize {
    audit_of(db, operation)
        .iter()
        .filter(|(_, outcome, status)| outcome == "failure" && *status == code)
        .count()
}

fn add_body(merchant: &str, number: &str, reference: &str) -> serde_json::Value {
    serde_json::json!({
        "merchant_id": merchant,
        "merchant_customer_id": CUSTOMER,
        "requestor_card_reference": reference,
        "card": { "card_number": number }
    })
}

fn delete_body(merchant: &str, reference: &str) -> serde_json::Value {
    serde_json::json!({
        "merchant_id": merchant,
        "merchant_customer_id": CUSTOMER,
        "card_reference": reference
    })
}

fn v2_add_body(entity: &str, vault_id: &str, number: &str) -> serde_json::Value {
    serde_json::json!({
        "entity_id": entity,
        "vault_id": vault_id,
        "data": { "card_number": number },
        "ttl": null
    })
}

fn v2_ref_body(entity: &str, vault_id: &str) -> serde_json::Value {
    serde_json::json!({ "entity_id": entity, "vault_id": vault_id })
}

/// Sends a request that must be refused with `status` and `message`, and checks that no row of
/// `locker`, `hash_table`, `vault` or `merchant` was written or deleted.
async fn assert_refused_without_change(
    vault: &Vault,
    db: &TestDb,
    path: &str,
    body: serde_json::Value,
    key: Option<&str>,
    expected: (u16, &str),
    what: &str,
) {
    let before = row_counts(db);
    let (status, response) = vault.post_with_key(path, body, key).await;
    assert_refusal(status, &response, expected.0, expected.1, what);
    assert_eq!(row_counts(db), before, "{what}: row counts changed");
}

fn last_audit(db: &TestDb, operation: &str) -> Option<(String, String, i16)> {
    audit_of(db, operation).pop()
}

fn audit(operation: &str, outcome: &str, code: i16) -> Option<(String, String, i16)> {
    Some((operation.to_string(), outcome.to_string(), code))
}

#[tokio::test]
async fn caller_adds_only_for_its_merchants() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let (writer, writer_hash) = caller_key();
    let (_other, other_hash) = caller_key();
    let vault = start_with_callers(
        &db,
        &keys,
        &[
            ("writer", &writer_hash, MERCHANT, Some("add")),
            ("other", &other_hash, MERCHANT_2, Some("read,add,delete")),
        ],
    )
    .await;

    let (status, _) = vault
        .post_with_key(
            "/data/add",
            add_body(MERCHANT, CARD_NUMBER, "own"),
            Some(&writer),
        )
        .await;
    assert_eq!(status, 200, "the caller adds for its own merchant");

    for path in ["/data/add", "/cards/add"] {
        let logged = refusals_in_audit(&db, "locker_add", 403);
        assert_refused_without_change(
            &vault,
            &db,
            path,
            add_body(MERCHANT_2, CARD_2, "intruder"),
            Some(&writer),
            (403, NOT_ALLOWED),
            path,
        )
        .await;
        assert_eq!(
            refusals_in_audit(&db, "locker_add", 403),
            logged + 1,
            "{path}: the refused add has no 403 audit row of its own"
        );
    }

    // A merchant that never existed, with a card number that fails validation: the refusal comes
    // before validation and before the merchant row and its key would be created.
    assert_refused_without_change(
        &vault,
        &db,
        "/data/add",
        add_body("never-created-merchant", "4111111111111112", "invalid"),
        Some(&writer),
        (403, NOT_ALLOWED),
        "invalid add for an unknown merchant",
    )
    .await;
    assert!(audit_holds_no_card(&db), "card number in an audit row");
}

#[tokio::test]
async fn caller_deletes_only_its_merchants_cards() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let (writer, writer_hash) = caller_key();
    let (other, other_hash) = caller_key();
    let (owner, owner_hash) = caller_key();
    let vault = start_with_callers(
        &db,
        &keys,
        &[
            ("writer", &writer_hash, MERCHANT, Some("delete")),
            ("other", &other_hash, MERCHANT_2, Some("read,add,delete")),
            ("owner", &owner_hash, MERCHANT, Some("read,add,delete")),
        ],
    )
    .await;
    let (status, _) = vault
        .post_with_key(
            "/data/add",
            add_body(MERCHANT_2, CARD_2, "theirs"),
            Some(&other),
        )
        .await;
    assert_eq!(status, 200, "the other caller stores its card");
    let (status, _) = vault
        .post_with_key(
            "/data/add",
            add_body(MERCHANT, CARD_NUMBER, "mine"),
            Some(&owner),
        )
        .await;
    assert_eq!(
        status, 200,
        "the owner stores a card for the writer's merchant"
    );

    for path in ["/data/delete", "/cards/delete"] {
        let logged = refusals_in_audit(&db, "locker_delete", 403);
        assert_refused_without_change(
            &vault,
            &db,
            path,
            delete_body(MERCHANT_2, "theirs"),
            Some(&writer),
            (403, NOT_ALLOWED),
            path,
        )
        .await;
        assert_eq!(
            refusals_in_audit(&db, "locker_delete", 403),
            logged + 1,
            "{path}: the refused delete has no 403 audit row of its own"
        );
    }
    let (status, body) = vault
        .post_with_key(
            "/data/retrieve",
            retrieve_request(MERCHANT_2, "theirs"),
            Some(&other),
        )
        .await;
    assert_eq!(status, 200, "the other merchant's card is still there");
    assert_card_number(&body, CARD_2, "theirs");

    // A reference that does not exist, and a merchant that never existed: the same refusal.
    for (merchant, what) in [
        (MERCHANT_2, "missing card of another merchant"),
        ("never-created-merchant", "unknown merchant"),
    ] {
        assert_refused_without_change(
            &vault,
            &db,
            "/data/delete",
            delete_body(merchant, "no-such-card"),
            Some(&writer),
            (403, NOT_ALLOWED),
            what,
        )
        .await;
    }

    let (status, _) = vault
        .post_with_key("/data/delete", delete_body(MERCHANT, "mine"), Some(&writer))
        .await;
    assert_eq!(status, 200, "the caller deletes its own merchant's card");
    let (status, _) = vault
        .post_with_key(
            "/data/retrieve",
            retrieve_request(MERCHANT, "mine"),
            Some(&owner),
        )
        .await;
    assert_eq!(status, 404, "the deleted card is gone");
}

#[tokio::test]
async fn caller_without_a_valid_key_cannot_add_or_delete() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let (_writer, writer_hash) = caller_key();
    let (unknown, _) = caller_key();
    let vault = start_with_callers(
        &db,
        &keys,
        &[("writer", &writer_hash, MERCHANT, Some("read,add,delete"))],
    )
    .await;
    store_card_with_ref(&vault, MERCHANT, CUSTOMER, card_data(), "own-card").await;

    for (key, what) in [(None, "no key"), (Some(unknown.as_str()), "unknown key")] {
        assert_refused_without_change(
            &vault,
            &db,
            "/data/add",
            add_body(MERCHANT, CARD_2, "new"),
            key,
            (401, KEY_REFUSED),
            &format!("add, {what}"),
        )
        .await;
        assert_refused_without_change(
            &vault,
            &db,
            "/data/delete",
            delete_body(MERCHANT, "own-card"),
            key,
            (401, KEY_REFUSED),
            &format!("delete, {what}"),
        )
        .await;
    }
    let refused = |op: &str| (op.to_string(), "failure".to_string(), 401_i16);
    assert!(
        audit_of(&db, "locker_delete") == vec![refused("locker_delete"), refused("locker_delete")],
        "the audit rows of the refused deletes differ from two 401 failures"
    );
    assert!(
        audit_of(&db, "locker_add").ends_with(&[refused("locker_add"), refused("locker_add")]),
        "the audit rows of the refused adds differ from two 401 failures"
    );
    assert!(audit_holds_no_card(&db), "card number in an audit row");
}

#[tokio::test]
async fn caller_adds_and_deletes_only_its_entities_through_v2() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let (writer, writer_hash) = caller_key();
    let (other, other_hash) = caller_key();
    let vault = start_with_callers(
        &db,
        &keys,
        &[
            ("writer", &writer_hash, MERCHANT, Some("read,add,delete")),
            ("other", &other_hash, MERCHANT_2, Some("read,add,delete")),
        ],
    )
    .await;
    let (status, _) = vault
        .post_with_key(
            "/api/v2/vault/add",
            v2_add_body(MERCHANT, "mine", CARD_NUMBER),
            Some(&writer),
        )
        .await;
    assert_eq!(status, 200, "v2 add for the caller's own entity");
    let (status, _) = vault
        .post_with_key(
            "/api/v2/vault/add",
            v2_add_body(MERCHANT_2, "theirs", CARD_2),
            Some(&other),
        )
        .await;
    assert_eq!(status, 200, "v2 add by the other caller");

    assert_refused_without_change(
        &vault,
        &db,
        "/api/v2/vault/add",
        v2_add_body(MERCHANT_2, "intruder", CARD_NUMBER),
        Some(&writer),
        (403, NOT_ALLOWED),
        "v2 add for another entity",
    )
    .await;
    assert!(
        last_audit(&db, "vault_add") == audit("vault_add", "failure", 403),
        "the refused v2 add has no 403 audit row"
    );
    // Overwriting the other entity's existing entry is an add too.
    assert_refused_without_change(
        &vault,
        &db,
        "/api/v2/vault/add?mode=upsert",
        v2_add_body(MERCHANT_2, "theirs", CARD_NUMBER),
        Some(&writer),
        (403, NOT_ALLOWED),
        "v2 upsert over another entity's entry",
    )
    .await;
    // An entity that never existed, with an expired ttl that fails validation.
    let mut invalid = v2_add_body("never-created-merchant", "invalid", CARD_NUMBER);
    invalid["ttl"] = serde_json::json!(0);
    assert_refused_without_change(
        &vault,
        &db,
        "/api/v2/vault/add",
        invalid,
        Some(&writer),
        (403, NOT_ALLOWED),
        "invalid v2 add for an unknown entity",
    )
    .await;

    for (entity, vault_id, what) in [
        (MERCHANT_2, "theirs", "v2 delete of another entity's entry"),
        (MERCHANT_2, "no-such-entry", "v2 delete of a missing entry"),
        (
            "never-created-merchant",
            "no-such-entry",
            "v2 delete for an unknown entity",
        ),
    ] {
        assert_refused_without_change(
            &vault,
            &db,
            "/api/v2/vault/delete",
            v2_ref_body(entity, vault_id),
            Some(&writer),
            (403, NOT_ALLOWED),
            what,
        )
        .await;
    }
    assert!(
        last_audit(&db, "vault_delete") == audit("vault_delete", "failure", 403),
        "the refused v2 delete has no 403 audit row"
    );

    let (status, body) = vault
        .post_with_key(
            "/api/v2/vault/retrieve",
            v2_ref_body(MERCHANT_2, "theirs"),
            Some(&other),
        )
        .await;
    assert_eq!(status, 200, "the other entity's entry is still there");
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    assert!(
        parsed["data"]["card_number"].as_str() == Some(CARD_2),
        "the other entity's entry was overwritten"
    );

    let (status, _) = vault
        .post_with_key(
            "/api/v2/vault/delete",
            v2_ref_body(MERCHANT, "mine"),
            Some(&writer),
        )
        .await;
    assert_eq!(status, 200, "v2 delete of the caller's own entry");
    assert!(audit_holds_no_card(&db), "card number in an audit row");
}

#[tokio::test]
async fn caller_without_a_valid_key_cannot_add_or_delete_through_v2() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let (writer, writer_hash) = caller_key();
    let (unknown, _) = caller_key();
    let vault = start_with_callers(
        &db,
        &keys,
        &[("writer", &writer_hash, MERCHANT, Some("read,add,delete"))],
    )
    .await;
    let (status, _) = vault
        .post_with_key(
            "/api/v2/vault/add",
            v2_add_body(MERCHANT, "mine", CARD_NUMBER),
            Some(&writer),
        )
        .await;
    assert_eq!(status, 200, "v2 add with the caller's key");

    for (key, what) in [(None, "no key"), (Some(unknown.as_str()), "unknown key")] {
        assert_refused_without_change(
            &vault,
            &db,
            "/api/v2/vault/add",
            v2_add_body(MERCHANT, "new", CARD_2),
            key,
            (401, KEY_REFUSED),
            &format!("v2 add, {what}"),
        )
        .await;
        assert_refused_without_change(
            &vault,
            &db,
            "/api/v2/vault/delete",
            v2_ref_body(MERCHANT, "mine"),
            key,
            (401, KEY_REFUSED),
            &format!("v2 delete, {what}"),
        )
        .await;
    }
    let refused = |op: &str| (op.to_string(), "failure".to_string(), 401_i16);
    assert!(
        audit_of(&db, "vault_delete") == vec![refused("vault_delete"), refused("vault_delete")],
        "the audit rows of the refused v2 deletes differ from two 401 failures"
    );
    assert!(
        audit_of(&db, "vault_add").ends_with(&[refused("vault_add"), refused("vault_add")]),
        "the audit rows of the refused v2 adds differ from two 401 failures"
    );
}

#[tokio::test]
async fn caller_needs_the_right_for_each_operation() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let (reader, reader_hash) = caller_key();
    let (adder, adder_hash) = caller_key();
    let (deleter, deleter_hash) = caller_key();
    let vault = start_with_callers(
        &db,
        &keys,
        &[
            ("reader", &reader_hash, MERCHANT, None),
            ("adder", &adder_hash, MERCHANT, Some("add")),
            ("deleter", &deleter_hash, MERCHANT, Some("delete")),
        ],
    )
    .await;
    let refused = (403, NOT_ALLOWED);

    // v1: the adder stores, the reader reads, the deleter deletes; every other pair is refused.
    assert_refused_without_change(
        &vault,
        &db,
        "/data/add",
        add_body(MERCHANT, CARD_NUMBER, "c1"),
        Some(&reader),
        refused,
        "reader adds",
    )
    .await;
    assert!(
        last_audit(&db, "locker_add") == audit("locker_add", "failure", 403),
        "the refused add of the reader has no 403 audit row"
    );
    assert_refused_without_change(
        &vault,
        &db,
        "/data/add",
        add_body(MERCHANT, CARD_NUMBER, "c1"),
        Some(&deleter),
        refused,
        "deleter adds",
    )
    .await;
    let (status, _) = vault
        .post_with_key(
            "/data/add",
            add_body(MERCHANT, CARD_NUMBER, "c1"),
            Some(&adder),
        )
        .await;
    assert_eq!(status, 200, "adder adds");
    let (status, _) = vault
        .post_with_key(
            "/data/retrieve",
            retrieve_request(MERCHANT, "c1"),
            Some(&reader),
        )
        .await;
    assert_eq!(status, 200, "reader reads");
    for (key, what) in [(&adder, "adder reads"), (&deleter, "deleter reads")] {
        let (status, body) = vault
            .post_with_key(
                "/data/retrieve",
                retrieve_request(MERCHANT, "c1"),
                Some(key),
            )
            .await;
        assert_refusal(status, &body, 403, NOT_ALLOWED, what);
    }
    for (key, what) in [(&reader, "reader deletes"), (&adder, "adder deletes")] {
        assert_refused_without_change(
            &vault,
            &db,
            "/data/delete",
            delete_body(MERCHANT, "c1"),
            Some(key),
            refused,
            what,
        )
        .await;
    }
    let (status, _) = vault
        .post_with_key("/data/delete", delete_body(MERCHANT, "c1"), Some(&deleter))
        .await;
    assert_eq!(status, 200, "deleter deletes");

    // v2: the same rights.
    for (key, what) in [
        (&reader, "reader adds through v2"),
        (&deleter, "deleter adds through v2"),
    ] {
        assert_refused_without_change(
            &vault,
            &db,
            "/api/v2/vault/add",
            v2_add_body(MERCHANT, "e1", CARD_NUMBER),
            Some(key),
            refused,
            what,
        )
        .await;
    }
    let (status, _) = vault
        .post_with_key(
            "/api/v2/vault/add",
            v2_add_body(MERCHANT, "e1", CARD_NUMBER),
            Some(&adder),
        )
        .await;
    assert_eq!(status, 200, "adder adds through v2");
    let (status, _) = vault
        .post_with_key(
            "/api/v2/vault/retrieve",
            v2_ref_body(MERCHANT, "e1"),
            Some(&reader),
        )
        .await;
    assert_eq!(status, 200, "reader reads through v2");
    for (key, what) in [
        (&adder, "adder reads through v2"),
        (&deleter, "deleter reads through v2"),
    ] {
        let (status, body) = vault
            .post_with_key(
                "/api/v2/vault/retrieve",
                v2_ref_body(MERCHANT, "e1"),
                Some(key),
            )
            .await;
        assert_refusal(status, &body, 403, NOT_ALLOWED, what);
    }
    for (key, what) in [
        (&reader, "reader deletes through v2"),
        (&adder, "adder deletes through v2"),
    ] {
        assert_refused_without_change(
            &vault,
            &db,
            "/api/v2/vault/delete",
            v2_ref_body(MERCHANT, "e1"),
            Some(key),
            refused,
            what,
        )
        .await;
    }
    let (status, _) = vault
        .post_with_key(
            "/api/v2/vault/delete",
            v2_ref_body(MERCHANT, "e1"),
            Some(&deleter),
        )
        .await;
    assert_eq!(status, 200, "deleter deletes through v2");
}

#[tokio::test]
async fn tenant_without_callers_refuses_every_data_call() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let (key, _) = caller_key();
    let vault = Vault::start_without_callers(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;

    let calls = [
        ("/data/add", add_body(MERCHANT, CARD_NUMBER, "c1")),
        ("/data/retrieve", retrieve_request(MERCHANT, "c1")),
        ("/data/delete", delete_body(MERCHANT, "c1")),
        (
            "/api/v2/vault/add",
            v2_add_body(MERCHANT, "e1", CARD_NUMBER),
        ),
        ("/api/v2/vault/retrieve", v2_ref_body(MERCHANT, "e1")),
        ("/api/v2/vault/delete", v2_ref_body(MERCHANT, "e1")),
    ];
    for (path, body) in calls {
        for (with_key, what) in [(None, "no key"), (Some(key.as_str()), "a key")] {
            assert_refused_without_change(
                &vault,
                &db,
                path,
                body.clone(),
                with_key,
                (401, KEY_REFUSED),
                &format!("{path}, {what}"),
            )
            .await;
        }
    }
    assert!(
        last_audit(&db, "locker_add") == audit("locker_add", "failure", 401),
        "the refused add has no 401 audit row"
    );
    assert!(
        last_audit(&db, "vault_delete") == audit("vault_delete", "failure", 401),
        "the refused v2 delete has no 401 audit row"
    );
}

// Controls that were in the code without a test (task T3: T12, T14, T15, T16, T17), see
// `docs/superpowers/specs/2026-11-25-untested-controls-design.md`.

impl Vault {
    /// Posts `body` with the harness caller's key and `tenant` as `x-tenant-id` (no header when
    /// `None`).
    async fn post_as_tenant(
        &self,
        path: &str,
        body: serde_json::Value,
        tenant: Option<&str>,
    ) -> (u16, String) {
        let mut request = self.client.post(format!("{}{path}", self.base)).json(&body);
        if let Some(tenant) = tenant {
            request = request.header("x-tenant-id", tenant);
        }
        if let Some(key) = &self.caller_key {
            request = request.header("x-vault-caller-key", key);
        }
        let response = request.send().await.expect("send request");
        let status = response.status().as_u16();
        (status, response.text().await.expect("response body"))
    }
}

/// Row counts of every table a data route writes: locker, hash, merchant, fingerprint, vault and
/// entity.
fn data_row_counts(db: &TestDb) -> [i64; 6] {
    ["locker", "hash_table", "merchant", "fingerprint", "vault", "entity"].map(|table| db.count(table))
}

/// One request for each data route: v1 under `/data` and `/cards`, v2, and `/entity`.
fn every_data_request(reference: &str) -> Vec<(String, serde_json::Value)> {
    let add = serde_json::json!({
        "merchant_id": MERCHANT,
        "merchant_customer_id": CUSTOMER,
        "card": { "card_number": CARD_NUMBER }
    });
    let fingerprint = serde_json::json!({ "data": CARD_NUMBER, "key": "fingerprint-test-key" });
    let v2_ref = serde_json::json!({ "entity_id": MERCHANT, "vault_id": reference });
    let mut requests = Vec::new();
    for prefix in ["/data", "/cards"] {
        requests.push((format!("{prefix}/add"), add.clone()));
        requests.push((format!("{prefix}/retrieve"), card_request(reference)));
        requests.push((format!("{prefix}/delete"), card_request(reference)));
        requests.push((format!("{prefix}/fingerprint"), fingerprint.clone()));
    }
    requests.push((
        "/api/v2/vault/add".to_string(),
        serde_json::json!({
            "entity_id": MERCHANT,
            "vault_id": reference,
            "data": { "card_number": CARD_NUMBER },
            "ttl": null
        }),
    ));
    requests.push(("/api/v2/vault/retrieve".to_string(), v2_ref.clone()));
    requests.push(("/api/v2/vault/delete".to_string(), v2_ref));
    requests.push(("/api/v2/vault/fingerprint".to_string(), fingerprint));
    requests.push(("/entity".to_string(), serde_json::json!({ "entity_id": MERCHANT })));
    requests
}

/// T15: a tenant id that is not configured, or no tenant id, is refused on every data route
/// before any row is read or written, with the tenant error and not the lock error.
#[tokio::test]
async fn unknown_tenant_is_refused_on_every_data_route() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    let reference = store_card(&vault).await;
    let before = data_row_counts(&db);

    let unknown = r#"{"code":"TE_03","message":"Tenant error: Invalid x-tenant-id","data":null}"#;
    let missing =
        r#"{"code":"TE_03","message":"Tenant error: x-tenant-id not found in headers","data":null}"#;
    for tenant in [Some("no-such-tenant"), Some("PUBLIC"), Some(""), None] {
        for (path, body) in every_data_request(&reference) {
            let (status, response) = vault.post_as_tenant(&path, body, tenant).await;
            let expected = if tenant.is_some() { unknown } else { missing };
            assert_eq!(
                (status, response.as_str()),
                (400, expected),
                "{path} with tenant {tenant:?}"
            );
        }
    }
    #[cfg(feature = "key_custodian")]
    {
        let (status, response) = vault
            .post_as_tenant(
                "/custodian/key1",
                serde_json::json!({ "key": keys.key1 }),
                Some("no-such-tenant"),
            )
            .await;
        assert_eq!((status, response.as_str()), (400, unknown), "custodian key");
    }

    assert_eq!(data_row_counts(&db), before, "no row written");
    // The configured tenant still reads its card.
    let (status, body) = vault.post("/data/retrieve", card_request(&reference)).await;
    assert_eq!(status, 200, "known tenant");
    assert_card_number(&body, CARD_NUMBER, &reference);
}

/// T14: before both custodians have unlocked the tenant, every data route answers the lock error
/// and writes no row; with one key only it is still locked; once unlocked, the same add succeeds.
#[cfg(feature = "key_custodian")]
#[tokio::test]
async fn data_routes_are_refused_before_unlock() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;

    let locked = r#"{"code":"TE_00","message":"Custodian is locked","data":null}"#;
    let assert_locked = |step: &'static str| {
        let vault = &vault;
        async move {
            for (path, body) in every_data_request("a-reference") {
                let (status, response) = vault.post(&path, body).await;
                assert_eq!((status, response.as_str()), (401, locked), "{path} {step}");
            }
        }
    };
    assert_locked("before any key").await;
    assert_eq!(send_key(&vault, "key1", &keys.key1).await, 200, "key1");
    assert_locked("with key 1 only").await;
    assert_eq!(send_key(&vault, "key2", &keys.key2).await, 200, "key2");
    assert_locked("with both keys, before decrypt").await;
    assert_eq!(data_row_counts(&db), [0; 6], "no row written while locked");

    let (status, _) = vault.post("/custodian/decrypt", serde_json::json!({})).await;
    assert_eq!(status, 200, "decrypt");
    let reference = store_card(&vault).await;
    let (status, body) = vault.post("/data/retrieve", card_request(&reference)).await;
    assert_eq!(status, 200, "retrieve once unlocked");
    assert_card_number(&body, CARD_NUMBER, &reference);
}

/// T17: a card reference the vault generates is an RFC 9562 UUID version 7 (version and variant
/// bits, a timestamp of now), unique, and holds no card number; a reference the
/// caller supplies is kept as is.
#[tokio::test]
async fn generated_card_reference_is_a_uuid_v7() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;

    let now_ms = || {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after 1970")
                .as_millis(),
        )
        .expect("milliseconds fit in u64")
    };
    let start = now_ms();
    let mut references = Vec::new();
    for (customer, number) in [(CUSTOMER, CARD_NUMBER), (CUSTOMER_2, CARD_2), (CUSTOMER, CARD_2)] {
        let response = store_card_as(&vault, MERCHANT, customer, number).await;
        references.push(
            response["payload"]["card_reference"]
                .as_str()
                .expect("card_reference")
                .to_string(),
        );
    }
    let end = now_ms();

    for reference in &references {
        assert_eq!(reference.len(), 36, "hyphenated form: {reference}");
        let uuid = uuid::Uuid::parse_str(reference).expect("a UUID");
        let bytes = uuid.as_bytes();
        assert_eq!(bytes[6] >> 4, 0b0111, "version 7: {reference}");
        assert_eq!(bytes[8] >> 6, 0b10, "RFC 9562 variant: {reference}");
        let mut ms = [0u8; 8];
        ms[2..].copy_from_slice(&bytes[..6]);
        let ms = u64::from_be_bytes(ms);
        assert!(
            (start.saturating_sub(5_000)..=end + 5_000).contains(&ms),
            "timestamp of the add: {reference}"
        );
        let digits: String = reference.chars().filter(char::is_ascii_digit).collect();
        assert!(
            !digits.contains(CARD_NUMBER) && !digits.contains(CARD_2),
            "no card number in {reference}"
        );
    }
    let mut unique = references.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), references.len(), "each reference is new");
    let stored: Vec<String> = db.locker_rows().into_iter().map(|row| row.locker_id).collect();
    for reference in &references {
        assert!(stored.contains(reference), "stored under {reference}");
    }

    let supplied = store_card_with_ref(&vault, MERCHANT_2, CUSTOMER, card_data(), "caller-ref-1").await;
    assert_eq!(supplied["payload"]["card_reference"], "caller-ref-1", "supplied reference kept");
}

/// T12: the fingerprint is keyed by the key the caller sends. The same card under two keys gets
/// two fingerprints and two rows; the same card under the same key gets the same one, also in a
/// batch. Nothing here computes or compares a hash: only the fingerprint ids are compared.
#[tokio::test]
async fn fingerprint_differs_for_two_caller_keys() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin);
    let keys = Keys::generate();
    let vault = Vault::start(&db, &keys.master_key).await;
    unlock(&vault, &keys).await;
    let key_a = hex::encode(random_bytes(32));
    let key_b = hex::encode(random_bytes(32));

    let fingerprint = |key: String, data: &'static str| {
        let vault = &vault;
        async move {
            let (status, body) = vault
                .post("/data/fingerprint", serde_json::json!({ "data": data, "key": key }))
                .await;
            assert_eq!(status, 200, "fingerprint");
            assert!(!body.contains(data), "no card number in the response");
            let body: serde_json::Value = serde_json::from_str(&body).expect("fingerprint JSON");
            body["fingerprint_id"].as_str().expect("fingerprint_id").to_string()
        }
    };
    let a = fingerprint(key_a.clone(), CARD_NUMBER).await;
    let b = fingerprint(key_b.clone(), CARD_NUMBER).await;
    assert_ne!(a, b, "two keys, two fingerprints");
    assert_eq!(fingerprint(key_a.clone(), CARD_NUMBER).await, a, "same key, same fingerprint");
    assert_eq!(fingerprint(key_b.clone(), CARD_NUMBER).await, b, "same key, same fingerprint");
    assert_ne!(fingerprint(key_a.clone(), CARD_2).await, a, "another card, another fingerprint");
    assert_eq!(db.count("fingerprint"), 3, "one row per key and card");

    let (status, body) = vault
        .post(
            "/data/fingerprint",
            serde_json::json!({ "batch_data": [
                { "label": "a", "data": CARD_NUMBER, "key": key_a },
                { "label": "b", "data": CARD_NUMBER, "key": key_b },
            ] }),
        )
        .await;
    assert_eq!(status, 200, "batch fingerprint");
    let body: serde_json::Value = serde_json::from_str(&body).expect("batch JSON");
    assert_eq!(body["fingerprints"]["a"], a.as_str(), "batch, key a");
    assert_eq!(body["fingerprints"]["b"], b.as_str(), "batch, key b");
    assert_eq!(db.count("fingerprint"), 3, "no new row");
}
