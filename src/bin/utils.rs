//!
//! # Utils
//!
//! Simple Cli tool for generating keys to be used in the locker before deployment
//!

use std::io::{Read, Write, stdin, stdout};

#[cfg(feature = "key_custodian")]
use hyperswitch_card_vault::routes;
use hyperswitch_card_vault::{
    api_client, app, config,
    crypto::encryption_manager::{
        encryption_interface::Encryption,
        managers::{
            aes::{GcmAes256, generate_aes256_key},
            jw::JWEncryption,
        },
    },
    domain, error, runtime_config, storage,
};
use hyperswitch_masking::Secret;
use josekit::jwe;

#[derive(argh::FromArgs, Debug)]
/// Utilities to generate associated properties used by locker
struct Cli {
    #[argh(subcommand)]
    nested: SubCommand,
}

#[derive(argh::FromArgs, Debug)]
#[argh(subcommand)]
#[non_exhaustive]
enum SubCommand {
    MasterKey(MasterKey),
    JweEncrypt(JweE),
    JweDecrypt(JweD),
    Rehash(Rehash),
    RotateMasterKey(RotateMasterKey),
}

#[derive(argh::FromArgs, Debug)]
#[argh(subcommand, name = "master-key")]
/// Generate the master key and optionally the associated key custodian keys
struct MasterKey {
    /// generate master key for key custodian feature disabled
    #[argh(switch, short = 'w')]
    without_custodian: bool,
}

#[derive(argh::FromArgs, Debug)]
#[argh(subcommand, name = "rehash")]
/// Recompute every duplicate-check hash of a tenant under the current master key. Stop the vault
/// first. With the key custodian feature, the two custodian keys are read from standard input,
/// one per line. Prints counts only. Exit code: 0 done, 2 stopped by --max-rows, 1 error.
struct Rehash {
    /// tenant id, as in the configuration
    #[argh(option)]
    tenant: String,
    /// rows read per database query (default 100)
    #[argh(option, default = "100")]
    batch_size: i64,
    /// stop after this many rows (exit code 2); run again without it to finish
    #[argh(option)]
    max_rows: Option<u64>,
}

#[derive(argh::FromArgs, Debug)]
#[argh(subcommand, name = "rotate-master-key")]
/// Re-encrypt every merchant key of a tenant under a new master key, then recompute every
/// duplicate-check hash under it. Stop the vault first. Keys are read from standard input, one per
/// line: with the key custodian feature, the former key 1 and key 2, the new encrypted master key,
/// then the new key 1 and key 2; without it, the new master key. Prints counts only. Exit code: 0
/// done, 2 stopped by --max-rows, 1 error.
struct RotateMasterKey {
    /// tenant id, as in the configuration
    #[argh(option)]
    tenant: String,
    /// rows read per database query (default 100)
    #[argh(option, default = "100")]
    batch_size: i64,
    /// stop once this many merchant rows are rewritten (exit code 2); run again to go on
    #[argh(option)]
    max_rows: Option<u64>,
}

#[derive(argh::FromArgs, Debug)]
#[argh(subcommand, name = "jwe-encrypt")]
/// Perform JWE operation
struct JweE {
    /// private key to be used to perform jwe operation
    #[argh(option, long = "priv")]
    private_key: Option<String>,
    /// public key to be used to perform jwe operation
    #[argh(option, long = "pub")]
    public_key: Option<String>,
}

#[derive(argh::FromArgs, Debug)]
#[argh(subcommand, name = "jwe-decrypt")]
/// Perform JWE operation
struct JweD {
    /// private key to be used to perform jwe operation
    #[argh(option, long = "priv")]
    private_key: Option<String>,
    /// public key to be used to perform jwe operation
    #[argh(option, long = "pub")]
    public_key: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Cli = argh::from_env();

    match args.nested {
        SubCommand::MasterKey(master_key_conf) => master_key_generator(master_key_conf)?,
        SubCommand::Rehash(rehash) => std::process::exit(rehash_command(&rehash)),
        SubCommand::RotateMasterKey(rotation) => std::process::exit(rotation_command(&rotation)),
        SubCommand::JweEncrypt(JweE {
            private_key,
            public_key,
        }) => {
            let priv_key = read_file_to_string(
                &private_key.ok_or(error::CryptoError::InvalidData("private key not found"))?,
            )?;
            let pub_key = read_file_to_string(
                &public_key.ok_or(error::CryptoError::InvalidData("public key not found"))?,
            )?;
            jwe_operation(|payload| {
                JWEncryption::new(priv_key, pub_key, jwe::RSA_OAEP_256, jwe::RSA_OAEP)?
                    .encrypt(payload)
                    .and_then(|payload| {
                        Ok(serde_json::to_vec(&payload)
                            .map_err(error::CryptoError::SerdeJsonError)?)
                    })
            })?;
        }
        SubCommand::JweDecrypt(JweD {
            private_key,
            public_key,
        }) => {
            let priv_key = read_file_to_string(
                &private_key.ok_or(error::CryptoError::InvalidData("private key not found"))?,
            )?;
            let pub_key = read_file_to_string(
                &public_key.ok_or(error::CryptoError::InvalidData("private key not found"))?,
            )?;
            jwe_operation(|payload| {
                serde_json::from_slice(&payload)
                    .map_err(error::CryptoError::SerdeJsonError)
                    .map_err(Into::into)
                    .and_then(|payload| {
                        JWEncryption::new(priv_key, pub_key, jwe::RSA_OAEP_256, jwe::RSA_OAEP)?
                            .decrypt(payload)
                    })
                // (x)
            })?;
        }
    }

    Ok(())
}

fn master_key_generator(master_key_conf: MasterKey) -> Result<(), Box<dyn std::error::Error>> {
    let master_key = generate_aes256_key();
    if master_key_conf.without_custodian {
        println!("master key: {}", hex::encode(master_key));
        Ok(())
    } else {
        let encryption_key = generate_aes256_key();
        let key_custodian_key = hex::encode(encryption_key);
        let algo = GcmAes256::new(encryption_key.to_vec());
        let encrypted_master_key = algo.encrypt(master_key.to_vec())?;
        let hexed_master_key = hex::encode(encrypted_master_key);
        println!("master key: {}", hexed_master_key);
        let (key1, key2) = key_custodian_key.split_at(key_custodian_key.len() / 2);
        println!("key 1: {}", key1);
        println!("key 2: {}", key2);

        Ok(())
    }
}

fn read_file_to_string(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = std::fs::File::open(name)?;
    let mut output = String::new();
    file.read_to_string(&mut output)?;
    Ok(output)
}

fn jwe_operation(
    op: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, error::ContainerError<error::CryptoError>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    stdin().read_to_string(&mut input)?;

    // let output = op(input.as_bytes().to_vec())?;
    let output = op(input.trim().as_bytes().to_vec())?;

    stdout().write_all(&output)?;

    Ok(())
}

/// Runs the re-hash job and prints its counts. Returns the exit code. Never prints card data, a
/// hash or a key: errors are reduced to their kind.
fn rehash_command(args: &Rehash) -> i32 {
    let result = tokio::runtime::Runtime::new()
        .map_err(|_| "runtime".to_string())
        .and_then(|runtime| runtime.block_on(run_rehash(args)));
    match result {
        Ok(report) => {
            println!("examined: {}", report.examined);
            println!("current: {}", report.current);
            println!("moved: {}", report.moved);
            println!("duplicates: {}", report.duplicates);
            println!("removed hash rows: {}", report.removed_hash_rows);
            println!("complete: {}", if report.complete { "yes" } else { "no" });
            if report.complete { 0 } else { 2 }
        }
        Err(kind) => {
            eprintln!("rehash failed: {kind}");
            1
        }
    }
}

/// Variant name of an API error, without its message, as the audit log keeps it.
fn error_kind(error: &error::ContainerError<error::ApiError>) -> String {
    let variant = format!("{:?}", error.get_inner());
    variant.split('(').next().unwrap_or_default().to_string()
}

async fn run_rehash(args: &Rehash) -> Result<domain::hash::RehashReport, String> {
    let mut global_config = config::GlobalConfig::new().map_err(|_| "configuration".to_string())?;
    global_config
        .validate()
        .map_err(|_| "configuration".to_string())?;
    global_config
        .fetch_raw_secrets()
        .await
        .map_err(|_| "secrets".to_string())?;
    if global_config.tenant_secrets.get(&args.tenant).is_none() {
        return Err("unknown tenant".to_string());
    }

    #[cfg_attr(not(feature = "key_custodian"), allow(unused_mut))]
    let mut tenant_config =
        config::TenantConfig::from_global_config(&global_config, args.tenant.clone());
    #[cfg(feature = "key_custodian")]
    {
        // Read from standard input, never from arguments, which other users can see.
        let mut lines = stdin().lines();
        let mut next_key = || lines.next().and_then(Result::ok).unwrap_or_default();
        let (key1, key2) = (next_key(), next_key());
        routes::key_custodian::aes_decrypt_custodian_key(
            &mut tenant_config,
            key1.trim(),
            key2.trim(),
        )
        .await
        .map_err(|error| error_kind(&error))?;
    }

    let api_client =
        api_client::ApiClient::new(&global_config).map_err(|_| "api client".to_string())?;
    let runtime_config_manager = std::sync::Arc::new(
        runtime_config::RuntimeConfigManager::new(
            &global_config.runtime_config,
            global_config.api_client.client_idle_timeout,
            global_config.api_client.pool_max_idle_per_host,
        )
        .map_err(|_| "runtime configuration".to_string())?,
    );
    let global_store = std::sync::Arc::new(storage::GlobalStore::new(
        #[cfg(feature = "kv")]
        global_config.kv.clone(),
    ));
    let state = app::TenantAppState::new(
        &global_config,
        tenant_config,
        api_client,
        #[cfg(feature = "redis")]
        None,
        runtime_config_manager,
        global_store,
    )
    .await
    .map_err(|_| "tenant state".to_string())?;

    domain::hash::rehash(&state, args.batch_size, args.max_rows)
        .await
        .map_err(|error| error_kind(&error))
}

/// Runs the master key rotation and prints its counts. Returns the exit code. Never prints a key, a
/// key part or a hash: errors are reduced to their kind.
fn rotation_command(args: &RotateMasterKey) -> i32 {
    let result = tokio::runtime::Runtime::new()
        .map_err(|_| "runtime".to_string())
        .and_then(|runtime| runtime.block_on(run_rotation(args)));
    match result {
        Ok(report) => {
            println!("merchant rows: {}", report.merchants);
            println!("rewritten: {}", report.rewritten);
            println!("already under the new key: {}", report.already_new);
            if let Some(hashes) = &report.hashes {
                println!("hash examined: {}", hashes.examined);
                println!("hash current: {}", hashes.current);
                println!("hash moved: {}", hashes.moved);
                println!("hash duplicates: {}", hashes.duplicates);
                println!("hash removed hash rows: {}", hashes.removed_hash_rows);
            }
            println!("complete: {}", if report.complete { "yes" } else { "no" });
            if report.complete { 0 } else { 2 }
        }
        Err(kind) => {
            eprintln!("rotation failed: {kind}");
            1
        }
    }
}

/// The former and the new master key, read as the design says: the former one from the
/// configuration (unlocked by the former custodian keys under `key_custodian`), the new one from
/// standard input.
async fn unlock_rotation_keys(
    tenant_config: &config::TenantConfig,
) -> Result<(Secret<Vec<u8>>, Secret<Vec<u8>>), error::ContainerError<error::ApiError>> {
    // Read from standard input, never from arguments, which other users can see.
    let lines: Vec<String> = stdin()
        .lines()
        .map_while(Result::ok)
        .map(|line| line.trim().to_string())
        .collect();

    #[cfg(feature = "key_custodian")]
    {
        let [former1, former2, new_encrypted, new1, new2] = lines.as_slice() else {
            return Err(error::ApiError::DecryptingKeysFailed("five lines expected").into());
        };
        let mut former = tenant_config.clone();
        routes::key_custodian::aes_decrypt_custodian_key(&mut former, former1, former2).await?;
        let mut new = tenant_config.clone();
        new.tenant_secrets.master_key = Secret::new(hex::decode(new_encrypted).map_err(|_| {
            error::ApiError::DecryptingKeysFailed("new encrypted master key is not hex")
        })?);
        routes::key_custodian::aes_decrypt_custodian_key(&mut new, new1, new2).await?;
        Ok((
            former.tenant_secrets.master_key,
            new.tenant_secrets.master_key,
        ))
    }

    #[cfg(not(feature = "key_custodian"))]
    {
        let new = lines
            .first()
            .and_then(|line| hex::decode(line).ok())
            .filter(|key| key.len() == 32)
            .ok_or(error::ApiError::ValidationError(
                "the new master key must be 32 bytes in hex",
            ))?;
        Ok((
            tenant_config.tenant_secrets.master_key.clone(),
            Secret::new(new),
        ))
    }
}

/// Tenant state built as the vault builds it, with `tenant_config` as given.
async fn rotation_state(
    global_config: &config::GlobalConfig,
    tenant_config: config::TenantConfig,
) -> Result<app::TenantAppState, String> {
    let api_client =
        api_client::ApiClient::new(global_config).map_err(|_| "api client".to_string())?;
    let runtime_config_manager = std::sync::Arc::new(
        runtime_config::RuntimeConfigManager::new(
            &global_config.runtime_config,
            global_config.api_client.client_idle_timeout,
            global_config.api_client.pool_max_idle_per_host,
        )
        .map_err(|_| "runtime configuration".to_string())?,
    );
    let global_store = std::sync::Arc::new(storage::GlobalStore::new(
        #[cfg(feature = "kv")]
        global_config.kv.clone(),
    ));
    app::TenantAppState::new(
        global_config,
        tenant_config,
        api_client,
        #[cfg(feature = "redis")]
        None,
        runtime_config_manager,
        global_store,
    )
    .await
    .map_err(|_| "tenant state".to_string())
}

async fn run_rotation(
    args: &RotateMasterKey,
) -> Result<domain::master_key::RotationReport, String> {
    let mut global_config = config::GlobalConfig::new().map_err(|_| "configuration".to_string())?;
    global_config
        .validate()
        .map_err(|_| "configuration".to_string())?;
    global_config
        .fetch_raw_secrets()
        .await
        .map_err(|_| "secrets".to_string())?;
    if global_config.tenant_secrets.get(&args.tenant).is_none() {
        return Err("unknown tenant".to_string());
    }
    let mut tenant_config =
        config::TenantConfig::from_global_config(&global_config, args.tenant.clone());

    let (former, new) = match unlock_rotation_keys(&tenant_config).await {
        Ok(keys) => keys,
        Err(refusal) => {
            // The refusal is recorded too; the state needs no key for that.
            let state = rotation_state(&global_config, tenant_config).await?;
            let error = domain::master_key::record_refused_run(&state, refusal).await;
            return Err(error_kind(&error));
        }
    };
    tenant_config.tenant_secrets.master_key = new;
    let state = rotation_state(&global_config, tenant_config).await?;
    domain::master_key::rotate(&state, &former, args.batch_size, args.max_rows)
        .await
        .map_err(|error| error_kind(&error))
}
