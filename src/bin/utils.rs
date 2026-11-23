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
    /// stop after this many rows; running the command again resumes
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
