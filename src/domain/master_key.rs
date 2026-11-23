//! Master key rotation: re-encrypts every merchant key of a tenant under a new master key, then
//! recomputes every duplicate-check hash under it. See
//! `docs/superpowers/specs/2026-11-23-master-key-rotation-design.md`.
//!
//! Nothing is stored about progress: the AES-GCM tag tells which of the two keys wraps a row, so a
//! run stopped anywhere is finished by running it again with the same keys.

use hyperswitch_masking::{PeekInterface, Secret, StrongSecret};

use crate::{
    app::TenantAppState,
    audit,
    crypto::encryption_manager::{encryption_interface::Encryption, managers::aes::GcmAes256},
    domain::hash::{self, RehashReport},
    error::{self, ContainerError},
    storage::{LockerInterface, MerchantInterface, types::EncryptedMerchant},
};

/// Which key opens a merchant row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedBy {
    New,
    Former,
    Neither,
}

/// The merchant key inside `blob` if `key` opens it, held so that it is wiped when dropped.
fn open(key: &GcmAes256, blob: &[u8]) -> Option<StrongSecret<Vec<u8>>> {
    key.decrypt(blob.to_vec()).ok().map(StrongSecret::new)
}

/// Tries the new key first, then the former one; the AES-GCM tag decides. The decrypted merchant
/// key is dropped at once.
pub(crate) fn wrapped_by(blob: &[u8], new: &GcmAes256, former: &GcmAes256) -> WrappedBy {
    if open(new, blob).is_some() {
        WrappedBy::New
    } else if open(former, blob).is_some() {
        WrappedBy::Former
    } else {
        WrappedBy::Neither
    }
}

/// Every row must open under the new key and none under the former one.
pub(crate) fn final_check(
    rows: &[EncryptedMerchant],
    new: &GcmAes256,
    former: &GcmAes256,
) -> Result<(), ContainerError<error::ApiError>> {
    for row in rows {
        let blob = row.enc_key.peek();
        let opens_former = open(former, blob).is_some();
        if wrapped_by(blob, new, former) != WrappedBy::New || opens_former {
            return Err(error::ApiError::MerchantKeyError.into());
        }
    }
    Ok(())
}

/// Counts printed by the command. `hashes` is set once the hash step has run.
#[derive(Debug, Default, Clone)]
pub struct RotationReport {
    pub merchants: u64,
    pub rewritten: u64,
    pub already_new: u64,
    pub hashes: Option<RehashReport>,
    pub complete: bool,
}

/// Rotates the tenant's master key. `state.config.tenant_secrets.master_key` holds the new key;
/// `former_master_key` the one that wraps the rows today. `max_rows` limits the rows rewritten in
/// this run. The run's outcome is recorded in the audit log.
pub async fn rotate(
    state: &TenantAppState,
    former_master_key: &Secret<Vec<u8>>,
    batch_size: i64,
    max_rows: Option<u64>,
) -> Result<RotationReport, ContainerError<error::ApiError>> {
    let result = rotate_rows(state, former_master_key, batch_size, max_rows).await;
    audit::record(
        &state.db,
        audit::master_key_rotation_run_audit(&state.config.tenant_id),
        result,
    )
    .await
}

async fn rotate_rows(
    state: &TenantAppState,
    former_master_key: &Secret<Vec<u8>>,
    batch_size: i64,
    max_rows: Option<u64>,
) -> Result<RotationReport, ContainerError<error::ApiError>> {
    if batch_size < 1 {
        return Err(error::ApiError::ValidationError("batch size must be at least 1").into());
    }
    let new_key = state.config.tenant_secrets.master_key.peek();
    if new_key == former_master_key.peek() {
        return Err(
            error::ApiError::ValidationError("the new master key equals the former one").into(),
        );
    }
    let new = GcmAes256::new(new_key.clone());
    let former = GcmAes256::new(former_master_key.peek().clone());

    // Pre-check, read only. The hash step reads the locker rows: under `kv` that read refuses, and
    // it must refuse here, before any merchant row is written.
    state.db.find_locker_batch(0, 1).await?;
    let rows = all_merchants(state, batch_size).await?;
    if rows
        .iter()
        .any(|row| wrapped_by(row.enc_key.peek(), &new, &former) == WrappedBy::Neither)
    {
        // A row under a third key: some earlier run used another key. Nothing is written.
        return Err(error::ApiError::MerchantKeyError.into());
    }

    let mut report = RotationReport {
        merchants: u64::try_from(rows.len()).unwrap_or(u64::MAX),
        ..RotationReport::default()
    };
    for row in &rows {
        match wrapped_by(row.enc_key.peek(), &new, &former) {
            WrappedBy::New => report.already_new += 1,
            WrappedBy::Former => {
                if max_rows.is_some_and(|max| report.rewritten >= max) {
                    return Ok(report);
                }
                rewrite_row(state, row, &new, &former).await?;
                report.rewritten += 1;
            }
            WrappedBy::Neither => return Err(error::ApiError::MerchantKeyError.into()),
        }
    }

    final_check(&all_merchants(state, batch_size).await?, &new, &former)?;
    let hashes = hash::rehash(state, batch_size, None).await?;
    report.complete = hashes.complete;
    report.hashes = Some(hashes);
    Ok(report)
}

/// Every merchant row, in `id` order, read `batch_size` at a time.
async fn all_merchants(
    state: &TenantAppState,
    batch_size: i64,
) -> Result<Vec<EncryptedMerchant>, ContainerError<error::ApiError>> {
    let mut rows = Vec::new();
    let mut cursor = 0;
    loop {
        let batch = state.db.find_merchant_batch(cursor, batch_size).await?;
        let Some(last) = batch.last() else {
            break;
        };
        cursor = last.id;
        rows.extend(batch);
    }
    Ok(rows)
}

/// Re-encrypts one row's merchant key under the new master key. The audit entry comes first; an
/// update that changes no row (someone else changed it) stops the run.
async fn rewrite_row(
    state: &TenantAppState,
    row: &EncryptedMerchant,
    new: &GcmAes256,
    former: &GcmAes256,
) -> Result<(), ContainerError<error::ApiError>> {
    let merchant_key = open(former, row.enc_key.peek())
        .ok_or_else(|| ContainerError::from(error::ApiError::MerchantKeyError))?;
    let rewrapped = new
        .encrypt(merchant_key.peek().clone())
        .map_err(|_| ContainerError::from(error::ApiError::EncodingError))?;
    drop(merchant_key);

    audit::record(
        &state.db,
        audit::master_key_rotation_row_audit(&state.config.tenant_id, &row.merchant_id),
        Ok(()),
    )
    .await?;
    let changed = state
        .db
        .update_merchant_enc_key(
            &row.merchant_id,
            row.enc_key.clone(),
            Secret::new(rewrapped),
        )
        .await?;
    if changed == 0 {
        return Err(error::ApiError::DatabaseError.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use hyperswitch_masking::Secret;

    use super::*;
    use crate::crypto::encryption_manager::{
        encryption_interface::Encryption, managers::aes::generate_aes256_key,
    };

    fn key() -> GcmAes256 {
        GcmAes256::new(generate_aes256_key().to_vec())
    }

    fn row(id: i32, blob: Vec<u8>) -> EncryptedMerchant {
        EncryptedMerchant {
            id,
            merchant_id: format!("merchant-{id}"),
            enc_key: Secret::new(blob),
        }
    }

    #[test]
    fn wrapped_by_tells_the_key_apart() {
        let (a, b, c) = (key(), key(), key());
        let blob = a.encrypt(b"merchant key".to_vec()).unwrap();
        assert_eq!(wrapped_by(&blob, &a, &b), WrappedBy::New);
        assert_eq!(wrapped_by(&blob, &b, &a), WrappedBy::Former);
        assert_eq!(wrapped_by(&blob, &b, &c), WrappedBy::Neither);
    }

    #[test]
    fn wrapped_by_prefers_the_new_key() {
        let a = key();
        let blob = a.encrypt(b"merchant key".to_vec()).unwrap();
        assert_eq!(wrapped_by(&blob, &a, &a), WrappedBy::New);
    }

    #[test]
    fn final_check_accepts_rows_under_the_new_key_only() {
        let (new, former) = (key(), key());
        let rows = [
            row(1, new.encrypt(b"one".to_vec()).unwrap()),
            row(2, new.encrypt(b"two".to_vec()).unwrap()),
        ];
        assert!(final_check(&rows, &new, &former).is_ok());
        assert!(final_check(&[], &new, &former).is_ok());
    }

    #[test]
    fn final_check_refuses_a_row_still_under_the_former_key() {
        let (new, former) = (key(), key());
        let rows = [
            row(1, new.encrypt(b"one".to_vec()).unwrap()),
            row(2, former.encrypt(b"two".to_vec()).unwrap()),
        ];
        assert!(final_check(&rows, &new, &former).is_err());
    }

    #[test]
    fn final_check_refuses_a_row_under_neither_key() {
        let (new, former, other) = (key(), key(), key());
        let rows = [row(1, other.encrypt(b"one".to_vec()).unwrap())];
        assert!(final_check(&rows, &new, &former).is_err());
    }
}
