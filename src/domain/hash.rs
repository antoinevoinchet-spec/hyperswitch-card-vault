use hyperswitch_masking::{PeekInterface, Secret};

use crate::{
    app::TenantAppState,
    audit,
    crypto::{hash_manager::managers::sha::CardDedupHmac, keymanager},
    error::{self, ContainerError, ResultContainerExt, StorageErrorExt},
    observability::metrics,
    routes::data::{
        crypto_operation, transformers,
        types::{Data, StoredData},
    },
    storage::{HashInterface, LockerInterface, types::HashTable, utils::generate_uuid},
};

/// Insert a hash row for `data_hash`, or return the existing one on a duplicate conflict.
///
/// `add_card` already checks `find_by_data_hash` first; this provides the race-safe insert
/// for the not-found branch (`db.insert` → on duplicate → `db.find`).
pub async fn insert_or_get(
    state: &TenantAppState,
    data_hash: Secret<Vec<u8>>,
) -> Result<HashTable, ContainerError<error::HashDBError>> {
    match state.db.insert_hash(data_hash.clone()).await {
        Ok(hash) => {
            super::record_get_or_insert_outcome(
                metrics::Resource::HashTable,
                metrics::DomainGetOrInsertOutcome::Created,
            );
            Ok(hash)
        }

        Err(err) if err.get_inner().is_duplicate() => {
            match state.db.find_optional_by_data_hash(data_hash).await {
                Ok(Some(hash)) => {
                    super::record_get_or_insert_outcome(
                        metrics::Resource::HashTable,
                        metrics::DomainGetOrInsertOutcome::FoundExistingAfterDuplicateInsert,
                    );
                    Ok(hash)
                }
                Ok(None) => {
                    super::record_get_or_insert_outcome(
                        metrics::Resource::HashTable,
                        metrics::DomainGetOrInsertOutcome::Error,
                    );
                    Err(error::HashDBError::DBInsertError.into())
                }
                Err(err) => {
                    super::record_get_or_insert_outcome(
                        metrics::Resource::HashTable,
                        metrics::DomainGetOrInsertOutcome::Error,
                    );
                    Err(err)
                }
            }
        }

        Err(err) => {
            super::record_get_or_insert_outcome(
                metrics::Resource::HashTable,
                metrics::DomainGetOrInsertOutcome::Error,
            );
            Err(err)
        }
    }
}

/// Age under which an unused hash row is kept by the final clean-up: a concurrent `/data/add` may
/// have inserted it and not yet stored the card that cites it.
const CLEAN_UP_MARGIN: time::Duration = time::Duration::seconds(60);

/// Re-hash job: gives every `locker` row of the tenant the duplicate-check hash that `/data/add`
/// computes today (current master key, merchant and customer scope), then deletes the hash rows
/// no row cites any more. See `docs/superpowers/specs/2026-11-23-rehash-job-design.md`.
///
/// Nothing is stored about progress: each row's state is recomputed, so running it again is
/// harmless and resumes an interrupted run. Rows are read in `id` order, `batch_size` at a time;
/// with `max_rows`, the run stops after that many rows and reports `complete = false`. The
/// decrypted card stays in memory; no value of it, of a hash or of a key is logged or returned.
pub async fn rehash(
    state: &TenantAppState,
    batch_size: i64,
    max_rows: Option<u64>,
) -> Result<RehashReport, ContainerError<error::ApiError>> {
    let result = rehash_rows(state, batch_size, max_rows).await;
    audit::record(
        &state.db,
        audit::rehash_run_audit(&state.config.tenant_id),
        result,
    )
    .await
}

async fn rehash_rows(
    state: &TenantAppState,
    batch_size: i64,
    max_rows: Option<u64>,
) -> Result<RehashReport, ContainerError<error::ApiError>> {
    if batch_size < 1 {
        // A limit of 0 would read no row and report a complete run.
        return Err(error::ApiError::ValidationError("batch size must be at least 1").into());
    }
    let started = crate::utils::date_time::now();
    let mut report = RehashReport::default();
    let mut cursor = 0;

    'batches: loop {
        let batch = state.db.find_locker_batch(cursor, batch_size).await?;
        if batch.is_empty() {
            report.complete = true;
            break;
        }
        for (id, locker) in batch {
            if max_rows.is_some_and(|max| report.examined >= max) {
                break 'batches;
            }
            cursor = id;
            report.examined += 1;
            rehash_row(state, locker, &mut report).await?;
        }
    }

    if report.complete {
        report.check_balance()?;
        // The clean-up deletes rows too: its audit entry comes first, like each row's.
        audit::record(
            &state.db,
            audit::rehash_cleanup_audit(&state.config.tenant_id),
            Ok(()),
        )
        .await?;
        let removed = state
            .db
            .delete_unused_hashes_before(started - CLEAN_UP_MARGIN)
            .await?;
        report.removed_hash_rows += u64::try_from(removed.len()).unwrap_or(u64::MAX);
    }
    Ok(report)
}

/// One row: current, moved to its current hash, or (W2 = A) detached when another row of the same
/// merchant and customer already holds that hash.
async fn rehash_row(
    state: &TenantAppState,
    locker: crate::storage::types::Locker,
    report: &mut RehashReport,
) -> Result<(), ContainerError<error::ApiError>> {
    let locker_id = locker.locker_id.clone();
    let merchant_id = locker.merchant_id.clone();
    let customer_id = locker.customer_id.clone();
    let old_hash_id = locker.hash_id.clone();
    let created_at = locker.created_at;

    let crypto_manager = keymanager::get_dek_manager(&state.config.external_key_manager)
        .find_by_entity_id(state, merchant_id.clone())
        .await?;
    let decrypted = crypto_operation::decrypt_data(state, crypto_manager, locker).await?;
    let stored = decrypted
        .data
        .get_decrypted_inner_value()
        .ok_or::<ContainerError<_>>(error::ApiError::DecodingError.into())?;
    let data = match serde_json::from_slice::<StoredData>(stored.peek())
        .change_error(error::ApiError::DecodingError)?
    {
        StoredData::CardData(card) => Data::Card { card },
        StoredData::EncData(enc_card_data) => Data::EncData { enc_card_data },
    };
    let dedup_hmac = CardDedupHmac::from_master_key(
        &state.config.tenant_secrets.master_key,
        &merchant_id,
        &customer_id,
    )
    .change_error(error::ApiError::EncodingError)?;
    let hash = Secret::new(transformers::get_hash(&data, dedup_hmac)?);
    drop(data);
    drop(decrypted);

    let cited = state.db.find_optional_by_hash_id(&old_hash_id).await?;
    if cited
        .as_ref()
        .is_some_and(|row| row.data_hash.peek() == hash.peek())
    {
        report.current += 1;
        return Ok(());
    }

    let target = state.db.find_optional_by_data_hash(hash.clone()).await?;
    if let Some(target) = &target {
        let holder = state
            .db
            .find_optional_by_hash_id_merchant_id_customer_id(
                &target.hash_id,
                &merchant_id,
                &customer_id,
            )
            .await?;
        if let Some(other) = holder.filter(|other| other.locker_id.peek() != locker_id.peek()) {
            if other.created_at < created_at {
                // The newer copy keeps the current hash (W2): detach the older holder, then move
                // this row. Both audit entries come before either write.
                record_row(state, &merchant_id, &customer_id, &other.locker_id).await?;
                record_row(state, &merchant_id, &customer_id, &locker_id).await?;
                move_row(
                    state,
                    &other.locker_id,
                    &merchant_id,
                    &customer_id,
                    &target.hash_id,
                    &generate_uuid(),
                    false,
                )
                .await?;
                let removed = move_row(
                    state,
                    &locker_id,
                    &merchant_id,
                    &customer_id,
                    &old_hash_id,
                    &target.hash_id,
                    true,
                )
                .await?;
                report.duplicates += 1;
                report.removed_hash_rows += removed;
                return Ok(());
            }
            if cited.is_none() {
                // Detached by an earlier run: nothing left to do.
                report.current += 1;
                return Ok(());
            }
            record_row(state, &merchant_id, &customer_id, &locker_id).await?;
            let removed = move_row(
                state,
                &locker_id,
                &merchant_id,
                &customer_id,
                &old_hash_id,
                &generate_uuid(),
                true,
            )
            .await?;
            report.duplicates += 1;
            report.removed_hash_rows += removed;
            return Ok(());
        }
    }

    // The audit entry comes before any write for this row.
    record_row(state, &merchant_id, &customer_id, &locker_id).await?;
    let new_hash_id = match target {
        Some(target) => target.hash_id,
        None => insert_or_get(state, hash).await?.hash_id,
    };
    let removed = move_row(
        state,
        &locker_id,
        &merchant_id,
        &customer_id,
        &old_hash_id,
        &new_hash_id,
        true,
    )
    .await?;
    report.moved += 1;
    report.removed_hash_rows += removed;
    Ok(())
}

/// Writes the row's audit entry; an error stops the job before the row changes.
async fn record_row(
    state: &TenantAppState,
    merchant_id: &str,
    customer_id: &str,
    locker_id: &Secret<String>,
) -> Result<(), ContainerError<error::ApiError>> {
    audit::record(
        &state.db,
        audit::rehash_row_audit(
            &state.config.tenant_id,
            merchant_id,
            customer_id,
            locker_id.peek(),
        ),
        Ok(()),
    )
    .await
}

/// Points the row at `new_hash_id`, then, with `delete_old`, deletes the old hash row if nothing
/// cites it any more. Returns the number of hash rows deleted (0 or 1).
async fn move_row(
    state: &TenantAppState,
    locker_id: &Secret<String>,
    merchant_id: &str,
    customer_id: &str,
    old_hash_id: &str,
    new_hash_id: &str,
    delete_old: bool,
) -> Result<u64, ContainerError<error::ApiError>> {
    let changed = state
        .db
        .update_locker_hash_id(
            locker_id.clone(),
            merchant_id,
            customer_id,
            old_hash_id,
            new_hash_id,
        )
        .await?;
    if changed == 0 {
        // The row changed since it was read: stop rather than count it.
        return Err(error::ApiError::DatabaseError.into());
    }
    if !delete_old {
        return Ok(0);
    }
    let removed = state.db.delete_hash_if_unused(old_hash_id).await?;
    Ok(u64::from(removed.is_some()))
}

/// Counts printed by the re-hash job. They must balance: every examined row is current, moved or
/// a duplicate.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RehashReport {
    pub examined: u64,
    pub current: u64,
    pub moved: u64,
    pub duplicates: u64,
    pub removed_hash_rows: u64,
    pub complete: bool,
}

impl RehashReport {
    /// Fails when the counts do not add up, so the final clean-up never runs on a run whose
    /// counts cannot be trusted.
    pub(crate) fn check_balance(&self) -> Result<(), ContainerError<error::ApiError>> {
        if self.examined == self.current + self.moved + self.duplicates {
            Ok(())
        } else {
            Err(error::ApiError::DatabaseError.into())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn report_balance_accepts_matching_counts() {
        let report = RehashReport {
            examined: 4,
            current: 1,
            moved: 2,
            duplicates: 1,
            ..RehashReport::default()
        };
        assert!(report.check_balance().is_ok());
    }

    #[test]
    fn report_balance_rejects_mismatched_counts() {
        let report = RehashReport {
            examined: 3,
            current: 1,
            moved: 1,
            ..RehashReport::default()
        };
        assert!(report.check_balance().is_err());
    }
}
