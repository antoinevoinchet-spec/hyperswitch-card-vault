use hyperswitch_masking::Secret;

use crate::{
    app::TenantAppState,
    error::{self, ContainerError, StorageErrorExt},
    observability::metrics,
    storage::{HashInterface, types::HashTable},
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
