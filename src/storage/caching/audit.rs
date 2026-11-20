use crate::{
    audit::{AuditEntry, AuditInterface},
    error::{ContainerError, StorageError},
    storage::{self, types},
};

/// Audit entries are never cached: the write goes straight to the inner storage.
impl<T> AuditInterface for super::Caching<T>
where
    T: AuditInterface
        + storage::Cacheable<types::Merchant>
        + storage::Cacheable<types::HashTable>
        + storage::Cacheable<types::Fingerprint>
        + super::CacheableWithEntity<T>
        + Sync
        + Send,
{
    async fn insert_audit_entry(&self, entry: AuditEntry) -> Result<(), ContainerError<StorageError>> {
        self.inner.insert_audit_entry(entry).await
    }
}
