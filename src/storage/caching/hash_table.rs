use hyperswitch_masking::Secret;

use crate::{
    error::ContainerError,
    storage::{self, types},
};

impl<T> storage::HashInterface for super::Caching<T>
where
    T: storage::HashInterface
        + storage::Cacheable<types::HashTable, Key = Secret<Vec<u8>>, Value = types::HashTable>
        + storage::Cacheable<types::Merchant>
        + storage::Cacheable<types::Fingerprint>
        + super::CacheableWithEntity<T>
        + Sync
        + Send,
{
    type Error = T::Error;

    async fn find_optional_by_data_hash(
        &self,
        data_hash: Secret<Vec<u8>>,
    ) -> Result<Option<types::HashTable>, ContainerError<Self::Error>> {
        match self.lookup::<types::HashTable>(data_hash.clone()).await {
            value @ Some(_) => Ok(value),
            None => Ok(
                match self
                    .inner
                    .find_optional_by_data_hash(data_hash.clone())
                    .await?
                {
                    None => None,
                    Some(value) => {
                        self.cache_data::<types::HashTable>(data_hash, value.clone())
                            .await;
                        Some(value)
                    }
                },
            ),
        }
    }

    async fn insert_hash(
        &self,
        data_hash: Secret<Vec<u8>>,
    ) -> Result<types::HashTable, ContainerError<Self::Error>> {
        let output = self.inner.insert_hash(data_hash.clone()).await?;
        self.cache_data::<types::HashTable>(data_hash, output.clone())
            .await;
        Ok(output)
    }

    async fn find_optional_by_hash_id(
        &self,
        hash_id: &str,
    ) -> Result<Option<types::HashTable>, ContainerError<Self::Error>> {
        self.inner.find_optional_by_hash_id(hash_id).await
    }

    async fn delete_hash_if_unused(
        &self,
        hash_id: &str,
    ) -> Result<Option<Secret<Vec<u8>>>, ContainerError<Self::Error>> {
        let deleted = self.inner.delete_hash_if_unused(hash_id).await?;
        if let Some(data_hash) = &deleted {
            self.forget_hash(data_hash).await;
        }
        Ok(deleted)
    }

    async fn delete_unused_hashes_before(
        &self,
        before: time::PrimitiveDateTime,
    ) -> Result<Vec<Secret<Vec<u8>>>, ContainerError<Self::Error>> {
        let deleted = self.inner.delete_unused_hashes_before(before).await?;
        for data_hash in &deleted {
            self.forget_hash(data_hash).await;
        }
        Ok(deleted)
    }
}

impl<T> super::Caching<T>
where
    T: storage::Cacheable<types::HashTable, Key = Secret<Vec<u8>>, Value = types::HashTable>
        + storage::Cacheable<types::Merchant>
        + storage::Cacheable<types::Fingerprint>
        + super::CacheableWithEntity<T>,
{
    /// Drops a deleted hash row from the cache, so a later lookup reads the database.
    async fn forget_hash(&self, data_hash: &Secret<Vec<u8>>) {
        <Self as super::GetCache<T, types::HashTable>>::get_cache(self)
            .invalidate(data_hash)
            .await;
    }
}
