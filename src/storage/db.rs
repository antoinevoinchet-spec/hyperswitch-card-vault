use async_bb8_diesel::{AsyncConnection, AsyncRunQueryDsl};
#[cfg(not(feature = "kv"))]
use diesel::{BoolExpressionMethods, OptionalExtension};
use diesel::{ExpressionMethods, QueryDsl, associations::HasTable};
#[cfg(not(feature = "kv"))]
use hyperswitch_masking::ExposeInterface;
use hyperswitch_masking::Secret;

use super::{
    DbOperation, MerchantInterface, Storage, schema, types,
    types::{StorageDecryption, StorageEncryption},
    utils,
};
use crate::{
    crypto::encryption_manager::managers::aes,
    error::{self, ContainerError, ResultContainerExt},
    logger,
    storage::scheme::StorageScheme,
};

impl MerchantInterface for Storage {
    type Algorithm = aes::GcmAes256;
    type Error = error::MerchantDBError;

    async fn find_by_merchant_id(
        &self,
        merchant_id: &str,
        key: &aes::GcmAes256,
    ) -> Result<types::Merchant, ContainerError<Self::Error>> {
        // Reads are routed to the read replica when enabled.
        let conn = self.route_conn().await?;

        // Single SELECT; a missing row surfaces (via `?`) as `MerchantDBError::NotFoundError`.
        // Decryption of the stored DEK is the merchant-specific envelope.
        let query = types::MerchantInner::table()
            .filter(schema::merchant::merchant_id.eq(merchant_id.to_owned()));

        let pool = conn.pool();
        let operation = DbOperation::FindOne;
        super::log_db_query::<<types::MerchantInner as HasTable>::Table, _>(
            &query, operation, pool,
        );

        let inner: types::MerchantInner =
            super::record_db_query::<<types::MerchantInner as HasTable>::Table, _, _, _>(
                query.get_result_async(conn.get()),
                operation,
                pool,
            )
            .await?;

        Ok(inner.decrypt(key)?)
    }

    async fn insert_merchant(
        &self,
        new: types::MerchantNew<'_>,
        key: &aes::GcmAes256,
    ) -> Result<types::Merchant, ContainerError<Self::Error>> {
        let conn = self.get_conn().await?;

        let query = diesel::insert_into(types::MerchantInner::table()).values(new.encrypt(key)?);

        let pool = conn.pool();
        let operation = DbOperation::Insert;
        super::log_db_query::<<types::MerchantInner as HasTable>::Table, _>(
            &query, operation, pool,
        );

        let inner: types::MerchantInner =
            super::record_db_query::<<types::MerchantInner as HasTable>::Table, _, _, _>(
                query.get_result_async(conn.get()),
                operation,
                pool,
            )
            .await?;

        Ok(inner.decrypt(key)?)
    }

    #[cfg(feature = "external_key_manager")]
    async fn find_all_keys_excluding_entity_keys(
        &self,
        key: &Self::Algorithm,
        limit: i64,
    ) -> Result<Vec<types::Merchant>, ContainerError<Self::Error>> {
        let conn = self.route_conn().await?;

        let query = schema::merchant::table
            .filter(
                schema::merchant::merchant_id
                    .ne_all(schema::entity::table.select(schema::entity::entity_id)),
            )
            .limit(limit);

        let pool = conn.pool();
        let operation = DbOperation::Filter;
        super::log_db_query::<<types::MerchantInner as HasTable>::Table, _>(
            &query, operation, pool,
        );

        let result: Result<Vec<types::MerchantInner>, ContainerError<Self::Error>> =
            super::record_db_query::<<types::MerchantInner as HasTable>::Table, _, _, _>(
                query.load_async::<types::MerchantInner>(conn.get()),
                operation,
                pool,
            )
            .await
            .change_error(error::StorageError::FindError)
            .map_err(ContainerError::from);

        result?
            .into_iter()
            .map(|inner| {
                inner
                    .decrypt(key)
                    .change_error(error::MerchantDBError::DEKDecryptionError)
            })
            .collect::<Result<Vec<_>, _>>()
    }

    async fn find_merchant_batch(
        &self,
        after_id: i32,
        limit: i64,
    ) -> Result<Vec<types::EncryptedMerchant>, ContainerError<Self::Error>> {
        let conn = self.get_conn().await?;
        let query = types::MerchantInner::table()
            .filter(schema::merchant::id.gt(after_id))
            .order(schema::merchant::id.asc())
            .limit(limit);

        let pool = conn.pool();
        // `Filter` exists only with `external_key_manager`; the re-hash batch read uses `FindOne`.
        let operation = DbOperation::FindOne;
        super::log_db_query::<<types::MerchantInner as HasTable>::Table, _>(
            &query, operation, pool,
        );

        let rows: Vec<types::MerchantInner> =
            super::record_db_query::<<types::MerchantInner as HasTable>::Table, _, _, _>(
                query.load_async(conn.get()),
                operation,
                pool,
            )
            .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn update_merchant_enc_key(
        &self,
        merchant_id: &str,
        expected: Secret<Vec<u8>>,
        new: Secret<Vec<u8>>,
    ) -> Result<usize, ContainerError<Self::Error>> {
        use diesel::BoolExpressionMethods as _;

        let conn = self.get_conn().await?;
        // Bound parameters; the second condition makes a concurrent change visible as 0 rows.
        let query = diesel::update(types::MerchantInner::table())
            .filter(
                schema::merchant::merchant_id
                    .eq(merchant_id.to_owned())
                    .and(schema::merchant::enc_key.eq(types::Encrypted::new(expected))),
            )
            .set(schema::merchant::enc_key.eq(types::Encrypted::new(new)));

        let pool = conn.pool();
        let operation = DbOperation::Update;
        super::log_db_query::<<types::MerchantInner as HasTable>::Table, _>(
            &query, operation, pool,
        );

        let output =
            super::record_db_query_rows::<<types::MerchantInner as HasTable>::Table, _, _>(
                query.execute_async(conn.get()),
                operation,
                pool,
            )
            .await?;
        Ok(output)
    }
}

impl super::LockerInterface for Storage {
    type Error = error::VaultDBError;

    async fn insert_locker(
        &self,
        new: types::LockerNew,
    ) -> Result<types::Locker, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            return super::kv::insert_resource_with_reverse_lookup::<types::Locker>(self, new)
                .await;
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;

            let query = diesel::insert_into(types::LockerInner::table()).values(new);

            let pool = conn.pool();
            let operation = DbOperation::Insert;
            super::log_db_query::<<types::LockerInner as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let output: types::LockerInner =
                super::record_db_query::<<types::LockerInner as HasTable>::Table, _, _, _>(
                    query.get_result_async(conn.get()),
                    operation,
                    pool,
                )
                .await?;

            Ok(output.into())
        }
    }

    async fn find_by_locker_id_merchant_id_customer_id(
        &self,
        locker_id: Secret<String>,
        merchant_id: &str,
        customer_id: &str,
    ) -> Result<types::Locker, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            let pk = super::kv::impls::locker::LockerPrimaryKeyType {
                locker_id: locker_id.clone(),
                merchant_id: merchant_id.to_string(),
                customer_id: customer_id.to_string(),
            };
            return super::kv::find_resource_by_id::<types::Locker>(self, pk).await;
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;

            // A missing row surfaces (via `?`) as `VaultDBError::NotFoundError`.
            let query = types::LockerInner::table().filter(
                schema::locker::locker_id
                    .eq(locker_id.expose())
                    .and(schema::locker::merchant_id.eq(merchant_id.to_owned()))
                    .and(schema::locker::customer_id.eq(customer_id.to_owned())),
            );

            let pool = conn.pool();
            let operation = DbOperation::FindOne;
            super::log_db_query::<<types::LockerInner as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let output: types::LockerInner =
                super::record_db_query::<<types::LockerInner as HasTable>::Table, _, _, _>(
                    query.get_result_async(conn.get()),
                    operation,
                    pool,
                )
                .await?;

            Ok(output.into())
        }
    }

    async fn find_optional_by_hash_id_merchant_id_customer_id(
        &self,
        hash_id: &str,
        merchant_id: &str,
        customer_id: &str,
    ) -> Result<Option<types::Locker>, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            let lookup_key = super::kv::impls::locker::LockerHashLookupKey {
                hash_id: hash_id.to_string(),
                merchant_id: merchant_id.to_string(),
                customer_id: customer_id.to_string(),
            };

            return super::kv::find_optional_resource_by_lookup_id::<types::Locker>(
                self, lookup_key,
            )
            .await;
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;

            let query = types::LockerInner::table().filter(
                schema::locker::hash_id
                    .eq(hash_id.to_owned())
                    .and(schema::locker::merchant_id.eq(merchant_id.to_owned()))
                    .and(schema::locker::customer_id.eq(customer_id.to_owned())),
            );

            let pool = conn.pool();
            let operation = DbOperation::FindOne;
            super::log_db_query::<<types::LockerInner as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let output = super::record_db_query_optional::<
                <types::LockerInner as HasTable>::Table,
                _,
                _,
                _,
            >(
                async {
                    query
                        .get_result_async::<types::LockerInner>(conn.get())
                        .await
                        .optional()
                },
                operation,
                pool,
            )
            .await?;

            Ok(output.map(From::from))
        }
    }

    async fn delete_locker(
        &self,
        locker_id: Secret<String>,
        merchant_id: &str,
        customer_id: &str,
    ) -> Result<usize, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            let pk = super::kv::impls::locker::LockerPrimaryKeyType {
                locker_id,
                merchant_id: merchant_id.to_string(),
                customer_id: customer_id.to_string(),
            };

            return super::kv::delete_resource_by_id_with_reverse_lookup::<types::Locker>(self, pk)
                .await;
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;
            let query = diesel::delete(types::LockerInner::table()).filter(
                schema::locker::locker_id
                    .eq(locker_id.expose())
                    .and(schema::locker::merchant_id.eq(merchant_id.to_owned()))
                    .and(schema::locker::customer_id.eq(customer_id.to_owned())),
            );

            let pool = conn.pool();
            let operation = DbOperation::Delete;
            super::log_db_query::<<types::LockerInner as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let output =
                super::record_db_query_rows::<<types::LockerInner as HasTable>::Table, _, _>(
                    query.execute_async(conn.get()),
                    operation,
                    pool,
                )
                .await?;
            Ok(output)
        }
    }

    async fn find_locker_batch(
        &self,
        after_id: i32,
        limit: i64,
    ) -> Result<Vec<(i32, types::Locker)>, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            let _ = (after_id, limit);
            Err(error::VaultDBError::DBFilterError.into())
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;
            let query = types::LockerInner::table()
                .select((schema::locker::id, schema::locker::all_columns))
                .filter(schema::locker::id.gt(after_id))
                .order(schema::locker::id.asc())
                .limit(limit);

            let pool = conn.pool();
            let operation = DbOperation::FindOne;
            super::log_db_query::<<types::LockerInner as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let rows: Vec<(i32, types::LockerInner)> =
                super::record_db_query::<<types::LockerInner as HasTable>::Table, _, _, _>(
                    query.load_async(conn.get()),
                    operation,
                    pool,
                )
                .await?;

            Ok(rows
                .into_iter()
                .map(|(id, inner)| (id, inner.into()))
                .collect())
        }
    }

    async fn update_locker_hash_id(
        &self,
        locker_id: Secret<String>,
        merchant_id: &str,
        customer_id: &str,
        old_hash_id: &str,
        new_hash_id: &str,
    ) -> Result<usize, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            let _ = (
                locker_id,
                merchant_id,
                customer_id,
                old_hash_id,
                new_hash_id,
            );
            Err(error::VaultDBError::DBError.into())
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;
            let query = diesel::update(types::LockerInner::table())
                .filter(
                    schema::locker::locker_id
                        .eq(locker_id.expose())
                        .and(schema::locker::merchant_id.eq(merchant_id.to_owned()))
                        .and(schema::locker::customer_id.eq(customer_id.to_owned()))
                        .and(schema::locker::hash_id.eq(old_hash_id.to_owned())),
                )
                .set(schema::locker::hash_id.eq(new_hash_id.to_owned()));

            let pool = conn.pool();
            let operation = DbOperation::Update;
            super::log_db_query::<<types::LockerInner as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let output =
                super::record_db_query_rows::<<types::LockerInner as HasTable>::Table, _, _>(
                    query.execute_async(conn.get()),
                    operation,
                    pool,
                )
                .await?;
            Ok(output)
        }
    }
}

impl super::HashInterface for Storage {
    type Error = error::HashDBError;

    async fn find_optional_by_data_hash(
        &self,
        data_hash: Secret<Vec<u8>>,
    ) -> Result<Option<types::HashTable>, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            let pk = super::kv::impls::hash_table::HashTablePrimaryKey { data_hash };

            return super::kv::find_optional_resource_by_id::<types::HashTable>(self, pk).await;
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;

            let query = types::HashTable::table()
                .filter(schema::hash_table::data_hash.eq(data_hash.expose()));

            let pool = conn.pool();
            let operation = DbOperation::FindOne;
            super::log_db_query::<<types::HashTable as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let output =
                super::record_db_query_optional::<<types::HashTable as HasTable>::Table, _, _, _>(
                    async {
                        query
                            .get_result_async::<types::HashTable>(conn.get())
                            .await
                            .optional()
                    },
                    operation,
                    pool,
                )
                .await?;

            Ok(output)
        }
    }

    async fn insert_hash(
        &self,
        data_hash: Secret<Vec<u8>>,
    ) -> Result<types::HashTable, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            let hash_table_new = types::HashTableNew {
                hash_id: utils::generate_uuid(),
                data_hash,
                created_at: crate::utils::date_time::now(),
                updated_by: Some(StorageScheme::PostgresOnly),
            };
            return super::kv::insert_resource::<types::HashTable>(self, hash_table_new).await;
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;

            let query =
                diesel::insert_into(types::HashTable::table()).values(types::HashTableNew {
                    hash_id: utils::generate_uuid(),
                    data_hash,
                    created_at: crate::utils::date_time::now(),
                    updated_by: Some(StorageScheme::PostgresOnly),
                });

            let pool = conn.pool();
            let operation = DbOperation::Insert;
            super::log_db_query::<<types::HashTable as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let output: types::HashTable =
                super::record_db_query::<<types::HashTable as HasTable>::Table, _, _, _>(
                    query.get_result_async(conn.get()),
                    operation,
                    pool,
                )
                .await?;

            Ok(output)
        }
    }

    async fn find_optional_by_hash_id(
        &self,
        hash_id: &str,
    ) -> Result<Option<types::HashTable>, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            let _ = hash_id;
            Err(error::HashDBError::DBFilterError.into())
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;
            let query = types::HashTable::table()
                .filter(schema::hash_table::hash_id.eq(hash_id.to_owned()));

            let pool = conn.pool();
            let operation = DbOperation::FindOne;
            super::log_db_query::<<types::HashTable as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let output =
                super::record_db_query_optional::<<types::HashTable as HasTable>::Table, _, _, _>(
                    async {
                        query
                            .get_result_async::<types::HashTable>(conn.get())
                            .await
                            .optional()
                    },
                    operation,
                    pool,
                )
                .await?;

            Ok(output)
        }
    }

    async fn delete_hash_if_unused(
        &self,
        hash_id: &str,
    ) -> Result<Option<Secret<Vec<u8>>>, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            let _ = hash_id;
            Err(error::HashDBError::DBError.into())
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;
            // Bound parameter; the NOT EXISTS keeps every row that a locker row still cites.
            let query = diesel::sql_query(
                "DELETE FROM hash_table h WHERE h.hash_id = $1 \
                 AND NOT EXISTS (SELECT 1 FROM locker l WHERE l.hash_id = h.hash_id) \
                 RETURNING h.data_hash",
            )
            .bind::<diesel::sql_types::Text, _>(hash_id.to_owned());

            let pool = conn.pool();
            let operation = DbOperation::Delete;
            super::log_db_query::<<types::HashTable as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let rows: Vec<DeletedHash> =
                super::record_db_query::<<types::HashTable as HasTable>::Table, _, _, _>(
                    query.load_async(conn.get()),
                    operation,
                    pool,
                )
                .await?;

            Ok(rows
                .into_iter()
                .next()
                .map(|row| Secret::new(row.data_hash)))
        }
    }

    async fn delete_unused_hashes_before(
        &self,
        before: time::PrimitiveDateTime,
    ) -> Result<Vec<Secret<Vec<u8>>>, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            let _ = before;
            Err(error::HashDBError::DBError.into())
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;
            let query = diesel::sql_query(
                "DELETE FROM hash_table h WHERE h.created_at < $1 \
                 AND NOT EXISTS (SELECT 1 FROM locker l WHERE l.hash_id = h.hash_id) \
                 RETURNING h.data_hash",
            )
            .bind::<diesel::sql_types::Timestamp, _>(before);

            let pool = conn.pool();
            let operation = DbOperation::Delete;
            super::log_db_query::<<types::HashTable as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let rows: Vec<DeletedHash> =
                super::record_db_query::<<types::HashTable as HasTable>::Table, _, _, _>(
                    query.load_async(conn.get()),
                    operation,
                    pool,
                )
                .await?;

            Ok(rows
                .into_iter()
                .map(|row| Secret::new(row.data_hash))
                .collect())
        }
    }
}

/// `data_hash` returned by the re-hash job's deletes.
#[cfg(not(feature = "kv"))]
#[derive(diesel::QueryableByName)]
struct DeletedHash {
    #[diesel(sql_type = diesel::sql_types::Binary)]
    data_hash: Vec<u8>,
}

impl super::TestInterface for Storage {
    type Error = error::TestDBError;

    async fn test(&self) -> Result<(), ContainerError<Self::Error>> {
        let conn = self.get_conn().await?;

        // Health probe: insert then delete within one transaction so nothing persists.
        conn.get()
            .transaction_async(|conn| async move {
                let query = diesel::select(diesel::dsl::sql::<diesel::sql_types::Integer>("1 + 1"));
                let _x: i32 = query.get_result_async(&conn).await.map_err(|err| {
                    logger::error!(read_err=?err, "Error while reading element in the database");
                    error::TestDBError::DBReadError
                })?;

                diesel::insert_into(types::HashTable::table())
                    .values(types::HashTableNew {
                        hash_id: "test".to_string(),
                        data_hash: Secret::new(b"0".to_vec()),
                        created_at: crate::utils::date_time::now(),
                        // Test-only — always PostgresOnly.
                        updated_by: Some(StorageScheme::PostgresOnly),
                    })
                    .execute_async(&conn)
                    .await
                    .map_err(|err| {
                        logger::error!(write_err=?err, "Error while writing to database");
                        error::TestDBError::DBWriteError
                    })?;

                diesel::delete(
                    types::HashTable::table()
                        .filter(schema::hash_table::hash_id.eq("test".to_string())),
                )
                .execute_async(&conn)
                .await
                .map_err(|err| {
                    logger::error!(delete_err=?err, "Error while deleting element in the database");
                    error::TestDBError::DBDeleteError
                })?;

                Ok::<(), error::TestDBError>(())
            })
            .await?;

        Ok(())
    }

    async fn test_replica(&self) -> Result<(), ContainerError<Self::Error>> {
        let conn = self.get_replica_conn().await?;

        let query = diesel::select(diesel::dsl::sql::<diesel::sql_types::Integer>("1 + 1"));
        let _x: i32 = query
            .get_result_async(conn.get())
            .await
            .change_error(error::StorageError::FindError)?;

        Ok(())
    }
}

impl super::FingerprintInterface for Storage {
    type Error = error::FingerprintDBError;

    async fn find_optional_by_fingerprint_hash(
        &self,
        fingerprint_hash: Secret<Vec<u8>>,
    ) -> Result<Option<types::Fingerprint>, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            // Return the Queryable model, not the New struct.
            return super::kv::find_optional_resource_by_id::<types::Fingerprint>(
                self,
                super::kv::impls::fingerprint::FingerprintPrimaryKey { fingerprint_hash },
            )
            .await;
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;

            let query = types::Fingerprint::table()
                .filter(schema::fingerprint::fingerprint_hash.eq(fingerprint_hash.expose()));

            let pool = conn.pool();
            let operation = DbOperation::FindOne;
            super::log_db_query::<<types::Fingerprint as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let output = super::record_db_query_optional::<
                <types::Fingerprint as HasTable>::Table,
                _,
                _,
                _,
            >(
                async {
                    query
                        .get_result_async::<types::Fingerprint>(conn.get())
                        .await
                        .optional()
                },
                operation,
                pool,
            )
            .await?;

            Ok(output)
        }
    }

    async fn insert_fingerprint(
        &self,
        fingerprint_hash: Secret<Vec<u8>>,
        fingerprint_id: Secret<String>,
    ) -> Result<types::Fingerprint, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            // `id: 0` — serial unknown at KV-insert time, assigned by drainer on replay.
            // `updated_by: PostgresOnly` is a placeholder — overwritten by `set_storage_scheme`
            // in `insert_resource` before the model is written to Redis or PG.
            let finger_print_new = types::FingerprintTableNew {
                fingerprint_hash: fingerprint_hash.clone(),
                fingerprint_id,
                updated_by: Some(StorageScheme::PostgresOnly),
            };
            return super::kv::insert_resource::<types::Fingerprint>(self, finger_print_new).await;
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;

            let query = diesel::insert_into(types::Fingerprint::table()).values(
                types::FingerprintTableNew {
                    fingerprint_hash,
                    fingerprint_id,
                    updated_by: Some(StorageScheme::PostgresOnly),
                },
            );

            let pool = conn.pool();
            let operation = DbOperation::Insert;
            super::log_db_query::<<types::Fingerprint as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let output: types::Fingerprint =
                super::record_db_query::<<types::Fingerprint as HasTable>::Table, _, _, _>(
                    query.get_result_async(conn.get()),
                    operation,
                    pool,
                )
                .await?;

            Ok(output)
        }
    }
}

#[cfg(feature = "external_key_manager")]
impl super::EntityInterface for Storage {
    type Error = error::EntityDBError;

    async fn find_by_entity_id(
        &self,
        entity_id: &str,
    ) -> Result<types::Entity, ContainerError<Self::Error>> {
        // Reads are routed to the read replica when enabled.
        let conn = self.route_conn().await?;

        // A missing row surfaces as `EntityDBError::NotFoundError` (see the `From<diesel>`
        // classifier), which `find_or_create_entity` in the key manager checks via
        // `is_not_found()`.
        let query =
            types::Entity::table().filter(schema::entity::entity_id.eq(entity_id.to_owned()));

        let pool = conn.pool();
        let operation = DbOperation::FindOne;
        super::log_db_query::<<types::Entity as HasTable>::Table, _>(&query, operation, pool);

        let output: types::Entity = super::record_db_query::<
            <types::Entity as HasTable>::Table,
            _,
            _,
            _,
        >(query.get_result_async(conn.get()), operation, pool)
        .await?;

        Ok(output)
    }

    async fn insert_entity(
        &self,
        entity_id: &str,
        identifier: &str,
    ) -> Result<types::Entity, ContainerError<Self::Error>> {
        let conn = self.get_conn().await?;

        let query = diesel::insert_into(types::Entity::table()).values(types::EntityTableNew {
            entity_id: entity_id.into(),
            enc_key_id: identifier.into(),
        });

        let pool = conn.pool();
        let operation = DbOperation::Insert;
        super::log_db_query::<<types::Entity as HasTable>::Table, _>(&query, operation, pool);

        let output: types::Entity = super::record_db_query::<
            <types::Entity as HasTable>::Table,
            _,
            _,
            _,
        >(query.get_result_async(conn.get()), operation, pool)
        .await?;

        Ok(output)
    }
}

impl super::ReverseLookupInterface for Storage {
    type Error = error::ReverseLookupDBError;

    async fn insert_reverse_lookup(
        &self,
        new: types::ReverseLookupNew,
    ) -> Result<types::ReverseLookup, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            return Box::pin(super::kv::insert_resource::<types::ReverseLookup>(
                self, new,
            ))
            .await;
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;

            let query = diesel::insert_into(types::ReverseLookup::table()).values(new);

            let pool = conn.pool();
            let operation = DbOperation::Insert;
            super::log_db_query::<<types::ReverseLookup as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let reverse_lookup = super::record_db_query::<
                <types::ReverseLookup as HasTable>::Table,
                _,
                _,
                _,
            >(query.get_result_async(conn.get()), operation, pool)
            .await?;
            Ok(reverse_lookup)
        }
    }

    async fn delete_reverse_lookup(
        &self,
        lookup_id: &str,
    ) -> Result<usize, ContainerError<Self::Error>> {
        #[cfg(feature = "kv")]
        {
            return Box::pin(super::kv::delete_resource_by_id::<types::ReverseLookup>(
                self,
                super::kv::impls::reverse_lookup::ReverseLookupPrimaryKey {
                    lookup_id: lookup_id.to_string(),
                },
            ))
            .await;
        }

        #[cfg(not(feature = "kv"))]
        {
            let conn = self.get_conn().await?;
            let query = diesel::delete(types::ReverseLookup::table())
                .filter(schema::reverse_lookup::lookup_id.eq(lookup_id.to_owned()));

            let pool = conn.pool();
            let operation = DbOperation::Delete;
            super::log_db_query::<<types::ReverseLookup as HasTable>::Table, _>(
                &query, operation, pool,
            );

            let output = super::record_db_query_rows::<
                <types::ReverseLookup as HasTable>::Table,
                _,
                _,
            >(query.execute_async(conn.get()), operation, pool)
            .await?;
            Ok(output)
        }
    }
}

impl crate::audit::AuditInterface for Storage {
    /// Always writes straight to PostgreSQL, never through the KV store, so an entry cannot be
    /// lost in a Redis outage.
    async fn insert_audit_entry(
        &self,
        entry: crate::audit::AuditEntry,
    ) -> Result<(), ContainerError<error::StorageError>> {
        let conn = self.get_conn().await?;
        let query = diesel::insert_into(schema::audit_log::table).values(entry);

        let pool = conn.pool();
        let operation = DbOperation::Insert;
        super::log_db_query::<schema::audit_log::table, _>(&query, operation, pool);

        super::record_db_query::<schema::audit_log::table, _, _, _>(
            query.execute_async(conn.get()),
            operation,
            pool,
        )
        .await
        .change_error(error::StorageError::InsertError)?;

        Ok(())
    }
}
