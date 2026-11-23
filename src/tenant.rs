use std::{collections::HashSet, sync::Arc};

use rustc_hash::FxHashMap;
use tokio::sync::RwLock;

#[cfg(not(feature = "key_custodian"))]
use crate::config::TenantConfig;
#[cfg(feature = "key_custodian")]
use crate::routes::key_custodian::CustodianKeyState;
use crate::{
    api_client::ApiClient, app::TenantAppState, config::GlobalConfig, error::ApiError, logger,
    runtime_config::RuntimeConfigManager,
};

pub struct GlobalAppState {
    pub tenants_app_state: RwLock<FxHashMap<String, Arc<TenantAppState>>>,
    #[cfg(feature = "key_custodian")]
    pub tenants_key_state: RwLock<FxHashMap<String, CustodianKeyState>>,
    /// Audit-only storage per tenant, usable before the tenant is unlocked, so custodian steps can
    /// write their audit row. Created on the tenant's first custodian call.
    #[cfg(feature = "key_custodian")]
    pub tenants_audit_store: RwLock<FxHashMap<String, Arc<crate::storage::Storage>>>,
    pub api_client: ApiClient,
    pub known_tenants: HashSet<String>,
    pub global_config: GlobalConfig,
    #[cfg(feature = "redis")]
    pub redis_store: Option<crate::storage::redis::RedisStore>,
    pub storage_global_store: Arc<crate::storage::GlobalStore>,
    pub runtime_config_manager: Arc<RuntimeConfigManager>,
}

impl GlobalAppState {
    ///
    /// # Panics
    ///
    /// If tenant specific AppState construction fails when `key_custodian` feature is disabled
    ///
    pub async fn new(global_config: GlobalConfig) -> Arc<Self> {
        let known_tenants = global_config
            .tenant_secrets
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        #[cfg(feature = "key_custodian")]
        let tenants_key_state = {
            let mut tenants_key_state: FxHashMap<String, CustodianKeyState> = FxHashMap::default();
            for tenant in known_tenants.clone() {
                tenants_key_state.insert(tenant.clone(), CustodianKeyState::default());
            }
            tenants_key_state
        };

        #[allow(clippy::expect_used)]
        let api_client = ApiClient::new(&global_config).expect("Failed to create api client");

        // Shared pool; tenants derive key-prefixed handles.
        #[cfg(feature = "redis")]
        #[allow(clippy::expect_used)]
        let redis_store = match &global_config.redis {
            Some(conf) => Some(
                crate::storage::redis::RedisStore::new(conf)
                    .await
                    .inspect(|redis_conn| redis_conn.spawn_error_watcher())
                    .inspect_err(|err| {
                        crate::logger::error!(?err, "Failed to initialize Redis;");
                    })
                    .expect("Failed to initialize Redis"),
            ),
            None => None,
        };

        #[allow(clippy::expect_used)]
        let runtime_config_manager = Arc::new(
            RuntimeConfigManager::new(
                &global_config.runtime_config,
                global_config.api_client.client_idle_timeout,
                global_config.api_client.pool_max_idle_per_host,
            )
            .expect("Failed to create runtime config manager"),
        );

        let storage_global_store = Arc::new(crate::storage::GlobalStore::new(
            #[cfg(feature = "kv")]
            global_config.kv.clone(),
        ));

        let tenants_app_state = {
            #[cfg(feature = "key_custodian")]
            {
                FxHashMap::default()
            }
            #[cfg(not(feature = "key_custodian"))]
            {
                let mut tenants_app_state = FxHashMap::default();
                for tenant_id in known_tenants.clone() {
                    let tenant_config =
                        TenantConfig::from_global_config(&global_config, tenant_id.clone());
                    #[allow(clippy::expect_used)]
                    let tenant_app_state = TenantAppState::new(
                        &global_config,
                        tenant_config,
                        api_client.clone(),
                        #[cfg(feature = "redis")]
                        redis_store.as_ref(),
                        runtime_config_manager.clone(),
                        storage_global_store.clone(),
                    )
                    .await
                    .expect("Failed while configuring AppState for tenants");
                    tenants_app_state.insert(tenant_id.clone(), Arc::new(tenant_app_state));
                }
                tenants_app_state
            }
        };

        Arc::new(Self {
            tenants_app_state: RwLock::new(tenants_app_state),
            #[cfg(feature = "key_custodian")]
            tenants_key_state: RwLock::new(tenants_key_state),
            #[cfg(feature = "key_custodian")]
            tenants_audit_store: RwLock::new(FxHashMap::default()),
            api_client: api_client.clone(),
            known_tenants: HashSet::<String>::from_iter(known_tenants),
            global_config,
            #[cfg(feature = "redis")]
            redis_store,
            storage_global_store,
            runtime_config_manager,
        })
    }

    pub async fn get_app_state_of_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Arc<TenantAppState>, ApiError> {
        self.tenants_app_state
            .read()
            .await
            .get(tenant_id)
            .cloned()
            .ok_or(ApiError::CustodianLocked)
    }

    pub fn is_known_tenant(&self, tenant_id: &str) -> Result<(), ApiError> {
        self.known_tenants
            .contains(tenant_id)
            .then_some(())
            .ok_or(ApiError::TenantError("Invalid x-tenant-id"))
    }

    pub async fn set_app_state(&self, state: TenantAppState) {
        let mut write_guard = self.tenants_app_state.write().await;
        write_guard.insert(state.config.tenant_id.clone(), Arc::new(state));
    }

    pub async fn apply_runtime_config_updates(&self) {
        #[cfg(feature = "kv")]
        {
            self.storage_global_store
                .refresh_kv_state_from_runtime_config(
                    &self.runtime_config_manager,
                    self.redis_store.as_ref(),
                )
                .await;
        }

        self.storage_global_store
            .refresh_replica_state_from_runtime_config(&self.runtime_config_manager, || async {
                // `use_replica` is global, but replica availability is verified through a
                // tenant `Storage` because the replica pool is owned there. The health check is
                // evaluated lazily only when runtime config tries to enable replica reads.
                let tenant_app_state = self.tenants_app_state.read().await.values().next().cloned();
                match tenant_app_state {
                    Some(tenant_app_state) => tenant_app_state
                        .db
                        .get_replica_conn()
                        .await
                        .inspect_err(|err| {
                            logger::error!("Error while checking read replica connection: {}", err)
                        })
                        .is_ok(),
                    None => false,
                }
            })
            .await;
    }

    /// Storage used to write the audit rows of custodian steps, before the tenant is unlocked. It
    /// only needs the database settings, which the custodian keys do not protect. If it cannot be
    /// created, the step fails like any other failed audit write.
    #[cfg(feature = "key_custodian")]
    pub async fn custodian_audit_store(
        &self,
        tenant_id: &str,
    ) -> Result<Arc<crate::storage::Storage>, crate::error::ContainerError<ApiError>> {
        if let Some(store) = self.tenants_audit_store.read().await.get(tenant_id) {
            return Ok(Arc::clone(store));
        }

        let mut stores = self.tenants_audit_store.write().await;
        if let Some(store) = stores.get(tenant_id) {
            return Ok(Arc::clone(store));
        }

        let schema = &self
            .global_config
            .tenant_secrets
            .get(tenant_id)
            .ok_or(ApiError::TenantError("Invalid x-tenant-id"))?
            .schema;

        let store = crate::storage::Storage::new(
            &self.global_config.database,
            None,
            schema,
            self.runtime_config_manager.clone(),
            self.storage_global_store.clone(),
            #[cfg(feature = "redis")]
            None,
        )
        .await
        .map_err(|error| {
            logger::error!(?error, "failed to create the custodian audit storage");
            ApiError::DatabaseInsertFailed("audit_log")
        })?;

        let store = Arc::new(store);
        stores.insert(tenant_id.to_string(), Arc::clone(&store));
        Ok(store)
    }

    #[cfg(feature = "key_custodian")]
    // Check if the custodian is already unlocked for a tenant, if so raise an error when calling custodian endpoints
    pub async fn is_custodian_unlocked(&self, tenant_id: &str) -> Result<(), ApiError> {
        self.tenants_app_state
            .read()
            .await
            .contains_key(tenant_id)
            .then_some(Err::<(), ApiError>(ApiError::CustodianUnlocked))
            .transpose()?;
        Ok(())
    }
}
