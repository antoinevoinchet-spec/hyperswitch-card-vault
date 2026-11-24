pub mod types;

use std::sync::Arc;

use axum::{Json, extract::Query};
use error_stack::ResultExt;
use hyperswitch_masking::{PeekInterface, Secret};

use crate::{
    app::TenantAppState,
    audit,
    crypto::keymanager,
    custom_extractors::{AuditRequestId, OptionalCallerKey, TenantStateResolver, authorize_read},
    error::{self, ContainerError, ResultContainerExt},
    logger,
    observability::metrics,
    routes::data::{crypto_operation, types::Validation},
    storage::storage_v2::VaultInterface,
    utils,
};

#[tracing::instrument(skip_all)]
pub async fn delete_data(
    TenantStateResolver(tenant_app_state): TenantStateResolver,
    AuditRequestId(request_id): AuditRequestId,
    Json(request): Json<types::DeleteDataRequest>,
) -> Result<Json<types::DeleteDataResponse>, ContainerError<error::ApiError>> {
    let pending =
        audit::delete_data_audit(&tenant_app_state.config.tenant_id, request_id, &request);
    let result = delete_data_inner(Arc::clone(&tenant_app_state), request).await;
    audit::record(&tenant_app_state.db, pending, result).await
}

#[tracing::instrument(skip_all)]
async fn delete_data_inner(
    tenant_app_state: Arc<TenantAppState>,
    request: types::DeleteDataRequest,
) -> Result<Json<types::DeleteDataResponse>, ContainerError<error::ApiError>> {
    let _entity = keymanager::get_dek_manager(&tenant_app_state.config.external_key_manager)
        .find_by_entity_id(&tenant_app_state, request.entity_id.clone())
        .await?;

    let delete_status = tenant_app_state
        .db
        .delete_from_vault(request.vault_id.clone().into(), &request.entity_id)
        .await?;

    let response = Json(types::DeleteDataResponse {
        entity_id: request.entity_id,
        vault_id: request.vault_id.into(),
    });

    match delete_status {
        0 => logger::info!(delete_data_response = "data not found to delete"),
        _ => logger::info!(delete_data_response=?response, "delete data was successful"),
    }

    Ok(response)
}

#[tracing::instrument(skip_all)]
pub async fn retrieve_data(
    TenantStateResolver(tenant_app_state): TenantStateResolver,
    AuditRequestId(request_id): AuditRequestId,
    OptionalCallerKey(caller_key): OptionalCallerKey,
    Json(request): Json<types::RetrieveDataRequest>,
) -> Result<Json<types::RetrieveDataResponse>, ContainerError<error::ApiError>> {
    let pending =
        audit::retrieve_data_audit(&tenant_app_state.config.tenant_id, request_id, &request);
    let result = retrieve_data_inner(Arc::clone(&tenant_app_state), caller_key, request).await;
    audit::record(&tenant_app_state.db, pending, result).await
}

#[tracing::instrument(skip_all)]
async fn retrieve_data_inner(
    tenant_app_state: Arc<TenantAppState>,
    caller_key: Option<Secret<String>>,
    request: types::RetrieveDataRequest,
) -> Result<Json<types::RetrieveDataResponse>, ContainerError<error::ApiError>> {
    authorize_read(
        &tenant_app_state.config.tenant_secrets.callers,
        caller_key.as_ref(),
        &request.entity_id,
    )?;

    let crypto_manager = keymanager::get_dek_manager(&tenant_app_state.config.external_key_manager)
        .find_by_entity_id(&tenant_app_state, request.entity_id.clone())
        .await?;

    let vault_data = tenant_app_state
        .db
        .find_by_vault_id_entity_id(request.vault_id.clone().into(), &request.entity_id)
        .await?;

    let decrypted_data =
        crypto_operation::decrypt_data(&tenant_app_state, crypto_manager, vault_data).await?;

    decrypted_data
        .expires_at
        .map(|ttl| -> Result<(), error::ApiError> {
            if utils::date_time::now() > ttl {
                crate::routes::record_expired_data_encountered(metrics::Resource::Vault);

                tokio::spawn(async move {
                    let result = tenant_app_state
                        .db
                        .delete_from_vault(request.vault_id.into(), &request.entity_id)
                        .await;

                    crate::routes::record_ttl_deletion_result(
                        metrics::Resource::Vault,
                        if result.is_ok() {
                            metrics::TtlDeletionOutcome::Deleted
                        } else {
                            metrics::TtlDeletionOutcome::Failed
                        },
                    );
                });

                Err(error::ApiError::NotFoundError)
            } else {
                Ok(())
            }
        })
        .transpose()?;
    let decrypted_inner_data = decrypted_data
        .data
        .get_decrypted_inner_value()
        .ok_or(error::ApiError::UnknownError)
        .attach_printable("Failed to decrypt the stored data")?;
    let data_value = serde_json::from_slice(decrypted_inner_data.peek().as_ref())
        .change_error(error::ApiError::DecodingError)?;

    logger::info!(retrieve_data_response = "retrieve data was successful");

    Ok(Json(types::RetrieveDataResponse { data: data_value }))
}

#[tracing::instrument(skip_all)]
pub async fn add_data(
    TenantStateResolver(tenant_app_state): TenantStateResolver,
    AuditRequestId(request_id): AuditRequestId,
    Query(params): Query<types::StoreDataRequestQueryParams>,
    Json(request): Json<types::StoreDataRequest>,
) -> Result<Json<types::StoreDataResponse>, ContainerError<error::ApiError>> {
    let pending = audit::store_data_audit(&tenant_app_state.config.tenant_id, request_id, &request);
    let result = add_data_inner(Arc::clone(&tenant_app_state), params, request).await;
    audit::record(&tenant_app_state.db, pending, result).await
}

#[tracing::instrument(skip_all)]
async fn add_data_inner(
    tenant_app_state: Arc<TenantAppState>,
    params: types::StoreDataRequestQueryParams,
    request: types::StoreDataRequest,
) -> Result<Json<types::StoreDataResponse>, ContainerError<error::ApiError>> {
    request.validate()?;

    let crypto_manager = keymanager::get_dek_manager(&tenant_app_state.config.external_key_manager)
        .find_or_create_entity(&tenant_app_state, request.entity_id.clone())
        .await?;

    let insert_data = crypto_operation::encrypt_data_and_upsert_into_db_v2(
        &tenant_app_state,
        crypto_manager,
        request,
        params.mode,
    )
    .await?;

    let response = Json(types::StoreDataResponse::from(insert_data));
    logger::info!(add_data_response=?response, "add data was successful");

    Ok(response)
}
