//! Audit log: one metadata-only entry per vault operation.
//!
//! An entry records who did which operation, when, and with which outcome. It never holds the data
//! the vault protects: only identifiers already present in the request, a UTC timestamp and the
//! result. See `docs/superpowers/specs/2026-11-20-audit-log-design.md`.

use axum::response::IntoResponse;
use diesel::Insertable;

use crate::{
    error::{ApiError, ContainerError, StorageError},
    logger,
    storage::schema,
};

/// Longest identifier kept in an entry, matching the `VARCHAR(255)` columns.
const MAX_ID_LENGTH: usize = 255;

/// Value stored instead of an identifier that looks like a card number.
const REDACTED: &str = "redacted";

/// Operations recorded in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOperation {
    LockerAdd,
    LockerRetrieve,
    LockerDelete,
    Fingerprint,
    VaultAdd,
    VaultRetrieve,
    VaultDelete,
    EntityCreate,
    KeyTransfer,
    CustodianKey1,
    CustodianKey2,
    CustodianDecrypt,
}

impl AuditOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LockerAdd => "locker_add",
            Self::LockerRetrieve => "locker_retrieve",
            Self::LockerDelete => "locker_delete",
            Self::Fingerprint => "fingerprint",
            Self::VaultAdd => "vault_add",
            Self::VaultRetrieve => "vault_retrieve",
            Self::VaultDelete => "vault_delete",
            Self::EntityCreate => "entity_create",
            Self::KeyTransfer => "key_transfer",
            Self::CustodianKey1 => "custodian_key1",
            Self::CustodianKey2 => "custodian_key2",
            Self::CustodianDecrypt => "custodian_decrypt",
        }
    }
}

/// Keeps a request id only when it is a UUID, so a caller cannot put free text in the log.
pub fn parse_request_id(raw: Option<&str>) -> Option<String> {
    raw.and_then(|value| uuid::Uuid::parse_str(value).ok())
        .map(|id| id.hyphenated().to_string())
}

/// Whether `value` looks like a payment card number: 13 to 19 digits, once spaces and hyphens
/// are removed, that pass the Luhn checksum.
fn looks_like_card_number(value: &str) -> bool {
    let digits: Option<Vec<u32>> = value
        .chars()
        .filter(|c| *c != ' ' && *c != '-')
        .map(|c| c.to_digit(10))
        .collect();

    let Some(digits) = digits else {
        return false;
    };

    if !(13..=19).contains(&digits.len()) {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| {
            if index % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                *digit
            }
        })
        .sum();

    sum.is_multiple_of(10)
}

/// Caller-chosen identifier, without control characters (PostgreSQL rejects NUL, which would
/// make the audit write fail), truncated to the column size and redacted if it looks like a card
/// number.
fn safe_id(value: &str) -> String {
    let cleaned: String = value.chars().filter(|c| !c.is_control()).collect();
    if looks_like_card_number(&cleaned) {
        REDACTED.to_string()
    } else {
        cleaned.chars().take(MAX_ID_LENGTH).collect()
    }
}

/// One row of the `audit_log` table. Every field is metadata; see the design for why each one
/// exposes no protected data.
#[derive(Debug, Clone, serde::Serialize, Insertable)]
#[diesel(table_name = schema::audit_log)]
pub struct AuditEntry {
    pub audit_id: String,
    pub created_at: time::PrimitiveDateTime,
    pub request_id: Option<String>,
    pub tenant_id: String,
    pub operation: String,
    pub merchant_id: Option<String>,
    pub customer_id: Option<String>,
    pub resource_id: Option<String>,
    pub outcome: String,
    pub status_code: i16,
    pub error_type: Option<String>,
}

/// An audit entry being built before the operation's outcome is known.
#[derive(Debug, Clone)]
pub struct PendingAudit {
    tenant_id: String,
    request_id: Option<String>,
    operation: AuditOperation,
    merchant_id: Option<String>,
    customer_id: Option<String>,
    resource_id: Option<String>,
}

impl PendingAudit {
    pub fn new(tenant_id: &str, request_id: Option<String>, operation: AuditOperation) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            request_id,
            operation,
            merchant_id: None,
            customer_id: None,
            resource_id: None,
        }
    }

    #[must_use]
    pub fn merchant(mut self, id: &str) -> Self {
        self.merchant_id = Some(safe_id(id));
        self
    }

    #[must_use]
    pub fn customer(mut self, id: &str) -> Self {
        self.customer_id = Some(safe_id(id));
        self
    }

    #[must_use]
    pub fn resource(mut self, id: &str) -> Self {
        self.resource_id = Some(safe_id(id));
        self
    }

    /// Builds the entry from the operation's result. Only the error kind and HTTP status are kept,
    /// never the error message.
    pub fn finish<T>(self, result: &Result<T, ContainerError<ApiError>>) -> AuditEntry {
        let (outcome, status_code, error_type) = match result {
            Ok(_) => ("success", 200, None),
            Err(error) => {
                let api_error = *error.get_inner();
                let status = api_error.into_response().status().as_u16();
                let variant = format!("{api_error:?}");
                let name = variant.split('(').next().unwrap_or_default().to_string();
                (
                    "failure",
                    i16::try_from(status).unwrap_or(i16::MAX),
                    Some(name),
                )
            }
        };

        AuditEntry {
            audit_id: uuid::Uuid::now_v7().to_string(),
            created_at: crate::utils::date_time::now(),
            request_id: self.request_id,
            tenant_id: self.tenant_id,
            operation: self.operation.as_str().to_string(),
            merchant_id: self.merchant_id,
            customer_id: self.customer_id,
            resource_id: self.resource_id,
            outcome: outcome.to_string(),
            status_code,
            error_type,
        }
    }
}

/// Destination of audit entries. Append-only: there is no update, delete or read method.
pub(crate) trait AuditInterface {
    async fn insert_audit_entry(
        &self,
        entry: AuditEntry,
    ) -> Result<(), ContainerError<StorageError>>;
}

/// Writes the audit entry for `result`, then returns `result`. If the entry cannot be written,
/// the operation's response is replaced by an error: no data leaves the vault without a trace.
pub(crate) async fn record<S: AuditInterface, T>(
    sink: &S,
    pending: PendingAudit,
    result: Result<T, ContainerError<ApiError>>,
) -> Result<T, ContainerError<ApiError>> {
    let entry = pending.finish(&result);
    let operation = entry.operation.clone();
    let audit_id = entry.audit_id.clone();
    let tenant_id = entry.tenant_id.clone();
    let request_id = entry.request_id.clone().unwrap_or_default();

    match sink.insert_audit_entry(entry).await {
        Ok(()) => result,
        Err(_) => {
            logger::error!(
                audit = true,
                operation = %operation,
                audit_id = %audit_id,
                tenant_id = %tenant_id,
                request_id = %request_id,
                "failed to write audit entry; operation response withheld"
            );
            Err(ApiError::DatabaseInsertFailed("audit_log").into())
        }
    }
}

/// Entry for `/data/add` and `/cards/add`. The stored reference is added from the response.
pub fn store_card_audit(
    tenant_id: &str,
    request_id: Option<String>,
    request: &crate::routes::data::types::StoreCardRequest,
) -> PendingAudit {
    PendingAudit::new(tenant_id, request_id, AuditOperation::LockerAdd)
        .merchant(&request.merchant_id)
        .customer(&request.merchant_customer_id)
}

/// Entry for `/data/retrieve` and `/cards/retrieve`.
pub fn retrieve_card_audit(
    tenant_id: &str,
    request_id: Option<String>,
    request: &crate::routes::data::types::RetrieveCardRequest,
) -> PendingAudit {
    PendingAudit::new(tenant_id, request_id, AuditOperation::LockerRetrieve)
        .merchant(&request.merchant_id)
        .customer(&request.merchant_customer_id)
        .resource(&request.card_reference)
}

/// Entry for `/data/delete` and `/cards/delete`.
pub fn delete_card_audit(
    tenant_id: &str,
    request_id: Option<String>,
    request: &crate::routes::data::types::DeleteCardRequest,
) -> PendingAudit {
    PendingAudit::new(tenant_id, request_id, AuditOperation::LockerDelete)
        .merchant(&request.merchant_id)
        .customer(&request.merchant_customer_id)
        .resource(&request.card_reference)
}

/// Entry for the fingerprint routes. It takes no request, so nothing from the payload (data,
/// key, labels) can reach the log.
pub fn fingerprint_audit(tenant_id: &str, request_id: Option<String>) -> PendingAudit {
    PendingAudit::new(tenant_id, request_id, AuditOperation::Fingerprint)
}

/// Entry for `/api/v2/vault/add`.
pub fn store_data_audit(
    tenant_id: &str,
    request_id: Option<String>,
    request: &crate::routes::routes_v2::data::types::StoreDataRequest,
) -> PendingAudit {
    PendingAudit::new(tenant_id, request_id, AuditOperation::VaultAdd)
        .merchant(&request.entity_id)
        .resource(&request.vault_id)
}

/// Entry for `/api/v2/vault/retrieve`.
pub fn retrieve_data_audit(
    tenant_id: &str,
    request_id: Option<String>,
    request: &crate::routes::routes_v2::data::types::RetrieveDataRequest,
) -> PendingAudit {
    PendingAudit::new(tenant_id, request_id, AuditOperation::VaultRetrieve)
        .merchant(&request.entity_id)
        .resource(&request.vault_id)
}

/// Entry for `/api/v2/vault/delete`.
pub fn delete_data_audit(
    tenant_id: &str,
    request_id: Option<String>,
    request: &crate::routes::routes_v2::data::types::DeleteDataRequest,
) -> PendingAudit {
    PendingAudit::new(tenant_id, request_id, AuditOperation::VaultDelete)
        .merchant(&request.entity_id)
        .resource(&request.vault_id)
}

/// Entry for `/entity`.
pub fn entity_audit(
    tenant_id: &str,
    request_id: Option<String>,
    request: &crate::routes::entity::CreateEntityRequest,
) -> PendingAudit {
    PendingAudit::new(tenant_id, request_id, AuditOperation::EntityCreate)
        .merchant(&request.entity_id)
}

/// Entry for `/key/transfer`. The request only holds a batch size, so no identifier is kept.
pub fn key_transfer_audit(tenant_id: &str, request_id: Option<String>) -> PendingAudit {
    PendingAudit::new(tenant_id, request_id, AuditOperation::KeyTransfer)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Mutex;

    use axum::response::IntoResponse;

    use super::*;
    use crate::error::{ApiError, ContainerError, StorageError};

    #[derive(Default)]
    struct MemorySink(Mutex<Vec<AuditEntry>>);

    impl AuditInterface for MemorySink {
        async fn insert_audit_entry(
            &self,
            entry: AuditEntry,
        ) -> Result<(), ContainerError<StorageError>> {
            self.0.lock().unwrap().push(entry);
            Ok(())
        }
    }

    struct FailingSink;

    impl AuditInterface for FailingSink {
        async fn insert_audit_entry(
            &self,
            _entry: AuditEntry,
        ) -> Result<(), ContainerError<StorageError>> {
            Err(StorageError::InsertError.into())
        }
    }

    fn only_entry(sink: &MemorySink) -> AuditEntry {
        let entries = sink.0.lock().unwrap();
        assert_eq!(entries.len(), 1);
        entries[0].clone()
    }

    #[tokio::test]
    async fn record_writes_success_entry() {
        let sink = MemorySink::default();
        let before = crate::utils::date_time::now();
        let pending = PendingAudit::new("public", None, AuditOperation::LockerRetrieve)
            .merchant("m1")
            .customer("c1")
            .resource("r1");

        let result = record(&sink, pending, Ok::<_, ContainerError<ApiError>>(7)).await;
        let after = crate::utils::date_time::now();

        assert_eq!(result.unwrap(), 7);
        let entry = only_entry(&sink);
        assert_eq!(entry.operation, "locker_retrieve");
        assert_eq!(entry.outcome, "success");
        assert_eq!(entry.status_code, 200);
        assert_eq!(entry.error_type, None);
        assert_eq!(entry.tenant_id, "public");
        assert_eq!(entry.merchant_id.as_deref(), Some("m1"));
        assert_eq!(entry.customer_id.as_deref(), Some("c1"));
        assert_eq!(entry.resource_id.as_deref(), Some("r1"));
        assert!(before <= entry.created_at && entry.created_at <= after);
    }

    #[tokio::test]
    async fn record_writes_failure_entry() {
        let sink = MemorySink::default();
        let pending = PendingAudit::new("public", None, AuditOperation::VaultRetrieve);

        let result: Result<(), _> =
            record(&sink, pending, Err(ApiError::NotFoundError.into())).await;

        assert!(matches!(
            result.unwrap_err().get_inner(),
            ApiError::NotFoundError
        ));
        let entry = only_entry(&sink);
        assert_eq!(entry.outcome, "failure");
        assert_eq!(entry.status_code, 404);
        assert_eq!(entry.error_type.as_deref(), Some("NotFoundError"));
    }

    #[tokio::test]
    async fn record_maps_validation_error_to_400() {
        let sink = MemorySink::default();
        let pending = PendingAudit::new("public", None, AuditOperation::EntityCreate);

        let result: Result<(), _> = record(
            &sink,
            pending,
            Err(ApiError::ValidationError("entity_id must not be empty").into()),
        )
        .await;

        assert!(result.is_err());
        let entry = only_entry(&sink);
        assert_eq!(entry.status_code, 400);
        assert_eq!(entry.error_type.as_deref(), Some("ValidationError"));
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("must not be empty"));
    }

    #[tokio::test]
    async fn record_fails_closed_when_sink_fails() {
        let pending = PendingAudit::new("public", None, AuditOperation::LockerRetrieve);

        let result = record(&FailingSink, pending, Ok::<_, ContainerError<ApiError>>(7)).await;

        let error = result.unwrap_err();
        assert!(matches!(
            error.get_inner(),
            ApiError::DatabaseInsertFailed("audit_log")
        ));
        assert_eq!(
            error.into_response().status(),
            hyper::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn parse_request_id_rejects_non_uuid() {
        assert_eq!(parse_request_id(Some("4111111111111111")), None);
        assert_eq!(parse_request_id(None), None);
        let id = uuid::Uuid::now_v7().to_string();
        assert_eq!(parse_request_id(Some(&id)), Some(id));
    }

    #[test]
    fn pending_truncates_long_ids() {
        let long = "a".repeat(300);
        let entry = PendingAudit::new("public", None, AuditOperation::LockerAdd)
            .merchant(&long)
            .customer(&long)
            .resource(&long)
            .finish(&Ok::<(), ContainerError<ApiError>>(()));

        let expected = "a".repeat(255);
        assert_eq!(entry.merchant_id.as_deref(), Some(expected.as_str()));
        assert_eq!(entry.customer_id.as_deref(), Some(expected.as_str()));
        assert_eq!(entry.resource_id.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn pending_redacts_card_shaped_ids() {
        let entry = PendingAudit::new("public", None, AuditOperation::LockerAdd)
            .merchant("4111111111111111")
            .customer("4111 1111 1111 1111")
            .resource("4111-1111-1111-1111")
            .finish(&Ok::<(), ContainerError<ApiError>>(()));

        assert_eq!(entry.merchant_id.as_deref(), Some("redacted"));
        assert_eq!(entry.customer_id.as_deref(), Some("redacted"));
        assert_eq!(entry.resource_id.as_deref(), Some("redacted"));
        assert!(
            !serde_json::to_string(&entry)
                .unwrap()
                .contains("4111111111111111")
        );

        let kept = PendingAudit::new("public", None, AuditOperation::LockerAdd)
            .merchant("merchant_123")
            .finish(&Ok::<(), ContainerError<ApiError>>(()));
        assert_eq!(kept.merchant_id.as_deref(), Some("merchant_123"));
    }

    #[test]
    fn store_card_entry_never_contains_card_number() {
        let request: crate::routes::data::types::StoreCardRequest =
            serde_json::from_value(serde_json::json!({
                "merchant_id": "merchant_abc",
                "merchant_customer_id": "customer_xyz",
                "requestor_card_reference": null,
                "card": { "card_number": "4111111111111111" },
                "ttl": null
            }))
            .unwrap();

        let entry = store_card_audit("public", None, &request)
            .finish(&Ok::<(), ContainerError<ApiError>>(()));

        let json = serde_json::to_string(&entry).unwrap();
        let debug = format!("{entry:?}");
        assert!(!json.contains("4111111111111111"));
        assert!(!debug.contains("4111111111111111"));
        assert!(json.contains("merchant_abc"));
        assert!(debug.contains("merchant_abc"));
    }

    #[test]
    fn fingerprint_entry_has_no_payload() {
        let request: crate::routes::data::types::FingerprintRequest =
            serde_json::from_value(serde_json::json!({
                "batch_data": [{
                    "label": "4111111111111111",
                    "data": "4111111111111111",
                    "key": "secret-key-value"
                }]
            }))
            .unwrap();
        assert!(request.batch_data.is_some());

        let entry =
            fingerprint_audit("public", None).finish(&Ok::<(), ContainerError<ApiError>>(()));

        let json = serde_json::to_string(&entry).unwrap();
        let debug = format!("{entry:?}");
        for secret in ["4111111111111111", "secret-key-value"] {
            assert!(!json.contains(secret));
            assert!(!debug.contains(secret));
        }
        assert_eq!(entry.operation, "fingerprint");
    }

    #[test]
    fn store_data_entry_never_contains_payload() {
        let request: crate::routes::routes_v2::data::types::StoreDataRequest =
            serde_json::from_value(serde_json::json!({
                "entity_id": "entity_abc",
                "vault_id": "vault_123",
                "data": { "card_number": "4111111111111111" },
                "ttl": null
            }))
            .unwrap();

        let entry = store_data_audit("public", None, &request)
            .finish(&Ok::<(), ContainerError<ApiError>>(()));

        let json = serde_json::to_string(&entry).unwrap();
        let debug = format!("{entry:?}");
        assert!(!json.contains("4111111111111111"));
        assert!(!debug.contains("4111111111111111"));
        assert!(json.contains("vault_123"));
        assert_eq!(entry.operation, "vault_add");
        assert_eq!(entry.merchant_id.as_deref(), Some("entity_abc"));
    }

    #[test]
    fn pending_strips_control_characters() {
        let entry = PendingAudit::new("public", None, AuditOperation::LockerRetrieve)
            .merchant("m\u{0}1")
            .customer("c\n1")
            .resource("r\u{7}1")
            .finish(&Ok::<(), ContainerError<ApiError>>(()));

        assert_eq!(entry.merchant_id.as_deref(), Some("m1"));
        assert_eq!(entry.customer_id.as_deref(), Some("c1"));
        assert_eq!(entry.resource_id.as_deref(), Some("r1"));
    }
}
