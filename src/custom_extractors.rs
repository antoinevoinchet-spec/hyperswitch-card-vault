use std::sync::Arc;

use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use hyperswitch_masking::{PeekInterface, Secret};

use crate::{
    app::TenantAppState,
    config::CallerConfig,
    error::{ApiError, ContainerError},
    storage::consts,
    tenant::GlobalAppState,
};

#[derive(Clone)]
pub struct TenantStateResolver(pub Arc<TenantAppState>);

#[async_trait]
impl FromRequestParts<Arc<GlobalAppState>> for TenantStateResolver {
    type Rejection = ContainerError<ApiError>;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<GlobalAppState>,
    ) -> Result<Self, Self::Rejection> {
        let tenant_id = parts
            .headers
            .get(consts::X_TENANT_ID)
            .and_then(|h| h.to_str().ok())
            .ok_or(ApiError::TenantError("x-tenant-id not found in headers"))?;

        state.is_known_tenant(tenant_id)?;
        Ok(Self(state.get_app_state_of_tenant(tenant_id).await?))
    }
}

#[cfg(feature = "key_custodian")]
#[derive(Debug)]
pub struct TenantId(pub String);

#[cfg(feature = "key_custodian")]
#[async_trait]
impl FromRequestParts<Arc<GlobalAppState>> for TenantId {
    type Rejection = ContainerError<ApiError>;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<GlobalAppState>,
    ) -> Result<Self, Self::Rejection> {
        let tenant_id = parts
            .headers
            .get(consts::X_TENANT_ID)
            .and_then(|h| h.to_str().ok())
            .map(ToString::to_string)
            .ok_or(ApiError::TenantError("x-tenant-id not found in header"))?;

        state.is_known_tenant(&tenant_id)?;
        state.is_custodian_unlocked(&tenant_id).await?;

        Ok(Self(tenant_id))
    }
}

/// Optionally reads `x-fingerprint-id` from request headers.
/// If present, the value must be exactly 20 alphanumeric (0-9 a-z A-Z) characters,
/// matching the format of server-generated fingerprint IDs.
#[derive(Debug)]
pub struct OptionalFingerprintId(pub Option<Secret<String>>);

#[async_trait]
impl FromRequestParts<Arc<GlobalAppState>> for OptionalFingerprintId {
    type Rejection = ContainerError<ApiError>;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<GlobalAppState>,
    ) -> Result<Self, Self::Rejection> {
        let fingerprint_id = parts
            .headers
            .get(consts::X_FINGERPRINT_ID)
            .and_then(|h| h.to_str().ok())
            .map(|s| -> Result<Secret<String>, ContainerError<ApiError>> {
                if s.len() != consts::ID_LENGTH || !s.chars().all(|c| c.is_ascii_alphanumeric()) {
                    Err(ContainerError::from(ApiError::ValidationError(
                        "x-fingerprint-id must be exactly 20 alphanumeric characters",
                    )))
                } else {
                    Ok(Secret::new(s.to_string()))
                }
            })
            .transpose()?;

        Ok(Self(fingerprint_id))
    }
}

/// The `x-request-id` header, kept for the audit log only when it is a UUID. Never rejects.
#[derive(Debug)]
pub struct AuditRequestId(pub Option<String>);

#[async_trait]
impl FromRequestParts<Arc<GlobalAppState>> for AuditRequestId {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<GlobalAppState>,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(crate::audit::parse_request_id(
            parts
                .headers
                .get(consts::X_REQUEST_ID)
                .and_then(|h| h.to_str().ok()),
        )))
    }
}

/// The `x-vault-caller-key` header, if present. Its `Debug` output masks the key.
#[derive(Debug)]
pub struct OptionalCallerKey(pub Option<Secret<String>>);

#[async_trait]
impl FromRequestParts<Arc<GlobalAppState>> for OptionalCallerKey {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<GlobalAppState>,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .headers
                .get(consts::X_VAULT_CALLER_KEY)
                .and_then(|h| h.to_str().ok())
                .map(|key| Secret::new(key.to_string())),
        ))
    }
}

/// Decides whether a caller may read the data of `merchant_id` (a v2 `entity_id` alike).
///
/// With no caller configured for the tenant, every read is allowed, as before this check existed.
/// Otherwise the key must match one caller (by its SHA-256) and `merchant_id` must be on that
/// caller's list. Runs before any key or row is loaded.
pub fn authorize_read(
    callers: &std::collections::HashMap<String, CallerConfig>,
    caller_key: Option<&Secret<String>>,
    merchant_id: &str,
) -> Result<(), ApiError> {
    if callers.is_empty() {
        return Ok(());
    }
    let key = caller_key.ok_or(ApiError::CallerKeyMissingOrUnknown)?;
    let key_hash = hex::encode(ring::digest::digest(
        &ring::digest::SHA256,
        key.peek().as_bytes(),
    ));
    let caller = callers
        .values()
        .find(|caller| caller.key_hash == key_hash)
        .ok_or(ApiError::CallerKeyMissingOrUnknown)?;
    if caller
        .merchants
        .split(',')
        .any(|allowed| !allowed.is_empty() && allowed == merchant_id)
    {
        Ok(())
    } else {
        Err(ApiError::CallerNotAllowed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod caller_tests {
    use std::collections::HashMap;

    use hyperswitch_masking::Secret;

    use super::{OptionalCallerKey, authorize_read};
    use crate::{config::CallerConfig, error::ApiError};

    const KEY: &str = "caller-key-for-unit-tests-only";

    fn sha256_hex(value: &str) -> String {
        hex::encode(ring::digest::digest(
            &ring::digest::SHA256,
            value.as_bytes(),
        ))
    }

    fn callers(merchants: &str) -> HashMap<String, CallerConfig> {
        HashMap::from([(
            "reader".to_string(),
            CallerConfig {
                key_hash: sha256_hex(KEY),
                merchants: merchants.to_string(),
            },
        )])
    }

    fn key(value: &str) -> Secret<String> {
        Secret::new(value.to_string())
    }

    #[test]
    fn authorize_read_allows_any_read_without_callers() {
        assert!(authorize_read(&HashMap::new(), None, "m1").is_ok());
    }

    #[test]
    fn authorize_read_refuses_a_missing_key() {
        assert!(matches!(
            authorize_read(&callers("m1"), None, "m1"),
            Err(ApiError::CallerKeyMissingOrUnknown)
        ));
    }

    #[test]
    fn authorize_read_refuses_an_unknown_key() {
        assert!(matches!(
            authorize_read(&callers("m1"), Some(&key("another-key")), "m1"),
            Err(ApiError::CallerKeyMissingOrUnknown)
        ));
    }

    #[test]
    fn authorize_read_allows_a_listed_merchant() {
        assert!(authorize_read(&callers("m1,m2"), Some(&key(KEY)), "m2").is_ok());
    }

    #[test]
    fn authorize_read_refuses_an_unlisted_merchant() {
        assert!(matches!(
            authorize_read(&callers("m1"), Some(&key(KEY)), "m2"),
            Err(ApiError::CallerNotAllowed)
        ));
        // A prefix or a part of a listed id is not that id.
        assert!(matches!(
            authorize_read(&callers("m10"), Some(&key(KEY)), "m1"),
            Err(ApiError::CallerNotAllowed)
        ));
    }

    #[test]
    fn authorize_read_with_an_empty_list_refuses_every_merchant() {
        assert!(matches!(
            authorize_read(&callers(""), Some(&key(KEY)), ""),
            Err(ApiError::CallerNotAllowed)
        ));
        assert!(matches!(
            authorize_read(&callers(""), Some(&key(KEY)), "m1"),
            Err(ApiError::CallerNotAllowed)
        ));
    }

    #[test]
    fn authorize_read_needs_the_exact_key_hash() {
        let mut upper = callers("m1");
        upper.get_mut("reader").unwrap().key_hash = sha256_hex(KEY).to_uppercase();
        assert!(matches!(
            authorize_read(&upper, Some(&key(KEY)), "m1"),
            Err(ApiError::CallerKeyMissingOrUnknown)
        ));
    }

    #[test]
    fn caller_key_debug_hides_the_key() {
        let printed = format!("{:?}", OptionalCallerKey(Some(key(KEY))));
        assert!(!printed.contains(KEY));
    }
}
