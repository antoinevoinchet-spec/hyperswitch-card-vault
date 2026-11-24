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

/// What a caller asks to do with the data of a merchant (a v2 entity alike).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerRight {
    Read,
    Add,
    Delete,
}

impl CallerRight {
    /// The word that grants this right in a caller's `rights`.
    fn word(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Add => "add",
            Self::Delete => "delete",
        }
    }
}

/// Decides whether a caller may use `right` on the data of `merchant_id` (a v2 `entity_id` alike).
///
/// A tenant with no caller configured refuses every call (decision D-A of T37). Otherwise the key
/// must match one caller (by its SHA-256), and one caller with that key must list both
/// `merchant_id` in its merchants and the word of `right` in its rights. Runs before any key or row
/// is loaded.
pub fn authorize_caller(
    callers: &std::collections::HashMap<String, CallerConfig>,
    caller_key: Option<&Secret<String>>,
    merchant_id: &str,
    right: CallerRight,
) -> Result<(), ApiError> {
    let key = caller_key.ok_or(ApiError::CallerKeyMissingOrUnknown)?;
    let key_hash = hex::encode(ring::digest::digest(
        &ring::digest::SHA256,
        key.peek().as_bytes(),
    ));
    // Every caller with this key counts, so two entries sharing a key do not depend on map order;
    // a merchant and a right must come from the same entry.
    let mut matching = callers
        .values()
        .filter(|caller| *caller.key_hash.peek() == key_hash)
        .peekable();
    if matching.peek().is_none() {
        return Err(ApiError::CallerKeyMissingOrUnknown);
    }
    let lists = |list: &str, wanted: &str| {
        list.split(',')
            .any(|item| !item.is_empty() && item == wanted)
    };
    if matching
        .any(|caller| lists(&caller.merchants, merchant_id) && lists(&caller.rights, right.word()))
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

    use super::{CallerRight, OptionalCallerKey, authorize_caller};
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
                key_hash: sha256_hex(KEY).into(),
                merchants: merchants.to_string(),
                rights: "read".to_string(),
            },
        )])
    }

    fn key(value: &str) -> Secret<String> {
        Secret::new(value.to_string())
    }

    const ALL: [CallerRight; 3] = [CallerRight::Read, CallerRight::Add, CallerRight::Delete];

    fn caller_with_rights(merchants: &str, rights: &str) -> HashMap<String, CallerConfig> {
        let mut map = callers(merchants);
        map.get_mut("reader").unwrap().rights = rights.to_string();
        map
    }

    #[test]
    fn authorize_caller_refuses_every_call_without_callers() {
        for right in ALL {
            for key in [None, Some(&key(KEY))] {
                assert!(matches!(
                    authorize_caller(&HashMap::new(), key, "m1", right),
                    Err(ApiError::CallerKeyMissingOrUnknown)
                ));
            }
        }
    }

    #[test]
    fn authorize_caller_allows_only_the_listed_rights() {
        for granted in ALL {
            let map = caller_with_rights("m1", granted.word());
            for asked in ALL {
                let result = authorize_caller(&map, Some(&key(KEY)), "m1", asked);
                if asked == granted {
                    assert!(result.is_ok(), "{granted:?} allows {asked:?} for m1");
                } else {
                    assert!(matches!(result, Err(ApiError::CallerNotAllowed)));
                }
                // An unlisted merchant stays refused whatever the right.
                assert!(matches!(
                    authorize_caller(&map, Some(&key(KEY)), "m2", asked),
                    Err(ApiError::CallerNotAllowed)
                ));
            }
        }
        let none = caller_with_rights("m1", "");
        for asked in ALL {
            assert!(matches!(
                authorize_caller(&none, Some(&key(KEY)), "m1", asked),
                Err(ApiError::CallerNotAllowed)
            ));
        }
    }

    #[test]
    fn authorize_caller_reads_by_default() {
        let config: CallerConfig = serde_json::from_value(
            serde_json::json!({ "key_hash": sha256_hex(KEY), "merchants": "m1" }),
        )
        .unwrap();
        let map = HashMap::from([("reader".to_string(), config)]);
        assert!(authorize_caller(&map, Some(&key(KEY)), "m1", CallerRight::Read).is_ok());
        for asked in [CallerRight::Add, CallerRight::Delete] {
            assert!(matches!(
                authorize_caller(&map, Some(&key(KEY)), "m1", asked),
                Err(ApiError::CallerNotAllowed)
            ));
        }
    }

    #[test]
    fn authorize_caller_ignores_unknown_rights() {
        let typo = caller_with_rights("m1", "write");
        for asked in ALL {
            assert!(matches!(
                authorize_caller(&typo, Some(&key(KEY)), "m1", asked),
                Err(ApiError::CallerNotAllowed)
            ));
        }
        // With a space, only the word spelled exactly counts: `read` is granted, ` add` is not.
        let spaced = caller_with_rights("m1", "read, add");
        assert!(authorize_caller(&spaced, Some(&key(KEY)), "m1", CallerRight::Read).is_ok());
        assert!(matches!(
            authorize_caller(&spaced, Some(&key(KEY)), "m1", CallerRight::Add),
            Err(ApiError::CallerNotAllowed)
        ));
    }

    #[test]
    fn authorize_caller_does_not_mix_two_callers_rights() {
        let mut two = caller_with_rights("m1", "add");
        two.insert(
            "second".to_string(),
            CallerConfig {
                key_hash: sha256_hex(KEY).into(),
                merchants: "m2".to_string(),
                rights: "delete".to_string(),
            },
        );
        for _ in 0..20 {
            assert!(matches!(
                authorize_caller(&two, Some(&key(KEY)), "m2", CallerRight::Add),
                Err(ApiError::CallerNotAllowed)
            ));
            assert!(matches!(
                authorize_caller(&two, Some(&key(KEY)), "m1", CallerRight::Delete),
                Err(ApiError::CallerNotAllowed)
            ));
            assert!(authorize_caller(&two, Some(&key(KEY)), "m1", CallerRight::Add).is_ok());
            assert!(authorize_caller(&two, Some(&key(KEY)), "m2", CallerRight::Delete).is_ok());
        }
    }

    #[test]
    fn authorize_read_refuses_a_missing_key() {
        assert!(matches!(
            authorize_caller(&callers("m1"), None, "m1", CallerRight::Read),
            Err(ApiError::CallerKeyMissingOrUnknown)
        ));
    }

    #[test]
    fn authorize_read_refuses_an_unknown_key() {
        assert!(matches!(
            authorize_caller(
                &callers("m1"),
                Some(&key("another-key")),
                "m1",
                CallerRight::Read
            ),
            Err(ApiError::CallerKeyMissingOrUnknown)
        ));
    }

    #[test]
    fn authorize_read_allows_a_listed_merchant() {
        assert!(
            authorize_caller(&callers("m1,m2"), Some(&key(KEY)), "m2", CallerRight::Read).is_ok()
        );
    }

    #[test]
    fn authorize_read_refuses_an_unlisted_merchant() {
        assert!(matches!(
            authorize_caller(&callers("m1"), Some(&key(KEY)), "m2", CallerRight::Read),
            Err(ApiError::CallerNotAllowed)
        ));
        // A prefix or a part of a listed id is not that id.
        assert!(matches!(
            authorize_caller(&callers("m10"), Some(&key(KEY)), "m1", CallerRight::Read),
            Err(ApiError::CallerNotAllowed)
        ));
    }

    #[test]
    fn authorize_read_with_an_empty_list_refuses_every_merchant() {
        assert!(matches!(
            authorize_caller(&callers(""), Some(&key(KEY)), "", CallerRight::Read),
            Err(ApiError::CallerNotAllowed)
        ));
        assert!(matches!(
            authorize_caller(&callers(""), Some(&key(KEY)), "m1", CallerRight::Read),
            Err(ApiError::CallerNotAllowed)
        ));
    }

    #[test]
    fn authorize_read_needs_the_exact_key_hash() {
        let mut upper = callers("m1");
        upper.get_mut("reader").unwrap().key_hash = sha256_hex(KEY).to_uppercase().into();
        assert!(matches!(
            authorize_caller(&upper, Some(&key(KEY)), "m1", CallerRight::Read),
            Err(ApiError::CallerKeyMissingOrUnknown)
        ));
    }

    #[test]
    fn authorize_read_with_two_callers_sharing_a_key_uses_both_lists() {
        let mut two = callers("m1");
        two.insert(
            "second".to_string(),
            CallerConfig {
                key_hash: sha256_hex(KEY).into(),
                merchants: "m2".to_string(),
                rights: "read".to_string(),
            },
        );
        // Whatever order the map yields, each listed merchant is allowed.
        for _ in 0..20 {
            assert!(authorize_caller(&two, Some(&key(KEY)), "m1", CallerRight::Read).is_ok());
            assert!(authorize_caller(&two, Some(&key(KEY)), "m2", CallerRight::Read).is_ok());
        }
    }

    #[test]
    fn caller_config_debug_hides_the_key_hash() {
        let printed = format!("{:?}", callers("m1"));
        assert!(!printed.contains(&sha256_hex(KEY)));
    }

    #[test]
    fn caller_key_debug_hides_the_key() {
        let printed = format!("{:?}", OptionalCallerKey(Some(key(KEY))));
        assert!(!printed.contains(KEY));
    }
}
