use hyperswitch_masking::{ExposeInterface, PeekInterface};

use super::types::{self, DataDuplicationCheck};
use crate::{
    crypto::hash_manager::hash_interface::Encode,
    error::{self, ContainerError, ResultContainerExt},
    storage,
};

impl From<(Option<DataDuplicationCheck>, storage::types::Locker)>
    for super::types::StoreCardResponse
{
    fn from(
        (duplication_check, value): (Option<DataDuplicationCheck>, storage::types::Locker),
    ) -> Self {
        Self {
            status: types::Status::Ok,
            payload: Some(super::types::StoreCardRespPayload {
                card_reference: value.locker_id.expose(),
                duplication_check,
                dedup: None,
            }),
        }
    }
}

impl From<storage::storage_v2::types::Vault>
    for crate::routes::routes_v2::data::types::StoreDataResponse
{
    fn from(value: storage::storage_v2::types::Vault) -> Self {
        Self {
            entity_id: value.entity_id,
            vault_id: value.vault_id,
        }
    }
}

impl TryFrom<storage::types::Locker> for super::types::RetrieveCardResponse {
    type Error = ContainerError<error::ApiError>;
    fn try_from(value: storage::types::Locker) -> Result<Self, Self::Error> {
        let decrypted_data = value
            .data
            .get_decrypted_inner_value()
            .ok_or::<ContainerError<_>>(error::ApiError::DecodingError.into())?;
        let (card, enc_card_data) =
            match serde_json::from_slice::<types::StoredData>(decrypted_data.peek())
                .change_error(error::ApiError::DecodingError)?
            {
                types::StoredData::EncData(data) => (None, Some(data)),
                types::StoredData::CardData(card) => (Some(card), None),
            };

        Ok(Self {
            status: types::Status::Ok,
            payload: Some(super::types::RetrieveCardRespPayload {
                card,
                enc_card_data,
            }),
        })
    }
}

impl From<storage::types::Fingerprint> for super::types::FingerprintResponse {
    fn from(value: storage::types::Fingerprint) -> Self {
        Self::Single {
            fingerprint_id: value.fingerprint_id,
        }
    }
}

impl std::cmp::PartialEq<types::Data> for super::types::StoredData {
    fn eq(&self, other: &types::Data) -> bool {
        match (self, other) {
            (Self::EncData(request_enc_card_data), types::Data::EncData { enc_card_data }) => {
                request_enc_card_data == enc_card_data
            }
            (Self::CardData(request_card), types::Data::Card { card }) => request_card == card,
            _ => false,
        }
    }
}

pub fn get_hash<T>(
    request: &types::Data,
    hash_algorithm: T,
) -> Result<Vec<u8>, ContainerError<error::ApiError>>
where
    T: Encode<
            Vec<u8>,
            Vec<u8>,
            ReturnType<Vec<u8>> = Result<Vec<u8>, error::ContainerError<error::CryptoError>>,
        >,
{
    let data = match request {
        types::Data::EncData { enc_card_data } => enc_card_data,
        types::Data::Card { card } => card.card_number.peek(),
    };

    let json_data = serde_json::to_vec(data).change_error(error::ApiError::EncodingError)?;

    let hash_data = hash_algorithm.encode(json_data)?;

    Ok(hash_data)
}

pub fn get_data_duplication_status(
    stored_payload: &storage::types::Locker,
    request_data: &types::Data,
) -> Result<DataDuplicationCheck, ContainerError<error::ApiError>> {
    let decrypted_data = stored_payload
        .data
        .get_decrypted_inner_value()
        .ok_or::<ContainerError<_>>(error::ApiError::DecodingError.into())?;
    let stored_data = serde_json::from_slice::<types::StoredData>(decrypted_data.peek())
        .change_error(error::ApiError::DecodingError)?;

    let is_metadata_duplicated = stored_data.eq(request_data);

    Ok(match is_metadata_duplicated {
        true => DataDuplicationCheck::Duplicated,
        false => DataDuplicationCheck::MetaDataChanged,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use hyperswitch_masking::Secret;

    use super::*;
    use crate::crypto::{
        encryption_manager::managers::aes::generate_aes256_key,
        hash_manager::managers::sha::CardDedupHmac,
    };

    fn data(value: serde_json::Value) -> types::Data {
        serde_json::from_value(value).expect("request data")
    }

    #[test]
    fn get_hash_keys_the_enc_card_data_branch() {
        let key = Secret::new(generate_aes256_key().to_vec());
        let hash = |request: &types::Data| {
            get_hash(request, CardDedupHmac::from_master_key(&key).unwrap()).unwrap()
        };
        let enc = data(serde_json::json!({ "enc_card_data": "4111111111111111" }));
        let card = data(serde_json::json!({ "card": { "card_number": "4111111111111111" } }));

        let first = hash(&enc);
        assert_eq!(first.len(), 64);
        assert_eq!(first, hash(&enc));
        // get_hash hashes the JSON-serialised string with the algorithm it is given.
        let expected = CardDedupHmac::from_master_key(&key)
            .unwrap()
            .encode(serde_json::to_vec("4111111111111111").unwrap())
            .unwrap();
        assert!(first == expected, "get_hash did not use the keyed hash");
        // Both branches hash the same JSON string here, so they meet on purpose: the input bytes
        // are unchanged by this fix, only the key is new.
        assert_eq!(first, hash(&card));
    }
}
