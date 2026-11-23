use hyperswitch_masking::{PeekInterface, Secret};
use ring::hmac;

use crate::{crypto::hash_manager::hash_interface::Encode, error};

///
/// Type providing encoding functional to perform hashing
///
pub struct Sha512;

impl Encode<Vec<u8>, Vec<u8>> for Sha512 {
    type ReturnType<T> = Result<T, error::ContainerError<error::CryptoError>>;

    fn encode(&self, input: Vec<u8>) -> Self::ReturnType<Vec<u8>> {
        let digest = ring::digest::digest(&ring::digest::SHA512, &input);
        Ok(digest.as_ref().to_vec())
    }
}

///
/// Type providing encoding functional to perform HMAC-SHA512 hashing
///
/// # Example
///
///```
/// use hyperswitch_card_vault::crypto::hash_manager::managers::sha::HmacSha512;
/// use hyperswitch_card_vault::crypto::hash_manager::hash_interface::Encode;
///
/// let data = "Hello, World!";
/// let key = "key";
/// let algo = HmacSha512::<1>::new(key.as_bytes().to_vec().into());
/// let hash = algo.encode(data.as_bytes().to_vec().into()).unwrap();
///
/// ```
///
/// This will not compile if `N` is less than or equal to 0.
///
/// ```compile_fail
///
/// use hyperswitch_card_vault::crypto::hash_manager::managers::sha::HmacSha512;
/// use hyperswitch_card_vault::crypto::hash_manager::hash_interface::Encode;
///
/// let key = "key";
/// let algo = HmacSha512::<0>::new(key.as_bytes().to_vec().into());
///
///
/// ```
///
///
pub struct HmacSha512<const N: usize = 1>(hyperswitch_masking::Secret<Vec<u8>>);

impl<const N: usize> HmacSha512<N> {
    pub fn new(key: hyperswitch_masking::Secret<Vec<u8>>) -> Self {
        #[allow(clippy::let_unit_value)]
        let _ = <Self as AssertGt0>::VALID;

        Self(key)
    }
}

impl<const N: usize> std::fmt::Display for HmacSha512<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HmacSha512<{}>", N)
    }
}

impl<const N: usize> Encode<Secret<Vec<u8>>, Secret<Vec<u8>>> for HmacSha512<N> {
    type ReturnType<T> = Result<T, error::ContainerError<error::CryptoError>>;

    fn encode(&self, input: Secret<Vec<u8>>) -> Self::ReturnType<Secret<Vec<u8>>> {
        let key = hmac::Key::new(ring::hmac::HMAC_SHA512, self.0.peek());
        let first = hmac::sign(&key, input.peek());

        let signature = (0..=(N - 1)).fold(first, |input, _| hmac::sign(&key, input.as_ref()));

        Ok(signature.as_ref().to_vec().into())
    }
}

/// HKDF context of the duplicate-check key. It is specific to this use and versioned, so the derived
/// key is independent of every other key taken from the tenant master key.
pub const CARD_DEDUP_INFO: &[u8] = b"hyperswitch-card-vault/card-dedup/v1";

///
/// Keyed hash of the card data used by the `/data/add` duplicate check (`hash_table.data_hash`).
///
/// The key is derived with HKDF-SHA512 from the tenant master key and [`CARD_DEDUP_INFO`]; the hash
/// is one plain HMAC-SHA512 of the input, 64 bytes, never truncated. Both come from `ring`.
///
pub struct CardDedupHmac(Secret<Vec<u8>>);

impl CardDedupHmac {
    pub fn from_master_key(
        master_key: &Secret<Vec<u8>>,
    ) -> Result<Self, error::ContainerError<error::CryptoError>> {
        if master_key.peek().is_empty() {
            return Err(error::CryptoError::InvalidData("empty master key").into());
        }

        let mut key = vec![0_u8; ring::hkdf::KeyType::len(&ring::hkdf::HKDF_SHA512)];
        ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA512, &[])
            .extract(master_key.peek())
            .expand(&[CARD_DEDUP_INFO], ring::hkdf::HKDF_SHA512)
            .and_then(|okm| okm.fill(&mut key))
            .map_err(|_| error::CryptoError::InvalidData("card dedup key derivation failed"))?;

        Ok(Self(Secret::new(key)))
    }
}

impl Encode<Vec<u8>, Vec<u8>> for CardDedupHmac {
    type ReturnType<T> = Result<T, error::ContainerError<error::CryptoError>>;

    fn encode(&self, input: Vec<u8>) -> Self::ReturnType<Vec<u8>> {
        Ok(hmac_sha512(self.0.peek(), &input))
    }
}

/// One plain HMAC-SHA512 (RFC 2104), computed by `ring`.
fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA512, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

trait AssertGt0 {
    const VALID: ();
}

impl<const N: usize> AssertGt0 for HmacSha512<N> {
    const VALID: () = assert!(N > 0);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    //!
    //! Testing HMAC-SHA512 encoding consists of 3 variables.
    //! 1. The input data
    //! 2. The Key
    //! 3. The `N` value
    //!

    use super::*;

    #[test]
    fn test_input_data_equal() {
        let data1 = "Hello, World!";
        let data2 = "Hello, World!";
        let key = "key";

        let algo = HmacSha512::<1>::new(key.as_bytes().to_vec().into());

        let hash1 = algo.encode(data1.as_bytes().to_vec().into()).unwrap();
        let hash2 = algo.encode(data2.as_bytes().to_vec().into()).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_input_data_not_equal() {
        let data1 = "Hello, World!";
        let data2 = "Hello, world";
        let key = "key";

        let algo = HmacSha512::<1>::new(key.as_bytes().to_vec().into());

        let hash1 = algo.encode(data1.as_bytes().to_vec().into()).unwrap();
        let hash2 = algo.encode(data2.as_bytes().to_vec().into()).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_key_not_equal() {
        let data = "Hello, World!";
        let key1 = "key1";
        let key2 = "key2";

        let algo1 = HmacSha512::<1>::new(key1.as_bytes().to_vec().into());
        let algo2 = HmacSha512::<1>::new(key2.as_bytes().to_vec().into());

        let hash1 = algo1.encode(data.as_bytes().to_vec().into()).unwrap();
        let hash2 = algo2.encode(data.as_bytes().to_vec().into()).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_key_equal() {
        let data = "Hello, World!";
        let key1 = "key";
        let key2 = "key";

        let algo1 = HmacSha512::<1>::new(key1.as_bytes().to_vec().into());
        let algo2 = HmacSha512::<1>::new(key2.as_bytes().to_vec().into());

        let hash1 = algo1.encode(data.as_bytes().to_vec().into()).unwrap();
        let hash2 = algo2.encode(data.as_bytes().to_vec().into()).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_n_equal() {
        let data = "Hello, World!";
        let key = "key";

        let algo1 = HmacSha512::<10>::new(key.as_bytes().to_vec().into());
        let algo2 = HmacSha512::<10>::new(key.as_bytes().to_vec().into());

        let hash1 = algo1.encode(data.as_bytes().to_vec().into()).unwrap();
        let hash2 = algo2.encode(data.as_bytes().to_vec().into()).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_n_not_equal() {
        let data = "Hello, World!";
        let key = "key";

        let algo1 = HmacSha512::<10>::new(key.as_bytes().to_vec().into());
        let algo2 = HmacSha512::<20>::new(key.as_bytes().to_vec().into());

        let hash1 = algo1.encode(data.as_bytes().to_vec().into()).unwrap();
        let hash2 = algo2.encode(data.as_bytes().to_vec().into()).unwrap();

        assert_ne!(hash1, hash2);
    }

    // Duplicate-check hash. Test data: the public test card number, keys from the generator behind
    // `utils master-key`, and RFC 4231 vectors. No key is printed on failure.

    use crate::crypto::encryption_manager::managers::aes::generate_aes256_key;

    const CARD: &[u8] = b"4111111111111111";

    fn master_key() -> Secret<Vec<u8>> {
        Secret::new(generate_aes256_key().to_vec())
    }

    fn sha512(data: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA512, data)
            .as_ref()
            .to_vec()
    }

    #[test]
    fn hmac_sha512_matches_rfc4231_case_2() {
        let expected = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                        9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
        assert_eq!(
            hex::encode(hmac_sha512(b"Jefe", b"what do ya want for nothing?")),
            expected
        );
    }

    #[test]
    fn card_dedup_same_card_same_key_gives_same_hash() {
        let key = master_key();
        let a = CardDedupHmac::from_master_key(&key)
            .unwrap()
            .encode(CARD.to_vec())
            .unwrap();
        let b = CardDedupHmac::from_master_key(&key)
            .unwrap()
            .encode(CARD.to_vec())
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn card_dedup_two_master_keys_give_two_hashes() {
        let a = CardDedupHmac::from_master_key(&master_key())
            .unwrap()
            .encode(CARD.to_vec())
            .unwrap();
        let b = CardDedupHmac::from_master_key(&master_key())
            .unwrap()
            .encode(CARD.to_vec())
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn card_dedup_differs_from_plain_sha512_and_from_master_key() {
        let key = master_key();
        let algo = CardDedupHmac::from_master_key(&key).unwrap();
        // The old code hashed the JSON-serialised number, that is, between double quotes.
        let quoted = [b"\"", CARD, b"\""].concat();
        let hash = algo.encode(quoted.clone()).unwrap();
        assert_ne!(hash, sha512(CARD));
        assert_ne!(hash, sha512(&quoted));
        assert_eq!(algo.0.peek().len(), 64);
        assert!(algo.0.peek() != key.peek(), "derived key equals master key");
    }

    #[test]
    fn card_dedup_rejects_empty_master_key() {
        assert!(CardDedupHmac::from_master_key(&Secret::new(Vec::new())).is_err());
    }

    #[test]
    fn card_dedup_key_is_hkdf_of_master_key_with_context() {
        struct Len64;
        impl ring::hkdf::KeyType for Len64 {
            fn len(&self) -> usize {
                64
            }
        }

        let key = master_key();
        let mut expected = [0_u8; 64];
        ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA512, &[])
            .extract(key.peek())
            .expand(&[CARD_DEDUP_INFO], Len64)
            .unwrap()
            .fill(&mut expected)
            .unwrap();

        let algo = CardDedupHmac::from_master_key(&key).unwrap();
        assert!(
            algo.0.peek() == &expected,
            "derived key is not HKDF(master key, context)"
        );
        assert!(
            algo.encode(CARD.to_vec()).unwrap() == hmac_sha512(&expected, CARD),
            "hash is not one HMAC-SHA512 under the derived key"
        );
    }

    #[test]
    fn card_dedup_context_is_versioned_and_specific() {
        assert_eq!(CARD_DEDUP_INFO, b"hyperswitch-card-vault/card-dedup/v1");
    }
}
