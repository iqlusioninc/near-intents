use super::{Curve, CurveType, TypedCurve};
use near_sdk::CryptoHash;
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
    elliptic_curve::scalar::IsHigh,
};

pub struct P256;

impl Curve for P256 {
    /// Concatenated `x || y` coordinates with no leading SEC1 tag byte.
    type PublicKey = [u8; 64];

    /// Concatenated `r || s` coordinates
    type Signature = [u8; 64];

    // Output of cryptographic hash function
    type Message = CryptoHash;

    type VerifyingKey = Self::PublicKey;

    fn verify(
        signature: &Self::Signature,
        prehashed: &Self::Message,
        public_key: &Self::VerifyingKey,
    ) -> Option<Self::PublicKey> {
        // convert signature
        let signature = Signature::from_slice(signature).ok()?;

        if signature.s().is_high().into() {
            // guard against signature malleability
            return None;
        }

        // convert verifying key
        let mut sec1 = [0; 65];
        sec1[0] = 4; // SEC1 uncompressed point tag before the x || y coordinates.
        sec1[1..].copy_from_slice(public_key);
        let verifying_key = VerifyingKey::from_sec1_bytes(&sec1).ok()?;

        // verify signature over prehashed
        verifying_key
            .verify_prehash(prehashed, &signature)
            .is_ok()
            .then_some(public_key)
            .copied()
    }
}

impl TypedCurve for P256 {
    const CURVE_TYPE: CurveType = CurveType::P256;
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 186-4 P-256/SHA-256 SigGen vector from RustCrypto's p256 tests.
    fn fixture() -> ([u8; 64], [u8; 32], [u8; 64]) {
        let mut public_key = [0; 64];
        hex::decode_to_slice(
            concat!(
                "e266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8a",
                "bfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39"
            ),
            &mut public_key,
        )
        .unwrap();
        let mut prehash = [0; 32];
        hex::decode_to_slice(
            "9b2db89cb0e8fa3cc7608b4d6cc1dec0114e0b9ff4080bea12b134f489ab2bbc",
            &mut prehash,
        )
        .unwrap();
        let mut signature = [0; 64];
        hex::decode_to_slice(
            concat!(
                "976d3a4e9d23326dc0baa9fa560b7c4e53f42864f508483a6473b6a11079b2db",
                "1b766e9ceb71ba6c01dcd46e0af462cd4cfa652ae5017d4555b8eeefe36e1932"
            ),
            &mut signature,
        )
        .unwrap();
        (public_key, prehash, signature)
    }

    #[test]
    fn valid_low_s_signature_preserves_public_key() {
        let (public_key, prehash, signature) = fixture();
        assert_eq!(
            P256::verify(&signature, &prehash, &public_key),
            Some(public_key)
        );
    }

    #[test]
    fn high_s_signature_is_rejected() {
        let (public_key, prehash, mut signature) = fixture();
        // Same valid ECDSA signature with s replaced by curve_order - s.
        hex::decode_to_slice(
            "e4899162148e4594fe232b91f50b9d326fec9582c216213f9e00dbd318f50c1f",
            &mut signature[32..],
        )
        .unwrap();
        let mut sec1 = [4; 65];
        sec1[1..].copy_from_slice(&public_key);
        assert!(
            VerifyingKey::from_sec1_bytes(&sec1)
                .unwrap()
                .verify_prehash(&prehash, &Signature::from_slice(&signature).unwrap())
                .is_ok()
        );
        assert_eq!(P256::verify(&signature, &prehash, &public_key), None);
    }

    #[test]
    fn invalid_prehash_and_public_key_are_rejected() {
        let (public_key, mut prehash, signature) = fixture();
        prehash[0] ^= 1;
        assert_eq!(P256::verify(&signature, &prehash, &public_key), None);
        assert_eq!(P256::verify(&signature, &prehash, &[0; 64]), None);
    }
}
