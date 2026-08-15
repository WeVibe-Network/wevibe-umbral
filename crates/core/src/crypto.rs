use umbral_pre::{
    Capsule, CapsuleFrag, DefaultDeserialize, DefaultSerialize, KeyFrag, PublicKey, SecretKey,
    VerifiedCapsuleFrag,
};

pub fn serialize_public_key(pk: &PublicKey) -> Vec<u8> {
    pk.to_compressed_bytes().to_vec()
}

pub fn deserialize_public_key(bytes: &[u8]) -> Result<PublicKey, String> {
    PublicKey::try_from_compressed_bytes(bytes).map_err(|e| format!("Invalid PublicKey: {e}"))
}

pub fn serialize_secret_key(sk: &SecretKey) -> Vec<u8> {
    sk.to_be_bytes().as_secret().to_vec()
}

pub fn serialize_key_frag(kf: &KeyFrag) -> Vec<u8> {
    kf.to_bytes()
        .expect("KeyFrag serialization should not fail")
        .into_vec()
}

pub fn deserialize_key_frag(bytes: &[u8]) -> Result<KeyFrag, String> {
    KeyFrag::from_bytes(bytes).map_err(|e| format!("Invalid KeyFrag: {e}"))
}

pub fn serialize_verified_capsule_frag(vcf: &VerifiedCapsuleFrag) -> Vec<u8> {
    vcf.to_bytes()
        .expect("VerifiedCapsuleFrag serialization should not fail")
        .into_vec()
}

pub fn deserialize_verified_capsule_frag(bytes: &[u8]) -> Result<VerifiedCapsuleFrag, String> {
    let cfrag = CapsuleFrag::from_bytes(bytes).map_err(|e| format!("Invalid CapsuleFrag: {e}"))?;
    Ok(cfrag.skip_verification())
}

pub fn serialize_capsule(capsule: &Capsule) -> Vec<u8> {
    capsule
        .to_bytes()
        .expect("Capsule serialization should not fail")
        .into_vec()
}

pub fn deserialize_capsule(bytes: &[u8]) -> Result<Capsule, String> {
    Capsule::from_bytes(bytes).map_err(|e| format!("Invalid Capsule: {e}"))
}

pub fn deserialize_secret_key(bytes: &[u8]) -> Result<SecretKey, String> {
    if bytes.len() != 32 {
        return Err(format!(
            "Invalid SecretKey length: expected 32 bytes, got {}",
            bytes.len()
        ));
    }

    let mut scalar_bytes = SecretKey::random().to_be_bytes();
    scalar_bytes.as_mut_secret().copy_from_slice(bytes);
    SecretKey::try_from_be_bytes(&scalar_bytes).map_err(|e| format!("Invalid SecretKey: {e}"))
}

/// Fingerprint for logging: first 8 hex chars of sha256(bytes).
/// NEVER log raw key/kfrag/capsule/plaintext bytes — this fingerprint + sizes only (D-MISSION-INVARIANT).
pub fn fingerprint(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..4])
}
