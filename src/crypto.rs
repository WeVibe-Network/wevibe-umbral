use umbral_pre::{
    Capsule, CapsuleFrag, KeyFrag, PublicKey, SecretKey, SecretKeyFactory, VerifiedCapsuleFrag,
};

pub fn serialize_public_key(pk: &PublicKey) -> Vec<u8> {
    pk.to_compressed_bytes().to_vec()
}

pub fn deserialize_public_key(bytes: &[u8]) -> Result<PublicKey, String> {
    PublicKey::try_from_compressed_bytes(bytes).map_err(|e| format!("Invalid PublicKey: {e}"))
}

pub fn serialize_key_frag(kf: &KeyFrag) -> Vec<u8> {
    rmp_serde::to_vec(kf).expect("KeyFrag serialization should not fail")
}

pub fn deserialize_key_frag(bytes: &[u8]) -> Result<KeyFrag, String> {
    rmp_serde::from_slice(bytes).map_err(|e| format!("Invalid KeyFrag: {e}"))
}

pub fn serialize_verified_capsule_frag(vcf: &VerifiedCapsuleFrag) -> Vec<u8> {
    rmp_serde::to_vec(vcf).expect("VerifiedCapsuleFrag serialization should not fail")
}

pub fn deserialize_verified_capsule_frag(bytes: &[u8]) -> Result<VerifiedCapsuleFrag, String> {
    let cfrag: CapsuleFrag =
        rmp_serde::from_slice(bytes).map_err(|e| format!("Invalid CapsuleFrag: {e}"))?;
    Ok(cfrag.skip_verification())
}

pub fn serialize_capsule(capsule: &Capsule) -> Vec<u8> {
    rmp_serde::to_vec(capsule).expect("Capsule serialization should not fail")
}

pub fn deserialize_capsule(bytes: &[u8]) -> Result<Capsule, String> {
    rmp_serde::from_slice(bytes).map_err(|e| format!("Invalid Capsule: {e}"))
}

pub fn deserialize_secret_key(bytes: &[u8]) -> Result<SecretKey, String> {
    SecretKeyFactory::from_secure_randomness(bytes)
        .map_err(|e| format!("Invalid SecretKey: {e}"))
        .map(|factory| factory.make_key(b""))
}
