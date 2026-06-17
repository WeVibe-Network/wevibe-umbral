use umbral_pre::{
    Capsule, CapsuleFrag, DefaultDeserialize, DefaultSerialize, KeyFrag, PublicKey, SecretKey,
    SecretKeyFactory, VerifiedCapsuleFrag,
};

pub fn serialize_public_key(pk: &PublicKey) -> Vec<u8> {
    pk.to_compressed_bytes().to_vec()
}

pub fn deserialize_public_key(bytes: &[u8]) -> Result<PublicKey, String> {
    PublicKey::try_from_compressed_bytes(bytes).map_err(|e| format!("Invalid PublicKey: {e}"))
}

pub fn serialize_secret_key_seed(seed: &[u8]) -> Vec<u8> {
    seed.to_vec()
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
    SecretKeyFactory::from_secure_randomness(bytes)
        .map_err(|e| format!("Invalid SecretKey: {e}"))
        .map(|factory| factory.make_key(b""))
}
