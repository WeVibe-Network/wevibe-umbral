//! Hex-in / hex-out Umbral operations.
//!
//! These are the operations the leader-side MCP performs locally (the
//! 2026-06-17 epoch-key pivot: the hub never mints epoch keys or kfrags).
//! They are deliberately pure `&str -> String` with no I/O, no process
//! spawning and no logging, so the exact same code compiles to a native
//! binary and to wasm32-unknown-unknown.
//!
//! Anything added here MUST stay wasm-compatible.

use crate::crypto;
use umbral_pre::{decrypt_reencrypted, encrypt, generate_kfrags, reencrypt, Signer};

fn decode_hex(label: &str, value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|e| format!("Invalid {label} hex: {e}"))
}

pub struct EncryptResult {
    pub capsule_hex: String,
    pub ciphertext_hex: String,
}

pub fn encrypt_hex(epoch_pk_hex: &str, plaintext_hex: &str) -> Result<EncryptResult, String> {
    let pk_bytes = decode_hex("epoch_pk", epoch_pk_hex)?;
    let plaintext = decode_hex("plaintext", plaintext_hex)?;

    let delegating_pk = crypto::deserialize_public_key(&pk_bytes)?;

    let (capsule, ciphertext) =
        encrypt(&delegating_pk, &plaintext).map_err(|e| format!("encrypt failed: {e}"))?;

    let capsule_bytes = crypto::serialize_capsule(&capsule);

    Ok(EncryptResult {
        capsule_hex: hex::encode(capsule_bytes),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

pub struct DeriveEpochKeyPairResult {
    pub secret_key_hex: String,
    pub public_key_hex: String,
}

pub fn derive_epoch_keypair_hex(seed_hex: &str) -> Result<DeriveEpochKeyPairResult, String> {
    let seed_bytes = decode_hex("seed", seed_hex)?;

    let sk = crypto::deserialize_secret_key(&seed_bytes)?;
    let pk = sk.public_key();

    Ok(DeriveEpochKeyPairResult {
        secret_key_hex: hex::encode(crypto::serialize_secret_key(&sk)),
        public_key_hex: hex::encode(crypto::serialize_public_key(&pk)),
    })
}

pub fn generate_kfrag_hex(
    delegating_sk_hex: &str,
    receiving_pk_hex: &str,
) -> Result<String, String> {
    let delegating_sk_bytes = decode_hex("delegating_sk", delegating_sk_hex)?;
    let receiving_pk_bytes = decode_hex("receiving_pk", receiving_pk_hex)?;

    let delegating_sk = crypto::deserialize_secret_key(&delegating_sk_bytes)?;
    let receiving_pk = crypto::deserialize_public_key(&receiving_pk_bytes)?;

    let signer = Signer::new(delegating_sk.clone());
    let kfrags = generate_kfrags(&delegating_sk, &receiving_pk, &signer, 1, 1, true, true);
    let vkfrag = kfrags
        .into_vec()
        .into_iter()
        .next()
        .ok_or_else(|| "generate_kfrags returned no kfrags".to_string())?;

    Ok(hex::encode(crypto::serialize_key_frag(&vkfrag.unverify())))
}

pub fn reencrypt_hex(capsule_hex: &str, kfrag_hex: &str) -> Result<String, String> {
    let capsule_bytes = decode_hex("capsule", capsule_hex)?;
    let kfrag_bytes = decode_hex("kfrag", kfrag_hex)?;

    let capsule = crypto::deserialize_capsule(&capsule_bytes)?;
    let kfrag = crypto::deserialize_key_frag(&kfrag_bytes)?;
    let verified_kfrag = kfrag.skip_verification();

    let vcfrag = reencrypt(&capsule, verified_kfrag);

    Ok(hex::encode(crypto::serialize_verified_capsule_frag(&vcfrag)))
}

pub fn decrypt_reencrypted_hex(
    capsule_hex: &str,
    cfrags_hex: &str,
    ciphertext_hex: &str,
    receiving_sk_hex: &str,
    delegating_pk_hex: &str,
) -> Result<String, String> {
    if cfrags_hex.trim().is_empty() {
        return Err("cfrags must not be empty".into());
    }

    let capsule_bytes = decode_hex("capsule", capsule_hex)?;
    let ciphertext = decode_hex("ciphertext", ciphertext_hex)?;
    let receiving_sk_bytes = decode_hex("receiving_sk", receiving_sk_hex)?;
    let delegating_pk_bytes = decode_hex("delegating_pk", delegating_pk_hex)?;

    let capsule = crypto::deserialize_capsule(&capsule_bytes)?;
    let delegating_pk = crypto::deserialize_public_key(&delegating_pk_bytes)?;
    let receiving_sk = crypto::deserialize_secret_key(&receiving_sk_bytes)?;

    let cfrag_hexes: Vec<&str> = cfrags_hex
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();

    if cfrag_hexes.is_empty() {
        return Err("cfrags must not be empty".into());
    }

    let verified_cfrags = cfrag_hexes
        .iter()
        .map(|hex_str| {
            let bytes = decode_hex("cfrag", hex_str)?;
            crypto::deserialize_verified_capsule_frag(&bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let plaintext = decrypt_reencrypted(
        &receiving_sk,
        &delegating_pk,
        &capsule,
        verified_cfrags,
        &ciphertext,
    )
    .map_err(|e| format!("decrypt_reencrypted failed: {e}"))?;

    Ok(hex::encode(plaintext))
}
