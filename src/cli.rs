use crate::crypto;
use serde_json::json;
use std::error::Error;
use std::io;
use umbral_pre::{decrypt_reencrypted, encrypt};

fn to_boxed_error(message: String) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

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

pub fn cmd_encrypt(epoch_pk_hex: &str, plaintext_hex: &str) -> Result<(), Box<dyn Error>> {
    let result = encrypt_hex(epoch_pk_hex, plaintext_hex).map_err(to_boxed_error)?;
    println!(
        "{}",
        json!({
            "capsule": result.capsule_hex,
            "ciphertext": result.ciphertext_hex,
        })
    );
    Ok(())
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

pub fn cmd_decrypt_reencrypted(
    capsule_hex: &str,
    cfrags_hex: &str,
    ciphertext_hex: &str,
    receiving_sk_hex: &str,
    delegating_pk_hex: &str,
) -> Result<(), Box<dyn Error>> {
    let plaintext_hex = decrypt_reencrypted_hex(
        capsule_hex,
        cfrags_hex,
        ciphertext_hex,
        receiving_sk_hex,
        delegating_pk_hex,
    )
    .map_err(to_boxed_error)?;

    println!("{}", json!({ "plaintext": plaintext_hex }));
    Ok(())
}
