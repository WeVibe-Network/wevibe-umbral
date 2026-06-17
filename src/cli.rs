use crate::crypto;
use serde_json::json;
use std::error::Error;
use std::io;
use umbral_pre::{decrypt_reencrypted, encrypt, generate_kfrags, SecretKeyFactory, Signer};

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

pub struct DeriveEpochKeyPairResult {
    pub secret_key_hex: String,
    pub public_key_hex: String,
}

pub fn derive_epoch_keypair_hex(seed_hex: &str) -> Result<DeriveEpochKeyPairResult, String> {
    let seed_bytes = decode_hex("seed", seed_hex)?;

    let sk = SecretKeyFactory::from_secure_randomness(&seed_bytes)
        .map_err(|e| format!("Invalid seed length: {e}"))?
        .make_key(b"");
    let pk = sk.public_key();

    Ok(DeriveEpochKeyPairResult {
        secret_key_hex: hex::encode(sk.to_be_bytes().as_secret()),
        public_key_hex: hex::encode(crypto::serialize_public_key(&pk)),
    })
}

pub fn cmd_derive_epoch_keypair(seed_hex: &str) -> Result<(), Box<dyn Error>> {
    let result = derive_epoch_keypair_hex(seed_hex).map_err(to_boxed_error)?;

    println!(
        "{{\"secret_key\":\"{}\",\"public_key\":\"{}\"}}",
        result.secret_key_hex, result.public_key_hex
    );

    Ok(())
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

pub fn cmd_generate_kfrags(
    delegating_sk_hex: &str,
    receiving_pk_hex: &str,
) -> Result<(), Box<dyn Error>> {
    let kfrag_hex = generate_kfrag_hex(delegating_sk_hex, receiving_pk_hex).map_err(to_boxed_error)?;
    println!("{kfrag_hex}");
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
