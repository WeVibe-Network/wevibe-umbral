//! CLI presentation layer.
//!
//! The crypto itself lives in `wevibe-umbral-core` (`crates/core/src/ops.rs`)
//! and is re-exported here so existing callers and tests keep using
//! `wevibe_umbral::cli::{encrypt_hex, derive_epoch_keypair_hex, …}`.
//! Only stdout formatting belongs in this file.

use serde_json::json;
use std::error::Error;
use std::io;

pub use wevibe_umbral_core::ops::{
    decrypt_reencrypted_hex, derive_epoch_keypair_hex, encrypt_hex, generate_kfrag_hex,
    reencrypt_hex, DeriveEpochKeyPairResult, EncryptResult,
};

fn to_boxed_error(message: String) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
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

pub fn cmd_derive_epoch_keypair(seed_hex: &str) -> Result<(), Box<dyn Error>> {
    let result = derive_epoch_keypair_hex(seed_hex).map_err(to_boxed_error)?;

    println!(
        "{{\"secret_key\":\"{}\",\"public_key\":\"{}\"}}",
        result.secret_key_hex, result.public_key_hex
    );

    Ok(())
}

pub fn cmd_generate_kfrags(
    delegating_sk_hex: &str,
    receiving_pk_hex: &str,
) -> Result<(), Box<dyn Error>> {
    let kfrag_hex = generate_kfrag_hex(delegating_sk_hex, receiving_pk_hex).map_err(to_boxed_error)?;
    println!("{kfrag_hex}");
    Ok(())
}

pub fn cmd_reencrypt(capsule_hex: &str, kfrag_hex: &str) -> Result<(), Box<dyn Error>> {
    let cfrag_hex = reencrypt_hex(capsule_hex, kfrag_hex).map_err(to_boxed_error)?;
    println!("{}", json!({ "cfrag": cfrag_hex }));
    Ok(())
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
