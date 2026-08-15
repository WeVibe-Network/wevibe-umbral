//! WASM bindings for WeVibe's Umbral PRE core.
//!
//! Built with `wasm-pack build --target nodejs --release` and vendored into
//! `wevibe-mcp/vendor/umbral-wasm/`, so the MCP carries its own crypto and
//! needs no binary path, no environment variable and no subprocess.
//!
//! These wrappers return the SAME JSON shapes the CLI printed on stdout, so
//! the TypeScript side parses identically to the old sidecar responses.
//! All crypto lives in `wevibe-umbral-core` and is shared byte-for-byte with
//! the native binary — do not reimplement anything here.

use wasm_bindgen::prelude::*;
use wevibe_umbral_core::ops;

fn js_err(message: String) -> JsValue {
    JsValue::from_str(&message)
}

/// Matches `wevibe-umbral derive-epoch-keypair --seed <hex>`.
#[wasm_bindgen(js_name = deriveEpochKeypair)]
pub fn derive_epoch_keypair(seed_hex: &str) -> Result<String, JsValue> {
    let result = ops::derive_epoch_keypair_hex(seed_hex).map_err(js_err)?;
    Ok(format!(
        "{{\"secret_key\":\"{}\",\"public_key\":\"{}\"}}",
        result.secret_key_hex, result.public_key_hex
    ))
}

/// Matches `wevibe-umbral encrypt --epoch-pk <hex> --plaintext <hex>`.
#[wasm_bindgen(js_name = encrypt)]
pub fn encrypt(epoch_pk_hex: &str, plaintext_hex: &str) -> Result<String, JsValue> {
    let result = ops::encrypt_hex(epoch_pk_hex, plaintext_hex).map_err(js_err)?;
    Ok(format!(
        "{{\"capsule\":\"{}\",\"ciphertext\":\"{}\"}}",
        result.capsule_hex, result.ciphertext_hex
    ))
}

/// Matches `wevibe-umbral generate-kfrags` — returns bare kfrag hex.
#[wasm_bindgen(js_name = generateKfrag)]
pub fn generate_kfrag(
    delegating_sk_hex: &str,
    receiving_pk_hex: &str,
) -> Result<String, JsValue> {
    ops::generate_kfrag_hex(delegating_sk_hex, receiving_pk_hex).map_err(js_err)
}

/// Matches `wevibe-umbral reencrypt` — returns bare cfrag hex.
///
/// Not currently called by the MCP (the hub relays re-encryption), but exported
/// so the cross-compatibility test can drive a full round trip in-process.
#[wasm_bindgen(js_name = reencrypt)]
pub fn reencrypt(capsule_hex: &str, kfrag_hex: &str) -> Result<String, JsValue> {
    ops::reencrypt_hex(capsule_hex, kfrag_hex).map_err(js_err)
}

/// Matches `wevibe-umbral decrypt-reencrypted` — returns plaintext hex.
#[wasm_bindgen(js_name = decryptReencrypted)]
pub fn decrypt_reencrypted(
    capsule_hex: &str,
    cfrags_hex: &str,
    ciphertext_hex: &str,
    receiving_sk_hex: &str,
    delegating_pk_hex: &str,
) -> Result<String, JsValue> {
    ops::decrypt_reencrypted_hex(
        capsule_hex,
        cfrags_hex,
        ciphertext_hex,
        receiving_sk_hex,
        delegating_pk_hex,
    )
    .map_err(js_err)
}
