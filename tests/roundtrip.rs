use wevibe_umbral::cli;

#[test]
fn test_cli_roundtrip_encrypt_reencrypt_decrypt() {
    let epoch_seed_hex = hex::encode([0x01u8; 32]);
    let receiving_seed_hex = hex::encode([0x02u8; 32]);
    let plaintext_hex = hex::encode([0x11u8; 32]);

    let epoch_keys = cli::derive_epoch_keypair_hex(&epoch_seed_hex)
        .expect("derive_epoch_keypair_hex should produce epoch keypair");
    let receiving_keys = cli::derive_epoch_keypair_hex(&receiving_seed_hex)
        .expect("derive_epoch_keypair_hex should produce receiving keypair");

    let encrypted = cli::encrypt_hex(&epoch_keys.public_key_hex, &plaintext_hex)
        .expect("encrypt_hex should succeed");

    let kfrag_hex = cli::generate_kfrag_hex(&epoch_keys.secret_key_hex, &receiving_keys.public_key_hex)
        .expect("generate_kfrag_hex should succeed");

    let cfrag_hex = cli::reencrypt_hex(&encrypted.capsule_hex, &kfrag_hex)
        .expect("reencrypt_hex should succeed");

    let decrypted_plaintext_hex = cli::decrypt_reencrypted_hex(
        &encrypted.capsule_hex,
        &cfrag_hex,
        &encrypted.ciphertext_hex,
        &receiving_keys.secret_key_hex,
        &epoch_keys.public_key_hex,
    )
    .expect("decrypt_reencrypted_hex should succeed");

    assert_eq!(decrypted_plaintext_hex, plaintext_hex);
}
