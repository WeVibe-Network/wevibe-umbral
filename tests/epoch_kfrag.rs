use umbral_pre::PublicKey;
use wevibe_umbral::{cli, crypto};

const SECRET_KEY_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 33;

fn fixed_hex(byte: u8, len: usize) -> String {
    hex::encode(vec![byte; len])
}

fn derive_with_seed_byte(seed_byte: u8) -> cli::DeriveEpochKeyPairResult {
    let seed_hex = fixed_hex(seed_byte, SECRET_KEY_BYTES);
    cli::derive_epoch_keypair_hex(&seed_hex)
        .expect("derive_epoch_keypair_hex should succeed for 32-byte seed")
}

#[test]
fn derive_epoch_keypair_hex_is_deterministic_for_same_seed() {
    let seed_hex = fixed_hex(0x11, SECRET_KEY_BYTES);

    let first =
        cli::derive_epoch_keypair_hex(&seed_hex).expect("first derivation should succeed");
    let second =
        cli::derive_epoch_keypair_hex(&seed_hex).expect("second derivation should succeed");

    assert_eq!(first.secret_key_hex, second.secret_key_hex);
    assert_eq!(first.public_key_hex, second.public_key_hex);
}

#[test]
fn derive_epoch_keypair_hex_distinguishes_different_seeds() {
    let first = derive_with_seed_byte(0x22);
    let second = derive_with_seed_byte(0x23);

    assert_ne!(first.secret_key_hex, second.secret_key_hex);
    assert_ne!(first.public_key_hex, second.public_key_hex);
}

#[test]
fn derive_epoch_keypair_hex_rejects_invalid_hex_inputs() {
    assert!(cli::derive_epoch_keypair_hex("abc").is_err());
    assert!(cli::derive_epoch_keypair_hex("zz").is_err());
}

#[test]
fn derive_epoch_keypair_hex_rejects_wrong_seed_lengths() {
    let empty_seed = String::new();
    let short_seed = fixed_hex(0x33, SECRET_KEY_BYTES - 1);
    let long_seed = fixed_hex(0x33, SECRET_KEY_BYTES + 1);

    for seed in [&empty_seed, &short_seed, &long_seed] {
        let err = match cli::derive_epoch_keypair_hex(seed) {
            Ok(_) => panic!("derive_epoch_keypair_hex should fail for wrong-length seed"),
            Err(err) => err,
        };
        assert!(
            err.contains("Invalid seed length"),
            "expected invalid seed length error, got: {err}"
        );
    }
}

#[test]
fn derive_epoch_keypair_hex_outputs_valid_public_key_shape() {
    let result = derive_with_seed_byte(0x44);

    let secret_key_bytes = hex::decode(&result.secret_key_hex).expect("secret key should be hex");
    assert_eq!(secret_key_bytes.len(), SECRET_KEY_BYTES);

    let public_key_bytes = hex::decode(&result.public_key_hex).expect("public key should be hex");
    assert_eq!(public_key_bytes.len(), PUBLIC_KEY_BYTES);

    PublicKey::try_from_compressed_bytes(&public_key_bytes)
        .expect("public key bytes should decode as compressed Umbral key");
}

#[test]
fn generate_kfrag_hex_happy_path_returns_valid_hex_of_expected_shape() {
    let delegating = derive_with_seed_byte(0x55);
    let receiving = derive_with_seed_byte(0x56);

    let kfrag_hex = cli::generate_kfrag_hex(&delegating.secret_key_hex, &receiving.public_key_hex)
        .expect("generate_kfrag_hex should succeed for valid keys");

    assert!(!kfrag_hex.is_empty(), "kfrag hex should not be empty");
    assert_eq!(kfrag_hex.len() % 2, 0, "kfrag hex must have even length");

    let kfrag_bytes = hex::decode(&kfrag_hex).expect("kfrag should be valid hex");
    assert!(!kfrag_bytes.is_empty(), "kfrag bytes should not be empty");

    let parsed_kfrag =
        crypto::deserialize_key_frag(&kfrag_bytes).expect("kfrag bytes should deserialize");
    let expected_hex_len = crypto::serialize_key_frag(&parsed_kfrag).len() * 2;
    assert_eq!(
        kfrag_hex.len(),
        expected_hex_len,
        "kfrag hex should match serialized key-frag length"
    );
}

#[test]
fn generate_kfrag_hex_rejects_invalid_hex_inputs() {
    let delegating = derive_with_seed_byte(0x66);
    let receiving = derive_with_seed_byte(0x67);

    assert!(cli::generate_kfrag_hex("abc", &receiving.public_key_hex).is_err());
    assert!(cli::generate_kfrag_hex("zz", &receiving.public_key_hex).is_err());
    assert!(cli::generate_kfrag_hex(&delegating.secret_key_hex, "abc").is_err());
    assert!(cli::generate_kfrag_hex(&delegating.secret_key_hex, "zz").is_err());
}

#[test]
fn generate_kfrag_hex_rejects_wrong_input_lengths() {
    let delegating = derive_with_seed_byte(0x77);
    let receiving = derive_with_seed_byte(0x78);

    let short_delegating_sk_hex = fixed_hex(0x79, SECRET_KEY_BYTES - 1);
    let long_delegating_sk_hex = fixed_hex(0x79, SECRET_KEY_BYTES + 1);
    assert!(
        cli::generate_kfrag_hex(&short_delegating_sk_hex, &receiving.public_key_hex).is_err()
    );
    assert!(cli::generate_kfrag_hex(&long_delegating_sk_hex, &receiving.public_key_hex).is_err());

    let short_receiving_pk_hex = fixed_hex(0x7A, PUBLIC_KEY_BYTES - 1);
    let long_receiving_pk_hex = fixed_hex(0x7A, PUBLIC_KEY_BYTES + 1);
    assert!(cli::generate_kfrag_hex(&delegating.secret_key_hex, &short_receiving_pk_hex).is_err());
    assert!(cli::generate_kfrag_hex(&delegating.secret_key_hex, &long_receiving_pk_hex).is_err());
}

#[test]
fn generate_kfrag_hex_multiple_calls_succeed_without_assuming_determinism() {
    let delegating = derive_with_seed_byte(0x88);
    let receiving = derive_with_seed_byte(0x89);

    let first = cli::generate_kfrag_hex(&delegating.secret_key_hex, &receiving.public_key_hex)
        .expect("first kfrag generation should succeed");
    let second = cli::generate_kfrag_hex(&delegating.secret_key_hex, &receiving.public_key_hex)
        .expect("second kfrag generation should succeed");

    let first_bytes = hex::decode(&first).expect("first kfrag should be valid hex");
    let second_bytes = hex::decode(&second).expect("second kfrag should be valid hex");

    crypto::deserialize_key_frag(&first_bytes).expect("first kfrag should deserialize");
    crypto::deserialize_key_frag(&second_bytes).expect("second kfrag should deserialize");

    assert_eq!(
        first_bytes.len(),
        second_bytes.len(),
        "kfrag serialized length should be stable across calls"
    );
}
