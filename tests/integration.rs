use wevibe_umbral::cli;
use wevibe_umbral::store::KFragStore;
use std::process::Command;
use umbral_pre::{
    decrypt_reencrypted, encrypt, generate_kfrags, reencrypt, Capsule, CapsuleFrag, KeyFrag,
    PublicKey, SecretKey, SecretKeyFactory, Signer, VerifiedCapsuleFrag,
};

fn serialize_public_key(pk: &PublicKey) -> Vec<u8> {
    pk.to_compressed_bytes().to_vec()
}

fn deserialize_public_key(bytes: &[u8]) -> PublicKey {
    PublicKey::try_from_compressed_bytes(bytes).unwrap()
}

fn serialize_key_frag(kf: &KeyFrag) -> Vec<u8> {
    rmp_serde::to_vec(kf).unwrap()
}

fn deserialize_key_frag(bytes: &[u8]) -> KeyFrag {
    rmp_serde::from_slice(bytes).unwrap()
}

fn serialize_verified_capsule_frag(vcf: &VerifiedCapsuleFrag) -> Vec<u8> {
    rmp_serde::to_vec(vcf).unwrap()
}

#[test]
fn test_store_and_retrieve_kfrag() {
    let store = KFragStore::new();
    let org_id = "org-1";
    let epoch_id = 42;
    let member_pk = b"member-pk-bytes".to_vec();
    let kfrag_bytes = b"kfrag-test-data".to_vec();

    store.insert(org_id, epoch_id, &member_pk, &kfrag_bytes);

    let retrieved = store.get(org_id, epoch_id, &member_pk);
    assert!(retrieved.is_some(), "Expected kfrag to be retrieved");
    assert_eq!(retrieved.unwrap(), kfrag_bytes);
}

#[test]
fn test_store_multiple_members_same_org() {
    let store = KFragStore::new();
    let org_id = "org-1";
    let epoch_id = 1;

    let member1_pk = b"member-1-pk".to_vec();
    let member2_pk = b"member-2-pk".to_vec();
    let member3_pk = b"member-3-pk".to_vec();

    let kfrag1 = b"kfrag-for-member-1".to_vec();
    let kfrag2 = b"kfrag-for-member-2".to_vec();
    let kfrag3 = b"kfrag-for-member-3".to_vec();

    store.insert(org_id, epoch_id, &member1_pk, &kfrag1);
    store.insert(org_id, epoch_id, &member2_pk, &kfrag2);
    store.insert(org_id, epoch_id, &member3_pk, &kfrag3);

    let retrieved1 = store.get(org_id, epoch_id, &member1_pk).unwrap();
    let retrieved2 = store.get(org_id, epoch_id, &member2_pk).unwrap();
    let retrieved3 = store.get(org_id, epoch_id, &member3_pk).unwrap();

    assert_eq!(retrieved1, kfrag1);
    assert_eq!(retrieved2, kfrag2);
    assert_eq!(retrieved3, kfrag3);
}

#[test]
fn test_delete_kfrags_by_member() {
    let store = KFragStore::new();
    let org_id = "org-1";
    let member_pk = b"target-member-pk".to_vec();

    let kfrag1 = b"kfrag-epoch-1".to_vec();
    let kfrag2 = b"kfrag-epoch-2".to_vec();
    let kfrag3 = b"kfrag-epoch-3".to_vec();

    store.insert(org_id, 1, &member_pk, &kfrag1);
    store.insert(org_id, 2, &member_pk, &kfrag2);
    store.insert(org_id, 3, &member_pk, &kfrag3);

    let other_member_pk = b"other-member-pk".to_vec();
    let other_kfrag = b"other-member-kfrag".to_vec();
    store.insert(org_id, 1, &other_member_pk, &other_kfrag);

    let deleted_count = store.delete(org_id, &member_pk);
    assert_eq!(deleted_count, 3, "Expected 3 kfrags deleted for target member");

    assert!(store.get(org_id, 1, &member_pk).is_none());
    assert!(store.get(org_id, 2, &member_pk).is_none());
    assert!(store.get(org_id, 3, &member_pk).is_none());

    let other_retrieved = store.get(org_id, 1, &other_member_pk).unwrap();
    assert_eq!(other_retrieved, other_kfrag);
}

#[test]
fn test_delete_org_kfrags() {
    let store = KFragStore::new();
    let org_a = "org-a";
    let org_b = "org-b";

    let member1_pk = b"member-1-pk".to_vec();
    let member2_pk = b"member-2-pk".to_vec();

    store.insert(org_a, 1, &member1_pk, b"org-a-member1-epoch1".as_slice());
    store.insert(org_a, 2, &member1_pk, b"org-a-member1-epoch2".as_slice());
    store.insert(org_a, 1, &member2_pk, b"org-a-member2-epoch1".as_slice());
    store.insert(org_b, 1, &member1_pk, b"org-b-member1-epoch1".as_slice());

    let deleted_count = store.delete_org(org_a);
    assert_eq!(deleted_count, 3, "Expected 3 kfrags deleted for org-a");

    assert!(store.get(org_a, 1, &member1_pk).is_none());
    assert!(store.get(org_a, 2, &member1_pk).is_none());
    assert!(store.get(org_a, 1, &member2_pk).is_none());

    let org_b_retrieved = store.get(org_b, 1, &member1_pk).unwrap();
    assert_eq!(org_b_retrieved, b"org-b-member1-epoch1".to_vec());
}

#[test]
fn test_overwrite_existing_kfrag() {
    let store = KFragStore::new();
    let org_id = "org-1";
    let epoch_id = 1;
    let member_pk = b"member-pk".to_vec();

    let kfrag_v1 = b"kfrag-version-1".to_vec();
    let kfrag_v2 = b"kfrag-version-2".to_vec();

    store.insert(org_id, epoch_id, &member_pk, &kfrag_v1);

    let first = store.get(org_id, epoch_id, &member_pk).unwrap();
    assert_eq!(first, kfrag_v1);

    store.insert(org_id, epoch_id, &member_pk, &kfrag_v2);

    let second = store.get(org_id, epoch_id, &member_pk).unwrap();
    assert_eq!(second, kfrag_v2);
}

#[test]
fn test_retrieve_nonexistent_kfrag() {
    let store = KFragStore::new();
    let org_id = "nonexistent-org";
    let epoch_id = 999;
    let member_pk = b"nonexistent-member".to_vec();

    let result = store.get(org_id, epoch_id, &member_pk);
    assert!(result.is_none(), "Expected None for nonexistent kfrag");
}

#[test]
fn test_factory_workaround_can_sign_and_verify() {
    let seed = b"01234567890123456789012345678901";
    let sk = SecretKeyFactory::from_secure_randomness(seed)
        .unwrap()
        .make_key(b"");
    let pk = sk.public_key();
    let pk_from_sk = sk.public_key();

    assert_eq!(pk, pk_from_sk);

    let signer = Signer::new(sk);
    let message = b"Verification test message";
    let signature = signer.sign(message);

    assert!(signature.verify(&pk_from_sk, message));
}

#[test]
fn test_secretkey_factory_workaround_produces_valid_signing_key() {
    let seed = b"test-seed-bytes-32-long-here!!!!";
    let sk = SecretKeyFactory::from_secure_randomness(seed)
        .unwrap()
        .make_key(b"");
    let pk = sk.public_key();

    let signer = Signer::new(sk);
    let message = b"test message";
    let signature = signer.sign(message);

    assert!(signature.verify(&pk, message));
}

#[test]
fn test_encrypt_reencrypt_decrypt_flow() {
    let epoch_sk = SecretKey::random();
    let epoch_pk = epoch_sk.public_key();

    let member_sk = SecretKey::random();
    let member_pk = member_sk.public_key();

    let signer = Signer::new(epoch_sk.clone());

    let kfrags = generate_kfrags(
        &epoch_sk,
        &member_pk,
        &signer,
        1,
        1,
        true,
        true,
    );

    let vkfrags = kfrags.into_vec();
    let vkfrag = vkfrags.first().expect("expected at least one kfrag");
    let kfrag = vkfrag.clone().unverify().skip_verification();

    let plaintext = b"The quick brown fox jumps over the lazy dog.";
    let (capsule, ciphertext) = encrypt(&epoch_pk, plaintext).unwrap();

    let vcfrag = reencrypt(&capsule, kfrag);

    let decrypted = decrypt_reencrypted(
        &member_sk,
        &epoch_pk,
        &capsule,
        [vcfrag],
        &ciphertext,
    )
    .expect("decrypt_reencrypted failed");

    assert_eq!(&decrypted[..], plaintext);
}

fn serialize_public_key_hex(pk: &PublicKey) -> String {
    hex::encode(pk.to_compressed_bytes())
}

fn deserialize_capsule(bytes: &[u8]) -> Capsule {
    rmp_serde::from_slice(bytes).unwrap()
}

fn serialize_secret_key_hex(sk: &SecretKey) -> String {
    hex::encode(sk.to_be_bytes().as_secret())
}

fn deserialize_verified_capsule_frag(bytes: &[u8]) -> VerifiedCapsuleFrag {
    let cfrag: CapsuleFrag = rmp_serde::from_slice(bytes).unwrap();
    cfrag.skip_verification()
}

#[test]
fn test_cli_unit_encrypt_decrypt_roundtrip() {
    let epoch_sk = SecretKey::random();
    let epoch_pk = epoch_sk.public_key();
    let member_seed = [11u8; 32];
    let member_sk = SecretKeyFactory::from_secure_randomness(&member_seed)
        .unwrap()
        .make_key(b"");

    let signer = Signer::new(epoch_sk.clone());
    let kfrags = generate_kfrags(
        &epoch_sk,
        &member_sk.public_key(),
        &signer,
        1,
        1,
        true,
        true,
    );
    let kfrag = kfrags.into_vec().first().unwrap().clone().unverify().skip_verification();

    let plaintext = b"this-is-a-32-byte-dek-for-test!";
    let epoch_pk_hex = serialize_public_key_hex(&epoch_pk);
    let plaintext_hex = hex::encode(plaintext);

    let encrypt_result = cli::encrypt_hex(&epoch_pk_hex, &plaintext_hex).unwrap();

    let capsule_bytes = hex::decode(&encrypt_result.capsule_hex).unwrap();
    let capsule = deserialize_capsule(&capsule_bytes);
    let vcfrag = reencrypt(&capsule, kfrag);
    let vcfrag_hex = hex::encode(rmp_serde::to_vec(&vcfrag).unwrap());

    let member_sk_hex = hex::encode(member_seed);
    let recovered_hex = cli::decrypt_reencrypted_hex(
        &encrypt_result.capsule_hex,
        &vcfrag_hex,
        &encrypt_result.ciphertext_hex,
        &member_sk_hex,
        &epoch_pk_hex,
    )
    .unwrap();

    let recovered = hex::decode(recovered_hex).unwrap();
    assert_eq!(&recovered[..], plaintext);
}

#[test]
fn test_cli_subprocess_encrypt_produces_json() {
    let binary = env!("CARGO_BIN_EXE_wevibe-umbral");

    let epoch_sk = SecretKey::random();
    let epoch_pk = epoch_sk.public_key();

    let plaintext = b"this-is-a-32-byte-dek-for-test!";
    let epoch_pk_hex = serialize_public_key_hex(&epoch_pk);
    let plaintext_hex = hex::encode(plaintext);

    let encrypt_output = Command::new(binary)
        .args(["encrypt", "--epoch-pk", &epoch_pk_hex, "--plaintext", &plaintext_hex])
        .output()
        .expect("encrypt subprocess failed");

    assert!(encrypt_output.status.success(), "encrypt failed: {}", String::from_utf8_lossy(&encrypt_output.stderr));

    let encrypt_result: serde_json::Value = serde_json::from_slice(&encrypt_output.stdout)
        .expect("failed to parse encrypt JSON output");

    assert!(encrypt_result["capsule"].is_string(), "capsule should be string");
    assert!(encrypt_result["ciphertext"].is_string(), "ciphertext should be string");

    let capsule_hex = encrypt_result["capsule"].as_str().unwrap();
    let ciphertext_hex = encrypt_result["ciphertext"].as_str().unwrap();

    assert!(!capsule_hex.is_empty(), "capsule should not be empty");
    assert!(!ciphertext_hex.is_empty(), "ciphertext should not be empty");

    let capsule_bytes = hex::decode(capsule_hex).unwrap();
    let ciphertext_bytes = hex::decode(ciphertext_hex).unwrap();
    assert_eq!(capsule_bytes.len(), 105, "capsule should be 105 bytes");
    assert_eq!(ciphertext_bytes.len(), 71, "ciphertext should be 71 bytes");
}

#[test]
fn test_cli_subprocess_decrypt_reencrypted_produces_json() {
    let binary = env!("CARGO_BIN_EXE_wevibe-umbral");

    let epoch_sk = SecretKey::random();
    let epoch_pk = epoch_sk.public_key();
    let member_seed = [29u8; 32];
    let member_sk = SecretKeyFactory::from_secure_randomness(&member_seed)
        .unwrap()
        .make_key(b"");

    let signer = Signer::new(epoch_sk.clone());
    let kfrags = generate_kfrags(
        &epoch_sk,
        &member_sk.public_key(),
        &signer,
        1,
        1,
        true,
        true,
    );
    let kfrag = kfrags.into_vec().first().unwrap().clone().unverify().skip_verification();

    let plaintext = b"this-is-a-32-byte-dek-for-test!";
    let epoch_pk_hex = serialize_public_key_hex(&epoch_pk);
    let plaintext_hex = hex::encode(plaintext);

    let encrypt_output = Command::new(binary)
        .args(["encrypt", "--epoch-pk", &epoch_pk_hex, "--plaintext", &plaintext_hex])
        .output()
        .expect("encrypt subprocess failed");
    assert!(encrypt_output.status.success());

    let encrypt_result: serde_json::Value = serde_json::from_slice(&encrypt_output.stdout).unwrap();
    let cli_capsule_hex = encrypt_result["capsule"].as_str().unwrap();
    let cli_ciphertext_hex = encrypt_result["ciphertext"].as_str().unwrap();

    let capsule_bytes = hex::decode(cli_capsule_hex).unwrap();
    let capsule: Capsule = deserialize_capsule(&capsule_bytes);
    let _ciphertext_bytes = hex::decode(&cli_ciphertext_hex).unwrap();

    let vcfrag = reencrypt(&capsule, kfrag);
    let vcfrag_bytes = rmp_serde::to_vec(&vcfrag).unwrap();
    let vcfrag_hex = hex::encode(&vcfrag_bytes);

    let member_sk_hex = hex::encode(member_seed);

    let decrypt_output = Command::new(binary)
        .args([
            "decrypt-reencrypted",
            "--capsule", cli_capsule_hex,
            "--cfrags", &vcfrag_hex,
            "--ciphertext", cli_ciphertext_hex,
            "--receiving-sk", &member_sk_hex,
            "--delegating-pk", &epoch_pk_hex,
        ])
        .output()
        .expect("decrypt subprocess failed");

    if !decrypt_output.status.success() {
        eprintln!("decrypt stderr: {}", String::from_utf8_lossy(&decrypt_output.stderr));
    }

    let decrypt_result: serde_json::Value = serde_json::from_slice(&decrypt_output.stdout)
        .expect("failed to parse decrypt JSON output");

    assert!(decrypt_result["plaintext"].is_string(), "plaintext should be string");
    let recovered_hex = decrypt_result["plaintext"].as_str().unwrap();
    let recovered = hex::decode(recovered_hex).unwrap();
    assert_eq!(&recovered[..], plaintext);
}

#[test]
fn test_cli_subprocess_encrypt_invalid_hex_errors() {
    let binary = env!("CARGO_BIN_EXE_wevibe-umbral");

    let output = Command::new(binary)
        .args(["encrypt", "--epoch-pk", "zzzz", "--plaintext", "aa"])
        .output()
        .expect("encrypt subprocess failed");

    assert!(!output.status.success());
    let stderr: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("stderr should be JSON");
    assert!(stderr["error"].as_str().unwrap().contains("Invalid epoch_pk hex"));
}

#[test]
fn test_cli_subprocess_decrypt_empty_cfrags_errors() {
    let binary = env!("CARGO_BIN_EXE_wevibe-umbral");

    let epoch_sk = SecretKey::random();
    let epoch_pk = epoch_sk.public_key();
    let member_seed = [51u8; 32];

    let plaintext = b"this-is-a-32-byte-dek-for-test!";
    let epoch_pk_hex = serialize_public_key_hex(&epoch_pk);
    let plaintext_hex = hex::encode(plaintext);

    let encrypt_output = Command::new(binary)
        .args(["encrypt", "--epoch-pk", &epoch_pk_hex, "--plaintext", &plaintext_hex])
        .output()
        .expect("encrypt subprocess failed");
    assert!(encrypt_output.status.success());

    let encrypt_result: serde_json::Value = serde_json::from_slice(&encrypt_output.stdout).unwrap();
    let cli_capsule_hex = encrypt_result["capsule"].as_str().unwrap();
    let cli_ciphertext_hex = encrypt_result["ciphertext"].as_str().unwrap();

    let output = Command::new(binary)
        .args([
            "decrypt-reencrypted",
            "--capsule",
            cli_capsule_hex,
            "--cfrags",
            "",
            "--ciphertext",
            cli_ciphertext_hex,
            "--receiving-sk",
            &hex::encode(member_seed),
            "--delegating-pk",
            &epoch_pk_hex,
        ])
        .output()
        .expect("decrypt subprocess failed");

    assert!(!output.status.success());
    let stderr: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("stderr should be JSON");
    assert_eq!(stderr["error"].as_str().unwrap(), "cfrags must not be empty");
}

#[test]
fn test_cli_subprocess_decrypt_wrong_key_errors() {
    let binary = env!("CARGO_BIN_EXE_wevibe-umbral");

    let epoch_sk = SecretKey::random();
    let epoch_pk = epoch_sk.public_key();
    let member_seed = [71u8; 32];
    let member_sk = SecretKeyFactory::from_secure_randomness(&member_seed)
        .unwrap()
        .make_key(b"");
    let wrong_member_seed = [72u8; 32];

    let signer = Signer::new(epoch_sk.clone());
    let kfrags = generate_kfrags(
        &epoch_sk,
        &member_sk.public_key(),
        &signer,
        1,
        1,
        true,
        true,
    );
    let kfrag = kfrags.into_vec().first().unwrap().clone().unverify().skip_verification();

    let plaintext = b"this-is-a-32-byte-dek-for-test!";
    let epoch_pk_hex = serialize_public_key_hex(&epoch_pk);
    let plaintext_hex = hex::encode(plaintext);

    let encrypt_output = Command::new(binary)
        .args(["encrypt", "--epoch-pk", &epoch_pk_hex, "--plaintext", &plaintext_hex])
        .output()
        .expect("encrypt subprocess failed");
    assert!(encrypt_output.status.success());

    let encrypt_result: serde_json::Value = serde_json::from_slice(&encrypt_output.stdout).unwrap();
    let cli_capsule_hex = encrypt_result["capsule"].as_str().unwrap();
    let cli_ciphertext_hex = encrypt_result["ciphertext"].as_str().unwrap();

    let capsule_bytes = hex::decode(cli_capsule_hex).unwrap();
    let capsule: Capsule = deserialize_capsule(&capsule_bytes);
    let vcfrag = reencrypt(&capsule, kfrag);
    let vcfrag_hex = hex::encode(rmp_serde::to_vec(&vcfrag).unwrap());

    let output = Command::new(binary)
        .args([
            "decrypt-reencrypted",
            "--capsule",
            cli_capsule_hex,
            "--cfrags",
            &vcfrag_hex,
            "--ciphertext",
            cli_ciphertext_hex,
            "--receiving-sk",
            &hex::encode(wrong_member_seed),
            "--delegating-pk",
            &epoch_pk_hex,
        ])
        .output()
        .expect("decrypt subprocess failed");

    assert!(!output.status.success());
    let stderr: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("stderr should be JSON");
    assert!(stderr["error"]
        .as_str()
        .unwrap()
        .contains("decrypt_reencrypted failed"));
}
