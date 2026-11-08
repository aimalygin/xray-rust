use super::*;

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// Xray-core's own `DeriveRSAKey` and `MarshalPKIXPublicKey`
/// (`tools/xmc-oracle`).
#[test]
fn derives_the_key_xray_core_derives() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/xmc/vectors.json"
    ))
    .unwrap();
    for key in vectors["keys"].as_array().unwrap() {
        let password = key["password"].as_str().unwrap();
        assert_eq!(
            derived_public_key(password).pkix,
            unhex(key["publicKey"].as_str().unwrap()),
            "{password}"
        );
    }
}

#[test]
fn pkcs1_encryption_pads_with_nonzero_bytes_and_round_trips() {
    let key = derived_public_key("synthetic-xmc-password");
    let message = b"0123456789abcdef";
    let first = key.encrypt(message).unwrap();
    let second = key.encrypt(message).unwrap();
    assert_eq!(first.len(), 128);
    assert_ne!(first, second, "padding is random");
    let private = derived_private_key("synthetic-xmc-password");
    assert_eq!(private.decrypt(&first).unwrap(), message);
    assert_eq!(private.decrypt(&second).unwrap(), message);
    // 117 bytes is the most a 1024-bit key carries.
    let longest = key.encrypt(&[0xa5; 117]).unwrap();
    assert_eq!(private.decrypt(&longest).unwrap(), [0xa5; 117]);
    assert!(key.encrypt(&[0; 118]).is_err());
    // A leading zero in the ciphertext keeps its length.
    for _ in 0..300 {
        let cipher = key.encrypt(b"").unwrap();
        assert_eq!(cipher.len(), 128);
        assert_eq!(private.decrypt(&cipher).unwrap(), b"");
    }
}
