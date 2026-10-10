use super::*;
use serde_json::Value;
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn fixture() -> Value {
    serde_json::from_str::<Value>(include_str!(
        "../../../../tests/fixtures/v08/protocol-primitives.json"
    ))
    .unwrap()["vmess"]
        .clone()
}
#[test]
fn vmess_kdf_auth_id_and_command_key_match_pinned_go() {
    let f = fixture();
    let id = uuid::Uuid::parse_str(f["id"].as_str().unwrap()).unwrap();
    let account = Account::new(id.as_bytes(), Cipher::Aes128Gcm, Options::default());
    assert_eq!(
        account.command_key.as_slice(),
        unhex(f["commandKey"].as_str().unwrap())
    );
    assert_eq!(
        crypto::auth_id(&*account.command_key, 1700000000, &[0x33; 4]).as_slice(),
        unhex(f["authId"].as_str().unwrap())
    );
    for case in f["kdf"].as_array().unwrap() {
        let path: Vec<Vec<u8>> = case["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| unhex(v.as_str().unwrap()))
            .collect();
        let refs: Vec<&[u8]> = path.iter().map(|v| v.as_slice()).collect();
        assert_eq!(
            crypto::kdf(&*account.command_key, &refs).as_slice(),
            unhex(case["output"].as_str().unwrap())
        );
    }
}
#[test]
fn vmess_records_match_pinned_go_masking_padding_and_authenticated_length() {
    for case in fixture()["records"].as_array().unwrap() {
        let key: [u8; 16] = unhex(case["key"].as_str().unwrap()).try_into().unwrap();
        let iv: [u8; 16] = unhex(case["iv"].as_str().unwrap()).try_into().unwrap();
        let cipher = Cipher::parse(case["method"].as_str().unwrap()).unwrap();
        let auth = case["authenticatedLength"]
            .as_bool()
            .unwrap()
            .then_some((&key, &iv));
        let mut writer = records::Records::new(cipher, &key, &iv, auth);
        let mut reader = records::Records::new(cipher, &key, &iv, auth);
        for chunk in case["chunks"].as_array().unwrap() {
            let payload = unhex(chunk["payload"].as_str().unwrap());
            let padding = chunk["padding"].as_u64().unwrap() as usize;
            let mut wire = writer.seal(&payload).unwrap();
            let end = wire.len();
            wire[end - padding..].fill(0);
            assert_eq!(wire.as_slice(), unhex(chunk["wire"].as_str().unwrap()));
            let n = reader.size_bytes();
            let mut length = wire[..n].to_vec();
            let (size, pad) = reader.decode_length(&mut length).unwrap();
            assert_eq!((size, pad), (wire.len() - n, padding));
            let mut body = wire[n..].to_vec();
            reader.open(&mut body, pad).unwrap();
            assert_eq!(body, payload);
        }
    }
}

#[test]
fn vmess_reuses_bounded_frames_with_both_length_encodings() {
    for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
        for authenticated in [false, true] {
            let (key, iv) = ([9; 16], [6; 16]);
            let auth = authenticated.then_some((&key, &iv));
            let mut writer = records::Records::new(cipher, &key, &iv, auth);
            let mut reader = records::Records::new(cipher, &key, &iv, auth);
            let mut wire = Zeroizing::new(Vec::new());
            let mut pointer = std::ptr::null();
            for i in 0..128 {
                let len = if i % 2 == 0 { writer.max_payload() } else { i };
                let payload = vec![i as u8; len];
                writer.seal_into(&payload, &mut wire).unwrap();
                assert!(wire.len() <= 8192);
                assert!(wire.capacity() <= 8192);
                if i == 0 {
                    pointer = wire.as_ptr();
                }
                assert_eq!(wire.as_ptr(), pointer);
                let n = reader.size_bytes();
                let mut length = wire[..n].to_vec();
                let (size, padding) = reader.decode_length(&mut length).unwrap();
                assert_eq!(size, wire.len() - n);
                let mut body = wire[n..].to_vec();
                reader.open(&mut body, padding).unwrap();
                assert_eq!(body, payload);
                wire.as_mut_slice().zeroize();
                wire.clear();
            }
        }
    }
}
#[test]
fn vmess_invalid_ciphers_and_destinations_fail_closed() {
    for cipher in ["none", "zero", "aes-128-cfb", "synthetic-secret"] {
        assert!(Cipher::parse(cipher).is_err());
    }
    for target in [
        Target::new(TargetAddr::Domain("".into()), 443, Network::Tcp),
        Target::new(
            TargetAddr::Ip("192.0.2.1".parse().unwrap()),
            0,
            Network::Udp,
        ),
        Target::new(TargetAddr::Domain("x".repeat(256)), 443, Network::Tcp),
    ] {
        assert!(Account::validate_target(&target).is_err());
    }
    let account = Account::new(&[0x55; 16], Cipher::Aes128Gcm, Options::default());
    assert!(!format!("{account:?}").contains("5555"));
}
