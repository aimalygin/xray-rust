use super::*;

#[test]
fn escapes_the_name_twice_as_go_does() {
    assert_eq!(request_path("my-server_1"), "/v1/my-server_1/connect");
    assert_eq!(request_path("a/b c"), "/v1/a%252Fb%2520c/connect");
    assert_eq!(request_path("x?y;z"), "/v1/x%253Fy%253Bz/connect");
}

#[test]
fn decodes_the_answer_as_go_does() {
    assert_eq!(
        decode_connect_response(br#"{"addresses":["198.51.100.1:1"],"nonce":"n","obfs":"o"}"#)
            .unwrap(),
        vec!["198.51.100.1:1".to_owned()]
    );
    assert_eq!(
        decode_connect_response(br#"{"Addresses":["a",null]} trailing"#).unwrap(),
        vec!["a".to_owned(), String::new()]
    );
    assert!(decode_connect_response(b"null").unwrap().is_empty());
    assert!(decode_connect_response(b"{}").unwrap().is_empty());
    for refused in [
        &b""[..],
        b"   ",
        b"[]",
        b"\"x\"",
        br#"{"addresses":"a"}"#,
        br#"{"addresses":[1]}"#,
        br#"{"nonce":5}"#,
        b"{\"addresses\":[",
    ] {
        assert!(
            decode_connect_response(refused).is_err(),
            "{}",
            String::from_utf8_lossy(refused)
        );
    }
}

#[test]
fn writes_the_request_body_as_json_marshal_does() {
    let meta = super::super::punch::PunchMetadata {
        nonce: [0xab; 16],
        obfs: [0x01; 32],
    };
    let body = connect_body(&["198.51.100.1:1".into(), "[2001:db8::1]:2".into()], &meta);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        format!(
            r#"{{"addresses":["198.51.100.1:1","[2001:db8::1]:2"],"nonce":"{}","obfs":"{}"}}"#,
            "ab".repeat(16),
            "01".repeat(32)
        )
    );
    let mut escaped = String::new();
    push_json_string(&mut escaped, "<a&b>\"\\\n\u{1}\u{2028}");
    assert_eq!(escaped, r#""\u003ca\u0026b\u003e\"\\\n\u0001\u2028""#);
}
