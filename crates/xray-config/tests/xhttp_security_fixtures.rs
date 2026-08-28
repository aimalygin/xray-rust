use xray_config::{
    parse_xray_json, RealityShortId, StreamSecurity, StreamTransport, XhttpMode, XhttpRange,
};

#[test]
fn parses_xhttp_tls_h2_share_link_equivalent_fixture() {
    let parsed = parse_xray_json(include_str!(
        "../../../tests/fixtures/configs/vless_xhttp_tls_h2.json"
    ))
    .expect("XHTTP + TLS fixture should parse");
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);

    let outbound = &parsed.config.outbounds[0];
    let StreamSecurity::Tls(tls) = &outbound.stream.security else {
        panic!("expected TLS security");
    };
    assert_eq!(tls.server_name.as_deref(), Some("edge.example"));
    assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
    assert_eq!(tls.alpn, ["h2"]);
    assert!(!tls.allow_insecure);

    let StreamTransport::Xhttp(xhttp) = &outbound.stream.transport else {
        panic!("expected XHTTP transport");
    };
    assert_eq!(xhttp.host.as_deref(), Some("edge.example"));
    assert_eq!(xhttp.path, "/share-link");
    assert_eq!(xhttp.mode, XhttpMode::PacketUp);
    assert_eq!(
        xhttp.sc_max_each_post_bytes,
        XhttpRange {
            from: 500_000,
            to: 500_000,
        }
    );
    assert_eq!(
        xhttp.sc_min_posts_interval_ms,
        XhttpRange { from: 60, to: 60 }
    );
    assert_eq!(xhttp.xmux.max_connections, XhttpRange { from: 16, to: 16 });
}

#[test]
fn parses_xhttp_reality_h2_share_link_equivalent_fixture() {
    let parsed = parse_xray_json(include_str!(
        "../../../tests/fixtures/configs/vless_xhttp_reality_h2.json"
    ))
    .expect("XHTTP + REALITY fixture should parse");
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);

    let outbound = &parsed.config.outbounds[0];
    let StreamSecurity::Reality(reality) = &outbound.stream.security else {
        panic!("expected REALITY security");
    };
    assert_eq!(reality.server_name, "www.example.com");
    assert_eq!(reality.fingerprint, "chrome");
    assert_eq!(reality.public_key, [1; 32]);
    assert_eq!(
        reality.short_id,
        RealityShortId::try_from_slice(&[2, 3, 4, 5]).unwrap()
    );
    assert_eq!(reality.spider_x, "/");

    let StreamTransport::Xhttp(xhttp) = &outbound.stream.transport else {
        panic!("expected XHTTP transport");
    };
    assert_eq!(xhttp.host, None);
    assert_eq!(xhttp.path, "/share-link");
    assert_eq!(xhttp.mode, XhttpMode::Auto);
    assert_eq!(xhttp.xmux.max_connections, XhttpRange { from: 16, to: 16 });
}
