use std::io::Cursor;
use xray_proxy::inbound::{parse_http_connect, parse_socks5_connect};
use xray_routing::{Network, TargetAddr};

#[tokio::test]
async fn parses_socks5_connect_domain_target() {
    let bytes = [
        0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        b'.', b'c', b'o', b'm', 0x01, 0xbb,
    ];

    let target = parse_socks5_connect(Cursor::new(bytes)).await.unwrap();

    assert_eq!(target.network, Network::Tcp);
    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
}

#[tokio::test]
async fn parses_http_connect_domain_target() {
    let raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";

    let target = parse_http_connect(Cursor::new(raw)).await.unwrap();

    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
}
