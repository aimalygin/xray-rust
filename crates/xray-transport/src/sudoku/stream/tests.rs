use super::*;
use crate::sudoku::codec::{Decoder, PackedEncoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn classic_goes_up_and_packed_comes_down() {
    let config = SudokuConfig {
        password: "synthetic".into(),
        padding_min: 10,
        padding_max: 40,
        ..Default::default()
    };
    let (client, mut server) = tokio::io::duplex(1 << 20);
    let mut stream = SudokuStream::new(Box::new(client), &config).unwrap();
    let tables = config.tables().unwrap();
    // Up: classic sudoku, as Xray's server reads it.
    stream.write_all(b"hello from the client").await.unwrap();
    stream.flush().await.unwrap();
    let mut wire = vec![0; 4096];
    let n = server.read(&mut wire).await.unwrap();
    assert!(n >= 21 * 4);
    let mut decoded = Vec::new();
    Decoder::default()
        .decode(&tables, &wire[..n], &mut decoded)
        .unwrap();
    assert_eq!(decoded, b"hello from the client");
    // Down: packed, as Xray's server writes it, in two writes.
    let mut packed = Vec::new();
    let mut encoder = PackedEncoder::new(&tables, config.padding());
    encoder.encode(b"hello ", &mut packed);
    encoder.encode(b"back", &mut packed);
    server.write_all(&packed).await.unwrap();
    drop(server);
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"hello back");
}

#[tokio::test]
async fn bad_settings_fail_and_a_partial_group_ends_with_the_stream() {
    let bad = SudokuConfig {
        ascii: "text".into(),
        ..Default::default()
    };
    assert!(SudokuStream::new(Box::new(tokio::io::duplex(64).0), &bad).is_err());
    let config = SudokuConfig::default();
    let tables = config.tables().unwrap();
    let (client, mut server) = tokio::io::duplex(1024);
    let mut stream = SudokuStream::new(Box::new(client), &config).unwrap();
    // One packed group is six bits: no byte yet, and none at EOF.
    server
        .write_all(&[tables[0].layout.encode_group(0x15)])
        .await
        .unwrap();
    drop(server);
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    assert!(out.is_empty());
}

/// The dialer puts sudoku outside the `header-custom` handshake: the
/// handshake goes out encoded, and the server's answer comes back packed.
#[tokio::test]
async fn the_dialer_wraps_the_header_custom_handshake_in_sudoku() {
    use crate::header_custom::{CustomItem, HeaderCustomTcpConfig};
    use crate::{ConnectorConfig, TransportDialer};
    use xray_routing::{Network, Target, TargetAddr};
    let packet = |bytes: &[u8]| CustomItem {
        delay: (0, 0),
        rand: 0,
        rand_range: (0, 255),
        packet: bytes.to_vec(),
        capture: String::new(),
        reuse: String::new(),
        transform: None,
    };
    let config = SudokuConfig {
        password: "synthetic".into(),
        ..Default::default()
    };
    let tables = config.tables().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_tables = tables.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut decoder = Decoder::default();
        let mut plain = Vec::new();
        let mut wire = [0; 1024];
        // The handshake, encoded: two bytes are eight clues.
        while plain.len() < 2 {
            let n = socket.read(&mut wire).await.unwrap();
            decoder
                .decode(&server_tables, &wire[..n], &mut plain)
                .unwrap();
        }
        assert_eq!(&plain[..2], b"HI");
        let mut reply = Vec::new();
        PackedEncoder::new(&server_tables, (0, 0)).encode(b"OK", &mut reply);
        socket.write_all(&reply).await.unwrap();
        while plain.len() < 6 {
            let n = socket.read(&mut wire).await.unwrap();
            decoder
                .decode(&server_tables, &wire[..n], &mut plain)
                .unwrap();
        }
        plain
    });
    let dialer = TransportDialer::system()
        .unwrap()
        .with_tcp_header_custom(Arc::new(HeaderCustomTcpConfig {
            clients: vec![vec![packet(b"HI")]],
            servers: vec![vec![packet(b"OK")]],
        }))
        .with_tcp_sudoku(Arc::new(config));
    let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
    let mut client = dialer
        .connect_resolved(&ConnectorConfig::Tcp, &target, &[address], None)
        .await
        .unwrap();
    client.write_all(b"data").await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(server.await.unwrap(), b"HIdata");
}
