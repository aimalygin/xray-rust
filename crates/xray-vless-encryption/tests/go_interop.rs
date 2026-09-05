use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use xray_vless_encryption::{CipherSuite, Client, Encryption};

#[path = "../../../tools/vless-encryption-oracle/support.rs"]
mod support;
use support::Oracle;

async fn echo(client: &Client, address: std::net::SocketAddr, suite: CipherSuite, payload: &[u8]) {
    let wire = TcpStream::connect(address).await.unwrap();
    let mut stream = client.connect_with_cipher(wire, suite).await.unwrap();
    stream.write_all(payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
#[ignore = "requires the guarded pinned Go oracle; run scripts/check-vless-encryption-oracle.sh"]
async fn pinned_go_1rtt_matrix() {
    for mode in ["native", "xorpub", "random"] {
        for kind in ["x25519", "mlkem768"] {
            for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
                let oracle = Oracle::start(mode, kind, -1, "echo");
                assert!(oracle.tls_pin.is_empty());
                let config: Encryption = oracle.encryption.parse().unwrap();
                tokio::time::timeout(Duration::from_secs(10), async {
                    let wire = TcpStream::connect(oracle.address).await.unwrap();
                    let stream = config
                        .client()
                        .unwrap()
                        .connect_with_cipher(wire, suite)
                        .await
                        .unwrap();
                    let (mut read, mut write) = tokio::io::split(stream);
                    let payload: Vec<u8> = (0..65539).map(|n| (n % 251) as u8).collect();
                    let send = async {
                        write.write_all(&payload).await.unwrap();
                        write.shutdown().await.unwrap();
                    };
                    let receive = async {
                        let mut data = Vec::new();
                        read.read_to_end(&mut data).await.unwrap();
                        assert_eq!(data, payload, "{mode}, {kind}, {suite:?}");
                    };
                    tokio::join!(send, receive);
                })
                .await
                .unwrap();
                oracle.finish();
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires the guarded pinned Go oracle; run scripts/check-vless-encryption-oracle.sh"]
async fn pinned_go_0rtt_chained_keys_and_configured_padding() {
    for mode in ["native", "xorpub", "random"] {
        for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
            let oracle = Oracle::start(mode, "x25519+mlkem768+x25519", -1, "session");
            let config: Encryption = oracle.encryption.parse().unwrap();
            let client = Client::new(config.client().unwrap().clone());
            tokio::time::timeout(Duration::from_secs(10), async {
                // The oracle asserts that this first exchange is cold and the
                // second uses the shorter resumed wire path.
                echo(&client, oracle.address, suite, b"cold ticket exchange").await;
                echo(&client, oracle.address, suite, b"authenticated early data").await;
            })
            .await
            .unwrap();
            oracle.finish();
        }
    }
}

#[tokio::test]
#[ignore = "requires the guarded pinned Go oracle; run scripts/check-vless-encryption-oracle.sh"]
async fn rejected_or_cancelled_0rtt_is_not_retried_or_reused() {
    for scenario in ["expire", "cancel"] {
        let oracle = Oracle::start("random", "x25519+mlkem768", -1, scenario);
        let config: Encryption = oracle.encryption.parse().unwrap();
        let client = Client::new(config.client().unwrap().clone());
        tokio::time::timeout(Duration::from_secs(10), async {
            echo(
                &client,
                oracle.address,
                CipherSuite::Aes256Gcm,
                b"populate ticket",
            )
            .await;

            let wire = TcpStream::connect(oracle.address).await.unwrap();
            let mut resumed = client.connect(wire).await.unwrap();
            if scenario == "cancel" {
                // Dropping before prewrite must invalidate the leased ticket.
                drop(resumed);
            } else {
                resumed
                    .write_all(b"never retry this early data")
                    .await
                    .unwrap();
                resumed.shutdown().await.unwrap();
                let mut exposed = Vec::new();
                assert!(resumed.read_to_end(&mut exposed).await.is_err());
                assert!(exposed.is_empty());
            }

            // The oracle asserts this third connection is a fresh 1-RTT
            // handshake. No rejected early data is sent a second time.
            echo(
                &client,
                oracle.address,
                CipherSuite::Aes256Gcm,
                b"fresh after invalidation",
            )
            .await;
        })
        .await
        .unwrap();
        oracle.finish();
    }
}

#[tokio::test]
#[ignore = "requires the guarded pinned Go oracle; run scripts/check-vless-encryption-oracle.sh"]
async fn pinned_go_corrupted_handshake_and_records_fail_closed() {
    for mode in ["native", "random"] {
        for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
            // PFS key/tag, ticket, padding length, padding, record header/body.
            for offset in [0, 1135, 1136, 1168, 1186, 1203, 1220] {
                let oracle = Oracle::start(mode, "x25519", offset, "echo");
                let config: Encryption = oracle.encryption.parse().unwrap();
                tokio::time::timeout(Duration::from_secs(5), async {
                    let wire = TcpStream::connect(oracle.address).await.unwrap();
                    let result = config
                        .client()
                        .unwrap()
                        .connect_with_cipher(wire, suite)
                        .await;
                    if offset < 1186 {
                        assert!(result.is_err(), "corrupted handshake accepted at {offset}");
                    } else {
                        let mut stream = result.unwrap();
                        stream.write_all(b"authenticated response").await.unwrap();
                        stream.flush().await.unwrap();
                        let mut output = Vec::new();
                        assert!(stream.read_to_end(&mut output).await.is_err());
                        assert!(output.is_empty());
                        assert!(stream.write_all(b"after failure").await.is_err());
                    }
                })
                .await
                .unwrap();
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires the guarded pinned Go oracle; run scripts/check-vless-encryption-oracle.sh"]
async fn pinned_go_wrong_key_and_truncated_replies_fail_closed() {
    let wrong = Oracle::start("native", "x25519", -1, "echo");
    let wrong_config: Encryption = wrong.encryption.parse().unwrap();
    drop(wrong);
    let oracle = Oracle::start("native", "x25519", -1, "echo");
    let wire = TcpStream::connect(oracle.address).await.unwrap();
    assert!(wrong_config.client().unwrap().connect(wire).await.is_err());
    drop(oracle);
    for cutoff in [0, 1, 16, 1135, 1167, 1185, 1202, 1204, 1220] {
        let oracle = Oracle::start("random", "mlkem768", -cutoff - 2, "echo");
        let config: Encryption = oracle.encryption.parse().unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            let wire = TcpStream::connect(oracle.address).await.unwrap();
            let result = config.client().unwrap().connect(wire).await;
            if cutoff < 1186 {
                assert!(result.is_err());
            } else {
                let mut stream = result.unwrap();
                // The peer may close before this request is delivered.
                let _ = stream
                    .write_all(b"response requiring complete authentication")
                    .await;
                let mut output = Vec::new();
                assert!(stream.read_to_end(&mut output).await.is_err());
                assert!(output.is_empty());
            }
        })
        .await
        .unwrap_or_else(|_| panic!("truncated reply at {cutoff} timed out"));
    }
}
