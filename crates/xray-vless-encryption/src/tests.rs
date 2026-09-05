use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::*;
use crypto::{derive, Aead, HeaderMask, MAX_NONCE};
use session::{Cache, Candidate, Prepared};

fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(197).wrapping_add(131)) as u8)
        .collect()
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn binary_kdf_and_both_aeads_match_pinned_go_vectors() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/vless-encryption/primitives.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["upstream"],
        "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
    );
    for vector in fixture["vectors"].as_array().unwrap() {
        let context = unhex(vector["context"].as_str().unwrap());
        let material = unhex(vector["material"].as_str().unwrap());
        assert_eq!(
            derive(&context, &material).as_slice(),
            unhex(vector["derived"].as_str().unwrap())
        );
        for (name, suite) in [
            ("aes", CipherSuite::Aes256Gcm),
            ("chacha", CipherSuite::ChaCha20Poly1305),
        ] {
            let mut aead = Aead::new(&context, &material, suite).unwrap();
            let mut data = pattern(31);
            aead.seal(&mut data, &[23, 3, 3, 0, 47]).unwrap();
            assert_eq!(data, unhex(vector[name].as_str().unwrap()));
            assert_eq!(aead.nonce[11], 1);
        }
    }
    let mut mask = HeaderMask::new(&pattern(96), pattern(16).as_slice().try_into().unwrap());
    let mut data = pattern(1088);
    // CTR state must survive arbitrary header/key-blob fragmentation.
    for chunk in data.chunks_mut(5) {
        mask.apply(chunk).unwrap();
    }
    assert_eq!(data, unhex(fixture["ctr"].as_str().unwrap()));
}

#[test]
fn byte_context_api_preserves_utf8_api() {
    for context in ["", "VLESS", "ключ 🔑"] {
        assert_eq!(
            *derive(context.as_bytes(), &pattern(96)),
            blake3::derive_key(context, &pattern(96))
        );
    }
}

fn config_string(mode: &str) -> String {
    let key = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x23; 32]));
    format!(
        "mlkem768x25519plus.{mode}.1rtt.{}",
        URL_SAFE_NO_PAD.encode(key.as_bytes())
    )
}

#[test]
fn config_is_bounded_strict_and_redacted() {
    assert!("none".parse::<Encryption>().unwrap().is_none());
    for mode in ["native", "xorpub", "random"] {
        let text = config_string(mode);
        let config: Encryption = text.parse().unwrap();
        let key = text.rsplit('.').next().unwrap();
        assert!(!format!("{config:?}").contains(key));
        for accepted in [
            text.replace("1rtt", "0rtt"),
            format!("{text}.{key}"),
            text.replace(".1rtt.", ".1rtt.100-35-35."),
            text.replace(".1rtt.", ".0rtt.100-35-64.100-0-1.50-128-512."),
        ] {
            let accepted: Encryption = accepted.parse().unwrap();
            assert!(!format!("{accepted:?}").contains(key));
        }
        for rejected in [
            format!("{text}="),
            text.replace(mode, "bad-mode"),
            text.replace(key, &URL_SAFE_NO_PAD.encode([0; 32])),
            text.replace(key, &"A".repeat(2000)),
            format!("{text}.{key}.{key}.{key}.{key}.{key}.{key}.{key}.{key}"),
            text.replace(".1rtt.", ".1rtt.99-35-35."),
            text.replace(".1rtt.", ".1rtt.100-34-35."),
            text.replace(".1rtt.", ".1rtt.101-35-35."),
            text.replace(".1rtt.", ".1rtt.100-35-35.100-0-1001."),
            text.replace(".1rtt.", ".1rtt.100-35-65554."),
        ] {
            let error = rejected.parse::<Encryption>().unwrap_err();
            assert!(!format!("{error:?} {error}").contains(key));
        }
    }
}

fn pair(
    capacity: usize,
    random: bool,
    suite: CipherSuite,
) -> (
    EncryptedStream<tokio::io::DuplexStream>,
    EncryptedStream<tokio::io::DuplexStream>,
) {
    let (left, right) = tokio::io::duplex(capacity);
    let key = [0x56; 96];
    let make = |inner, client| {
        let (send, receive, iv1, iv2) = if client {
            (b"client", b"server", [1; 16], [2; 16])
        } else {
            (b"server", b"client", [2; 16], [1; 16])
        };
        EncryptedStream::new(
            inner,
            Zeroizing::new(key),
            Aead::new(send, &key, suite).unwrap(),
            Some(Aead::new(receive, &key, suite).unwrap()),
            random.then(|| (HeaderMask::new(&key, &iv1), HeaderMask::new(&key, &iv2))),
            0,
        )
    };
    (make(left, true), make(right, false))
}

#[tokio::test]
async fn records_survive_fragmentation_backpressure_and_half_close() {
    for random in [false, true] {
        for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
            let (mut left, mut right) = pair(7, random, suite);
            let payload = pattern(20003);
            let client = async {
                left.write_all(&payload).await.unwrap();
                left.shutdown().await.unwrap();
                let mut echo = Vec::new();
                left.read_to_end(&mut echo).await.unwrap();
                assert_eq!(echo, b"received");
                assert!(left.write_all(b"after close").await.is_err());
            };
            let server = async {
                let mut received = Vec::new();
                right.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, payload);
                right.write_all(b"received").await.unwrap();
                right.shutdown().await.unwrap();
            };
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(client, server);
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn simultaneous_bidirectional_backpressure_does_not_deadlock() {
    let (left, right) = pair(1, true, CipherSuite::Aes256Gcm);
    let exchange = |stream| async move {
        let (mut read, mut write) = tokio::io::split(stream);
        let sender = async {
            write.write_all(&pattern(17000)).await.unwrap();
            write.shutdown().await.unwrap();
        };
        let receiver = async {
            let mut data = Vec::new();
            read.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, pattern(17000));
        };
        tokio::join!(sender, receiver);
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(exchange(left), exchange(right));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn pending_flush_and_partial_read_survive_cancellation() {
    let (mut left, mut right) = pair(1, true, CipherSuite::ChaCha20Poly1305);
    left.write_all(b"first").await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(1), left.flush())
        .await
        .is_err());
    let mut data = [0; 5];
    assert!(
        tokio::time::timeout(Duration::from_millis(1), right.read_exact(&mut data))
            .await
            .is_err()
    );
    let sender = async {
        left.flush().await.unwrap();
        left.write_all(b"second").await.unwrap();
        left.shutdown().await.unwrap();
    };
    let receiver = async {
        let mut data = Vec::new();
        right.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"firstsecond");
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(sender, receiver);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn nonce_wrap_rekeys_both_directions_after_authenticated_record() {
    let (mut left, mut right) = pair(4096, true, CipherSuite::Aes256Gcm);
    left.write_aead.nonce = MAX_NONCE;
    right.read_aead.as_mut().unwrap().nonce = MAX_NONCE;
    for data in [b"wrap".as_slice(), b"new key"] {
        left.write_all(data).await.unwrap();
        left.flush().await.unwrap();
        let mut received = vec![0; data.len()];
        right.read_exact(&mut received).await.unwrap();
        assert_eq!(received, data);
    }
    assert_eq!(left.write_aead.nonce[11], 1);
    assert_eq!(right.read_aead.as_ref().unwrap().nonce[11], 1);
}

#[tokio::test]
async fn malformed_records_poison_stream_and_never_expose_plaintext() {
    for case in 0..10 {
        let (wire, mut peer) = tokio::io::duplex(4096);
        let key = [9; 96];
        let mut stream = EncryptedStream::new(
            wire,
            Zeroizing::new(key),
            Aead::new(b"send", &key, CipherSuite::Aes256Gcm).unwrap(),
            Some(Aead::new(b"recv", &key, CipherSuite::Aes256Gcm).unwrap()),
            None,
            0,
        );
        let mut header = [23, 3, 3, 0, 20];
        let mut body = b"data".to_vec();
        Aead::new(b"recv", &key, CipherSuite::Aes256Gcm)
            .unwrap()
            .seal(&mut body, &header)
            .unwrap();
        match case {
            0 => header[0] = 22,
            1 => header[4] = 16,
            2 => {
                header[3] = 65;
                header[4] = 1;
            } // 16641
            3 => body[19] ^= 1,
            _ => (),
        }
        let mut data = header.to_vec();
        data.extend_from_slice(&body);
        if case >= 4 {
            data.truncate([1, 2, 4, 5, 6, 24][case - 4]);
        }
        peer.write_all(&data).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut output = Vec::new();
        assert!(stream.read_to_end(&mut output).await.is_err());
        assert!(output.is_empty());
        assert!(stream.write_all(b"must not send").await.is_err());
        assert!(stream.read_u8().await.is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn handshake_deadline_drops_carrier() {
    let config: Encryption = config_string("native").parse().unwrap();
    let (stream, mut peer) = tokio::io::duplex(8192);
    let result = config.client().unwrap().connect(stream).await;
    assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::TimedOut));
    let mut hello = Vec::new();
    peer.read_to_end(&mut hello).await.unwrap();
    assert!(!hello.is_empty());
}

#[tokio::test(start_paused = true)]
async fn resumed_confirmation_obeys_handshake_deadline_and_invalidates_ticket() {
    let cache = Cache::default();
    let Prepared::Fresh(epoch) = cache.prepare().unwrap() else {
        panic!("cache must be empty")
    };
    Candidate::new(cache.clone(), epoch, Zeroizing::new([7; 64]), [9; 16], 60).publish();
    let Prepared::Resume(resumption) = cache.prepare().unwrap() else {
        panic!("ticket must be available")
    };
    let (carrier, _peer) = tokio::io::duplex(64);
    let key = [5; 96];
    let mut stream = EncryptedStream::resumed(
        carrier,
        Zeroizing::new(key),
        Aead::new(b"write", &key, CipherSuite::Aes256Gcm).unwrap(),
        None,
        vec![1, 2, 3],
        resumption.lease,
        tokio::time::Instant::now() + handshake::HANDSHAKE_TIMEOUT,
    );

    tokio::time::advance(handshake::HANDSHAKE_TIMEOUT + Duration::from_secs(1)).await;
    let error = stream.write_all(b"request").await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(matches!(cache.prepare().unwrap(), Prepared::Fresh(_)));
}

#[tokio::test]
async fn replayed_records_and_reflected_direction_are_rejected() {
    let (mut left, mut right) = pair(4096, false, CipherSuite::Aes256Gcm);
    left.write_all(b"once").await.unwrap();
    left.flush().await.unwrap();
    let mut record = [0; 25];
    right.inner.read_exact(&mut record).await.unwrap();
    left.inner.write_all(&record).await.unwrap();
    left.inner.write_all(&record).await.unwrap();
    let mut plain = [0; 4];
    right.read_exact(&mut plain).await.unwrap();
    assert_eq!(&plain, b"once");
    assert!(right.read_exact(&mut plain).await.is_err());

    // A client-to-server record cannot authenticate in the reverse direction.
    let (mut left, mut right) = pair(4096, false, CipherSuite::Aes256Gcm);
    right.inner.write_all(&record).await.unwrap();
    assert!(left.read_exact(&mut plain).await.is_err());
}

#[tokio::test]
async fn plaintext_peer_is_never_a_downgrade_fallback() {
    let config: Encryption = config_string("native").parse().unwrap();
    let (stream, mut peer) = tokio::io::duplex(8192);
    peer.write_all(&[0; 1203]).await.unwrap();
    peer.shutdown().await.unwrap();
    assert!(config.client().unwrap().connect(stream).await.is_err());
    let mut sent = Vec::new();
    peer.read_to_end(&mut sent).await.unwrap();
    assert!(sent.len() > 1298); // Only an encrypted client hello was sent.
}

#[tokio::test]
async fn maximum_peer_padding_and_record_are_bounded_and_authenticated() {
    let (wire, mut peer) = tokio::io::duplex(100_000);
    let key = [7; 96];
    let mut receive = Aead::new(b"recv", &key, CipherSuite::ChaCha20Poly1305).unwrap();
    receive.nonce[11] = 2; // ticket and padding length already authenticated
    let mut sender = Aead::new(b"recv", &key, CipherSuite::ChaCha20Poly1305).unwrap();
    sender.nonce[11] = 2;
    let mut stream = EncryptedStream::new(
        wire,
        Zeroizing::new(key),
        Aead::new(b"send", &key, CipherSuite::ChaCha20Poly1305).unwrap(),
        Some(receive),
        None,
        65535,
    );
    let mut padding = vec![0; 65535 - 16];
    sender.seal(&mut padding, &[]).unwrap();
    peer.write_all(&padding).await.unwrap();
    let header = [23, 3, 3, 65, 0]; // 16640 ciphertext bytes
    let plain = pattern(16640 - 16);
    let mut body = plain.clone();
    sender.seal(&mut body, &header).unwrap();
    peer.write_all(&header).await.unwrap();
    peer.write_all(&body).await.unwrap();
    peer.shutdown().await.unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), plain[0]);
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, plain[1..]);
    assert!(stream.body.capacity() <= 65535);
}

#[tokio::test]
async fn cancelling_a_handshake_drops_carrier_and_retry_uses_fresh_iv() {
    let config: Encryption = config_string("native").parse().unwrap();
    let mut previous = None;
    for _ in 0..2 {
        let (stream, mut peer) = tokio::io::duplex(8192);
        let mut handshake = Box::pin(config.client().unwrap().connect(stream));
        let mut iv = [0; 16];
        tokio::select! {
            _ = &mut handshake => panic!("handshake must wait for peer"),
            result = peer.read_exact(&mut iv) => { result.unwrap(); }
        }
        drop(handshake);
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        if let Some(previous) = previous {
            assert_ne!(iv, previous);
        }
        previous = Some(iv);
    }
}

async fn write_direct<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut EncryptedStream<S>,
    bytes: &[u8],
) {
    for fragment in bytes.chunks(3) {
        let mut remaining = fragment;
        while !remaining.is_empty() {
            let n = std::future::poll_fn(|cx| stream.poll_write_vision_direct(cx, remaining))
                .await
                .unwrap();
            remaining = &remaining[n..];
        }
    }
    stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn vision_direct_retains_decrypted_tail_and_fragmented_random_mask() {
    for random in [false, true] {
        let (mut left, mut right) = pair(1, random, CipherSuite::Aes256Gcm);
        let mut tls = Vec::new();
        for size in [17u16, 8193, 16640, 31] {
            tls.extend_from_slice(&[23, 3, 3]);
            tls.extend_from_slice(&size.to_be_bytes());
            tls.extend_from_slice(&pattern(size as usize));
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            let send = async {
                // This entire record is authenticated before a one-byte caller
                // read; the remaining bytes must survive the direct transition.
                left.write_all(b"Dtail").await.unwrap();
                // A cancelled flush cannot duplicate output or CTR advancement.
                assert!(tokio::time::timeout(Duration::from_millis(1), left.flush())
                    .await
                    .is_err());
                write_direct(&mut left, &tls).await;
                let mut ack = Vec::new();
                left.read_to_end(&mut ack).await.unwrap();
                assert_eq!(ack, b"reverse stays encrypted");
            };
            let receive = async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                assert_eq!(right.read_u8().await.unwrap(), b'D');
                let mut actual = Vec::new();
                loop {
                    let mut byte = [0];
                    let mut buf = tokio::io::ReadBuf::new(&mut byte);
                    std::future::poll_fn(|cx| right.poll_read_vision_direct(cx, &mut buf))
                        .await
                        .unwrap();
                    if buf.filled().is_empty() {
                        break;
                    }
                    actual.extend_from_slice(buf.filled());
                }
                assert_eq!(&actual[..4], b"tail");
                assert_eq!(&actual[4..], tls);
                right.write_all(b"reverse stays encrypted").await.unwrap();
                right.shutdown().await.unwrap();
            };
            tokio::join!(send, receive);
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn vision_direct_cannot_recover_poisoned_or_incomplete_records() {
    let (mut left, mut right) = pair(128, true, CipherSuite::Aes256Gcm);
    left.write_all(b"authenticated").await.unwrap();
    left.flush().await.unwrap();
    // Force an unfinished header, as after a cancelled record read.
    right.header_pos = 1;
    let mut bytes = [0; 8];
    let mut buf = tokio::io::ReadBuf::new(&mut bytes);
    assert!(
        std::future::poll_fn(|cx| right.poll_read_vision_direct(cx, &mut buf))
            .await
            .is_err()
    );
    assert!(buf.filled().is_empty());
    assert!(
        std::future::poll_fn(|cx| right.poll_write_vision_direct(cx, b"bypass"))
            .await
            .is_err()
    );
    assert!(right.read(&mut bytes).await.is_err());
}
