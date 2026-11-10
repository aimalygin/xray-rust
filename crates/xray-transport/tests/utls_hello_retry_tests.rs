//! A HelloRetryRequest answered as uTLS answers it (`handshake_client_tls13.go`).
//!
//! A scripted server reads the first ClientHello, writes a HelloRetryRequest
//! built by hand -- naming a group, carrying a cookie, or both -- and reads the
//! second ClientHello. uTLS sends the requested group's key share alone
//! (RFC 8446 section 4.1.2; OpenSSL and Go's crypto/tls refuse more with
//! `illegal_parameter`), inserts a cookie anywhere but the last two places of
//! its extension list, and pads the second ClientHello by its own length.

#[path = "support/client_hello_draws.rs"]
mod client_hello_draws;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{TlsClientConfig, TlsConnector};

use crate::client_hello_draws::{extension_body, extension_types};

const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_COOKIE: u16 = 0x002c;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_PADDING: u16 = 0x0015;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const GROUP_SECP256R1: u16 = 0x0017;

/// The random a ServerHello carries to be a HelloRetryRequest: SHA-256 of
/// "HelloRetryRequest" (RFC 8446 section 4.1.3).
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// A HelloRetryRequest's key_share: the group it names.
fn key_share_naming(group: u16) -> (u16, Vec<u8>) {
    (EXT_KEY_SHARE, group.to_be_bytes().to_vec())
}

/// A HelloRetryRequest's cookie extension.
fn cookie(bytes: &[u8]) -> (u16, Vec<u8>) {
    let mut body = (bytes.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(bytes);
    (EXT_COOKIE, body)
}

async fn read_record(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .expect("a record header must arrive");
    let mut payload = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
    stream
        .read_exact(&mut payload)
        .await
        .expect("the whole record must arrive");
    (header[0], payload)
}

/// A HelloRetryRequest answering `client_hello`: TLS 1.3, its session id
/// echoed, TLS_AES_128_GCM_SHA256, and `extensions` after supported_versions.
fn hello_retry_request(client_hello: &[u8], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let session_id_len = usize::from(client_hello[4 + 2 + 32]);
    let session_id = &client_hello[4 + 2 + 32 + 1..4 + 2 + 32 + 1 + session_id_len];
    let mut encoded = Vec::new();
    for (extension_type, body) in
        std::iter::once(&(EXT_SUPPORTED_VERSIONS, vec![0x03, 0x04])).chain(extensions)
    {
        encoded.extend_from_slice(&extension_type.to_be_bytes());
        encoded.extend_from_slice(&(body.len() as u16).to_be_bytes());
        encoded.extend_from_slice(body);
    }
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
    body.push(session_id_len as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&[0x13, 0x01, 0x00]);
    body.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
    body.extend(encoded);
    let mut message = vec![0x02];
    message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend(body);
    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(&(message.len() as u16).to_be_bytes());
    record.extend(message);
    record
}

async fn dial(fingerprint: &str, alpn: &[String], addr: SocketAddr) {
    let config = TlsClientConfig {
        server_name: "server.test".to_owned(),
        allow_insecure: true,
        pinned_peer_cert_sha256: Vec::new(),
        verify_peer_cert_by_name: Vec::new(),
        alpn: alpn.to_vec(),
        fingerprint: Some(fingerprint.to_owned()),
    };
    // The handshake cannot finish against a server that stops after the
    // second ClientHello; how it ends is not what this is about.
    let _ = TlsConnector::system()
        .expect("system roots must load")
        .connect(
            &Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp),
            &config,
        )
        .await;
}

/// The ClientHellos `fingerprint` sends around a HelloRetryRequest carrying
/// `extensions`, as handshake messages: the first, then the second (past the
/// middlebox-compatibility ChangeCipherSpec).
async fn hellos_around_retry(
    fingerprint: &str,
    extensions: &[(u16, Vec<u8>)],
) -> (Vec<u8>, Vec<u8>) {
    hellos_around_retry_with_alpn(fingerprint, &[], extensions).await
}

/// [`hellos_around_retry`] with `alpn` configured: `http/1.1` alone is Xray's
/// override, which appends ALPN to a profile that has none.
async fn hellos_around_retry_with_alpn(
    fingerprint: &str,
    alpn: &[&str],
    extensions: &[(u16, Vec<u8>)],
) -> (Vec<u8>, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener must bind");
    let addr = listener.local_addr().expect("the listener has an address");
    let extensions = extensions.to_vec();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("the client must connect");
        let (_, first) = read_record(&mut stream).await;
        stream
            .write_all(&hello_retry_request(&first, &extensions))
            .await
            .expect("the HelloRetryRequest must go out");
        loop {
            let (content_type, payload) = read_record(&mut stream).await;
            if content_type == 0x16 {
                return (first, payload);
            }
        }
    });
    let name = fingerprint.to_owned();
    let alpn = alpn
        .iter()
        .map(|protocol| (*protocol).to_owned())
        .collect::<Vec<_>>();
    let client = tokio::spawn(async move { dial(&name, &alpn, addr).await });
    // A client that cannot build its second ClientHello sends none.
    let hellos = tokio::time::timeout(std::time::Duration::from_secs(10), server)
        .await
        .unwrap_or_else(|_| panic!("{fingerprint}: no second ClientHello within ten seconds"))
        .expect("the scripted server must finish");
    client.abort();
    hellos
}

/// The groups of a ClientHello's key shares, in order.
fn key_share_groups(hello: &[u8]) -> Vec<u16> {
    let body = extension_body(hello, EXT_KEY_SHARE).expect("a key_share extension");
    let mut groups = Vec::new();
    let mut cursor = 2;
    while cursor < body.len() {
        groups.push(u16::from_be_bytes([body[cursor], body[cursor + 1]]));
        cursor += 4 + usize::from(u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]));
    }
    groups
}

fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && high & 0x0f == 0x0a
}

/// A HelloRetryRequest naming P-256, which no Chrome profile sends a share
/// for, gets one P-256 share: no GREASE share, no ML-KEM or Kyber one.
#[tokio::test]
async fn a_retry_naming_a_group_gets_its_key_share_alone() {
    for fingerprint in [
        "chrome",
        "hellochrome_133",
        "hellochrome_131",
        "hellochrome_120",
        "hellochrome_120_pq",
    ] {
        let (first, second) =
            hellos_around_retry(fingerprint, &[key_share_naming(GROUP_SECP256R1)]).await;

        let first_groups = key_share_groups(&first);
        assert!(
            first_groups.iter().any(|group| is_grease(*group)),
            "{fingerprint}: the first ClientHello carries a GREASE share, {first_groups:x?}"
        );
        assert_eq!(
            key_share_groups(&second),
            vec![GROUP_SECP256R1],
            "{fingerprint}: the second ClientHello carries the requested share alone"
        );
    }
}

/// A HelloRetryRequest with a cookie and no group gets the cookie back, the
/// first ClientHello's key shares unchanged, and the cookie anywhere but the
/// last two places, as uTLS's `p.Intn(len(Extensions) - 2)` puts it: over
/// 512 retries every allowed place comes up (with sixteen or seventeen of
/// them, a given one is missed with probability below `10^-13`) and no other.
#[tokio::test]
async fn a_retry_with_a_cookie_gets_it_back_where_utls_would_place_it() {
    let sent = [0xc0, 0x0c, 0x1e, 0x5e];
    // `randomizednoalpn` with `http/1.1`: an ALPN extension the override
    // appends is one more place in uTLS's list too.
    for (fingerprint, alpn) in [
        ("chrome", &[][..]),
        ("hellochrome_133", &[][..]),
        ("randomizednoalpn", &["http/1.1"][..]),
    ] {
        let mut places = BTreeSet::new();
        let mut others = 0;
        for _ in 0..512 {
            let (first, second) =
                hellos_around_retry_with_alpn(fingerprint, alpn, &[cookie(&sent)]).await;
            assert_eq!(
                extension_body(&second, EXT_COOKIE),
                Some(cookie(&sent).1.as_slice()),
                "{fingerprint}: the cookie comes back as sent"
            );
            assert_eq!(
                extension_body(&second, EXT_KEY_SHARE),
                extension_body(&first, EXT_KEY_SHARE),
                "{fingerprint}: a cookie alone changes no key share"
            );
            assert_eq!(extension_body(&first, EXT_COOKIE), None);

            let types = extension_types(&second);
            others = types.len() - 1;
            places.insert(
                types
                    .iter()
                    .position(|extension_type| *extension_type == EXT_COOKIE)
                    .expect("the second ClientHello carries the cookie"),
            );
        }
        assert_eq!(
            places,
            (0..others - 2).collect::<BTreeSet<_>>(),
            "{fingerprint}: every place but the last two of {others}"
        );
    }
}

/// Each ClientHello is padded as BoringSSL pads uTLS's, by its own length:
/// Chrome 120's hello, twelve bytes short of uTLS's for the six suites rustls
/// lacks, is padded when uTLS's is 256 to 511 bytes before padding. A P-256
/// share in place of the X25519 and GREASE ones adds 28 bytes, so the
/// second ClientHello leaves the window the first sat in with the shortest
/// ECH length; a cookie adds 10 and keeps it there.
#[tokio::test]
async fn hellochrome_120_pads_each_client_hello_by_its_own_length() {
    const OFFSET: isize = 12;
    fn padding(hello: &[u8]) -> Option<usize> {
        extension_body(hello, EXT_PADDING).map(<[u8]>::len)
    }
    fn assert_pads_as_boringssl(hello: &[u8], what: &str) {
        let unpadded = hello.len() - padding(hello).map_or(0, |padding| 4 + padding);
        let utls = unpadded as isize + OFFSET;
        let expected = (256..512).contains(&utls).then(|| {
            let padding = 512 - utls;
            (if padding > 4 { padding - 4 } else { 1 }) + OFFSET
        });
        assert_eq!(
            padding(hello).map(|padding| padding as isize),
            expected,
            "{what}: uTLS's hello is {utls} bytes before padding"
        );
    }

    for (retry, extensions) in [
        ("P-256", vec![key_share_naming(GROUP_SECP256R1)]),
        ("cookie", vec![cookie(&[1, 2, 3, 4])]),
    ] {
        let mut seen = BTreeMap::new();
        for _ in 0..client_hello_draws::ECH_DRAWS {
            let (first, second) = hellos_around_retry("hellochrome_120", &extensions).await;
            assert_pads_as_boringssl(&first, "first ClientHello");
            assert_pads_as_boringssl(
                &second,
                &format!("second ClientHello after a {retry} retry"),
            );
            let ech = extension_body(&first, EXT_ENCRYPTED_CLIENT_HELLO)
                .map(<[u8]>::len)
                .expect("hellochrome_120 carries ECH GREASE");
            seen.insert(ech, (padding(&first).is_some(), padding(&second).is_some()));
        }
        let shortest = seen.get(&186).copied();
        match retry {
            "P-256" => assert_eq!(shortest, Some((true, false)), "{seen:?}"),
            _ => assert_eq!(shortest, Some((true, true)), "{seen:?}"),
        }
        assert_eq!(seen.len(), 4, "every ECH length drawn: {seen:?}");
    }
}

/// Against OpenSSL's own `s_server` with `-groups P-256`, which answers
/// every Chrome profile's hello with a HelloRetryRequest naming P-256 and
/// refuses a second ClientHello carrying any other share. Every shaped
/// handshake must complete. Set `XRAY_HRR_OPENSSL` to an OpenSSL 3 binary.
///
/// `-stateless`, the way `s_server` sends a cookie, is no judge of the
/// cookie path: in OpenSSL 3.5.9 it closes the connection after its
/// HelloRetryRequest for its own `s_client` too. The scripted server above
/// checks that second ClientHello instead.
#[tokio::test]
#[ignore = "requires an OpenSSL 3 binary in XRAY_HRR_OPENSSL"]
async fn shaped_handshakes_complete_through_openssl_hello_retry_requests() {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let openssl = std::env::var("XRAY_HRR_OPENSSL").expect("XRAY_HRR_OPENSSL names OpenSSL 3");
    let directory = std::env::temp_dir().join(format!("xray-hrr-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["server.test".to_owned()]).unwrap();
    std::fs::write(directory.join("cert.der"), cert.der()).unwrap();
    std::fs::write(directory.join("key.der"), signing_key.serialize_der()).unwrap();

    for (mode, args) in [("groups P-256", &["-groups", "P-256", "-www"][..])] {
        let port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let mut server = Command::new(&openssl)
            .args(["s_server", "-tls1_3", "-accept"])
            .arg(format!("127.0.0.1:{port}"))
            .args(["-certform", "DER", "-keyform", "DER", "-cert"])
            .arg(directory.join("cert.der"))
            .arg("-key")
            .arg(directory.join("key.der"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("openssl s_server must start");
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        for _ in 0..50 {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        for fingerprint in [
            "chrome",
            "hellochrome_133",
            "hellochrome_131",
            "hellochrome_120",
        ] {
            let config = TlsClientConfig {
                server_name: "server.test".to_owned(),
                allow_insecure: true,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: Vec::new(),
                fingerprint: Some(fingerprint.to_owned()),
            };
            let outcome = tokio::time::timeout(
                Duration::from_secs(10),
                TlsConnector::system().unwrap().connect(
                    &Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp),
                    &config,
                ),
            )
            .await;
            assert!(
                matches!(outcome, Ok(Ok(_))),
                "{fingerprint} through s_server {mode}: {:?}",
                outcome.map(|result| result.map(|_| ()))
            );
        }
        let _ = server.kill();
        let _ = server.wait();
    }
    let _ = std::fs::remove_dir_all(&directory);
}
