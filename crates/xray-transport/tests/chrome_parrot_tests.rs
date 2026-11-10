//! Xray-core's ChromeParrot first flight, byte for byte.
//!
//! `tests/fixtures/chrome-parrot/initials.json` holds what Xray-core
//! v26.11.9's own Hysteria dialer sent with its default ChromeParrot QUIC
//! stack, under a deterministic `crypto/rand`, together with every random read
//! behind it (`tools/chrome-parrot-oracle`; `scripts/check-chrome-parrot-interop.sh`
//! regenerates it and points `XRAY_CHROME_PARROT_INITIALS` at the fresh copy).
//! Given the same draws, the vendored quinn-proto must produce the same
//! transport parameters and, carrying the same ClientHello, the same four
//! encrypted Initial datagrams: the first flight and its retransmission.

use std::any::Any;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::crypto::{self, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{
    congestion::NewRenoConfig, ClientConfig, ConnectError, ConnectionId, Endpoint, EndpointConfig,
    RandomConnectionIdGenerator, Side, TransportConfig, TransportError, VarInt,
};
use serde_json::Value;

#[path = "../../../tests/support/chrome_parrot_wire.rs"]
mod chrome_parrot_wire;

const QUIC_GO_PACKER: &str = "github.com/apernet/quic-go.newPacketPacker";
const QUIC_GO_WIRE: &str = "github.com/apernet/quic-go/internal/wire.";
/// quic-go's initial congestion window, 32 packets of the 1250-byte
/// ChromeParrot initial size
const QUIC_GO_INITIAL_WINDOW: u64 = 32 * 1250;

fn fixture() -> Value {
    let path = std::env::var("XRAY_CHROME_PARROT_INITIALS").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/chrome-parrot/initials.json"
        )
        .to_owned()
    });
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn reads<'a>(case: &'a Value, prefix: &'a str) -> impl Iterator<Item = Vec<u8>> + 'a {
    case["random_reads"]
        .as_array()
        .unwrap()
        .iter()
        .filter(move |read| read["source"].as_str().unwrap().starts_with(prefix))
        .map(|read| unhex(read["hex"].as_str().unwrap()))
}

/// The configuration Xray's ChromeParrot pins: 30 s idle timeout, 6 MiB stream
/// and 15 MiB connection windows, 100 and 103 streams, 1472-byte UDP payloads.
fn chrome_transport() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .chrome_parrot(true)
        .max_idle_timeout(Some(VarInt::from_u32(30_000).into()))
        .stream_receive_window(VarInt::from_u32(6_291_456))
        .receive_window(VarInt::from_u32(15_728_640))
        .max_concurrent_bidi_streams(VarInt::from_u32(100))
        .max_concurrent_uni_streams(VarInt::from_u32(103))
        .initial_mtu(1250)
        .min_mtu(1250);
    transport
}

#[test]
fn transport_parameters_match_xray() {
    let fixture = fixture();
    let mut endpoint = EndpointConfig::default();
    endpoint.max_udp_payload_size(1472).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let mut draws = reads(case, QUIC_GO_WIRE).collect::<Vec<_>>().into_iter();
        let mut random = |out: &mut [u8]| {
            let draw = draws.next().expect("quic-go drew fewer random bytes");
            assert_eq!(out.len(), draw.len(), "a draw of another size");
            out.copy_from_slice(&draw);
        };
        let ours = quinn_proto::chrome_parrot_transport_parameters(
            &chrome_transport(),
            &endpoint,
            &[],
            &mut random,
        );
        assert!(draws.next().is_none(), "quic-go drew more random bytes");
        let theirs = case["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["type"] == 0x39)
            .map(|e| unhex(e["data"].as_str().unwrap()))
            .unwrap();
        assert_eq!(hex(&ours), hex(&theirs), "seed {}", case["seed"]);
    }
}

/// A rustls QUIC session that sends a recorded ClientHello instead of its
/// own: the Initial keys are still those the destination connection ID
/// derives.
struct ReplayClientConfig {
    inner: Arc<QuicClientConfig>,
    client_hello: Vec<u8>,
}

impl crypto::ClientConfig for ReplayClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        Ok(Box::new(ReplaySession {
            inner: Arc::clone(&self.inner).start_session(version, server_name, params)?,
            client_hello: Some(self.client_hello.clone()),
        }))
    }
}

struct ReplaySession {
    inner: Box<dyn crypto::Session>,
    client_hello: Option<Vec<u8>>,
}

impl crypto::Session for ReplaySession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        self.inner.initial_keys(dst_cid, side)
    }
    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        None
    }
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None
    }
    fn early_data_accepted(&self) -> Option<bool> {
        None
    }
    fn is_handshaking(&self) -> bool {
        true
    }
    fn read_handshake(&mut self, _: &[u8]) -> Result<bool, TransportError> {
        unreachable!("the server never answers")
    }
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(None)
    }
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        if let Some(hello) = self.client_hello.take() {
            buf.extend_from_slice(&hello);
        }
        None
    }
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        None
    }
    fn is_valid_retry(&self, _: &ConnectionId, _: &[u8], _: &[u8]) -> bool {
        false
    }
    fn export_keying_material(
        &self,
        _: &mut [u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        Err(ExportKeyingMaterialError)
    }
}

fn quic_rustls() -> Arc<QuicClientConfig> {
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    Arc::new(QuicClientConfig::try_from(Arc::new(tls)).unwrap())
}

/// The datagrams a ChromeParrot client connection sends for `case`: its first
/// flight, then, once the loss detection timer fires, the probes.
fn first_flight(case: &Value) -> Vec<Vec<u8>> {
    let dcid = unhex(case["datagrams"][0]["dcid"].as_str().unwrap());
    let seed: [u8; 16] = reads(case, QUIC_GO_PACKER)
        .next()
        .expect("the packer seed")
        .try_into()
        .unwrap();
    first_flight_with(
        dcid,
        seed,
        unhex(case["client_hello"].as_str().unwrap()),
        case["datagrams"].as_array().unwrap().len(),
    )
}

/// The first `wanted` datagrams of a ChromeParrot client connection to
/// `dcid` whose packet layout is seeded with `seed` and whose TLS stack sends
/// `client_hello`.
fn first_flight_with(
    dcid: Vec<u8>,
    seed: [u8; 16],
    client_hello: Vec<u8>,
    wanted: usize,
) -> Vec<Vec<u8>> {
    let mut transport = chrome_transport();
    let mut reno = NewRenoConfig::default();
    reno.initial_window(QUIC_GO_INITIAL_WINDOW);
    transport
        .chrome_parrot_seed(Some(seed))
        .congestion_controller_factory(Arc::new(reno));
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.cid_generator(|| Box::new(RandomConnectionIdGenerator::new(0)));
    let mut endpoint = Endpoint::new(Arc::new(endpoint_config), None, true, None);
    let mut client = ClientConfig::new(Arc::new(ReplayClientConfig {
        inner: quic_rustls(),
        client_hello,
    }));
    client
        .transport_config(Arc::new(transport))
        .initial_dst_cid_provider(Arc::new(move || ConnectionId::new(&dcid)));
    let remote: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let mut now = Instant::now();
    let (_, mut connection) = endpoint
        .connect(now, client, remote, "chrome-parrot.example")
        .unwrap();
    let mut datagrams = Vec::new();
    let deadline = now + Duration::from_secs(60);
    while datagrams.len() < wanted && now < deadline {
        let mut buf = Vec::new();
        match connection.poll_transmit(now, 10, &mut buf) {
            Some(transmit) => {
                assert!(transmit.segment_size.is_none(), "one datagram per transmit");
                datagrams.push(buf[..transmit.size].to_vec());
            }
            None => {
                now = connection.poll_timeout().expect("a timer");
                connection.handle_timeout(now);
            }
        }
    }
    datagrams
}

#[test]
fn first_flight_and_probes_match_xray() {
    let fixture = fixture();
    for case in fixture["cases"].as_array().unwrap() {
        let ours = first_flight(case);
        let theirs = case["datagrams"].as_array().unwrap();
        assert_eq!(ours.len(), theirs.len());
        for (i, (ours, theirs)) in ours.iter().zip(theirs).enumerate() {
            assert_eq!(
                hex(ours),
                theirs["hex"].as_str().unwrap(),
                "seed {} datagram {i}: Xray's frames {:?}",
                case["seed"],
                theirs["frames"],
            );
        }
    }
}

/// A probe carries one lost packet's frames whole, in a datagram of the full
/// 1250 bytes as quic-go's probes are: with a 2400-byte ClientHello the first
/// packet's head and tail take more room than a 1200-byte datagram has.
#[test]
fn probes_carry_whole_packets_at_the_full_size() {
    let mut hello = vec![0x01, 0x00, 0x09, 0x5c];
    hello.extend((0..2396u32).map(|i| (i % 251) as u8));
    let datagrams = first_flight_with(vec![0x5a; 8], [0x42; 16], hello, 4);
    let ranges = |datagram: &[u8]| {
        let initial = chrome_parrot_wire::decrypt_initial(datagram).unwrap();
        assert_eq!(initial.datagram_len, 1250);
        let mut ranges: Vec<(u64, u64)> = initial
            .frames
            .iter()
            .filter_map(|frame| match frame {
                chrome_parrot_wire::Frame::Crypto { offset, data } => {
                    Some((*offset, *offset + data.len() as u64))
                }
                _ => None,
            })
            .collect();
        ranges.sort();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if last.1 == start => last.1 = end,
                _ => merged.push((start, end)),
            }
        }
        merged
    };
    let first = ranges(&datagrams[0]);
    assert_eq!(first.len(), 2, "head and tail: {first:?}");
    assert!(first[1].1 - first[1].0 + first[0].1 > 1150, "{first:?}");
    assert_eq!(ranges(&datagrams[2]), first, "the first probe");
    assert_eq!(
        ranges(&datagrams[3]),
        ranges(&datagrams[1]),
        "the second probe"
    );
}
