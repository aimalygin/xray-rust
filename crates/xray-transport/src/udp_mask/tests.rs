use super::*;
use crate::{
    hysteria::carrier::key,
    udp_noise::{NoiseRange, UdpNoiseConfig, UdpNoiseItem},
};
use std::time::Duration;
use tokio::{net::UdpSocket, time::timeout};
use zeroize::Zeroizing;

const PASSWORD: &str = "synthetic-salamander";

fn salamander(input: &[u8], salt: [u8; 8]) -> Vec<u8> {
    let mask = key(PASSWORD, &salt);
    let mut output = salt.to_vec();
    output.extend(
        input
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % mask.len()]),
    );
    output
}

fn unsalt(datagram: &[u8]) -> Vec<u8> {
    let (salt, body) = datagram.split_at(8);
    let mask = key(PASSWORD, salt);
    body.iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i % mask.len()])
        .collect()
}

fn masks(noise_before_salamander: bool) -> HysteriaCarrierConfig {
    let zero = || NoiseRange { from: 0, to: 0 };
    HysteriaCarrierConfig {
        salamander_password: Some(Arc::new(Zeroizing::new(PASSWORD.into()))),
        noise: Some(UdpNoiseConfig {
            items: vec![UdpNoiseItem {
                packet: b"prelude".to_vec(),
                random_length: zero(),
                random_bytes: zero(),
                delay_ms: NoiseRange { from: 5, to: 5 },
                segments: Vec::new(),
            }],
            reset_secs: zero(),
            before_salamander: noise_before_salamander,
        }),
        ..Default::default()
    }
}

async fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0; 2048];
    let (n, from) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("a datagram")
        .unwrap();
    (buf[..n].to_vec(), from)
}

async fn masked(peer: SocketAddr, masks: &HysteriaCarrierConfig) -> MaskedUdpSocket {
    let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
    MaskedUdpSocket::connect(socket, peer, masks, None)
        .await
        .unwrap()
}

/// Noise goes first, once, inside or outside Salamander as listed; every
/// payload goes salted, and the peer's salted replies come back unmasked.
#[tokio::test]
async fn noise_and_salamander_shape_both_directions() {
    for noise_before_salamander in [false, true] {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = masked(peer.local_addr().unwrap(), &masks(noise_before_salamander)).await;
        let local = socket.local_addr().unwrap();
        socket.send(b"first").await.unwrap();
        socket.send(b"second").await.unwrap();
        let (noise, from) = recv(&peer).await;
        assert_eq!(from, local);
        if noise_before_salamander {
            assert_eq!(unsalt(&noise), b"prelude");
        } else {
            assert_eq!(noise, b"prelude");
        }
        assert_eq!(unsalt(&recv(&peer).await.0), b"first");
        assert_eq!(unsalt(&recv(&peer).await.0), b"second");

        peer.send_to(&salamander(b"reply", [7; 8]), local)
            .await
            .unwrap();
        let mut buf = [0; 64];
        let (n, from) = timeout(Duration::from_secs(2), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (&buf[..n], from),
            (b"reply".as_slice(), peer.local_addr().unwrap())
        );
    }
}

/// Another sender's datagram never reaches the receiver, nor does one too
/// short to carry a salt; the peer's next datagram does.
#[tokio::test]
async fn other_senders_and_unmaskable_datagrams_are_dropped() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = masked(peer.local_addr().unwrap(), &masks(false)).await;
    let local = socket.local_addr().unwrap();
    stranger
        .send_to(&salamander(b"stranger", [1; 8]), local)
        .await
        .unwrap();
    peer.send_to(b"short", local).await.unwrap();
    peer.send_to(&salamander(b"peer", [2; 8]), local)
        .await
        .unwrap();
    let mut buf = [0; 64];
    let (n, from) = timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (&buf[..n], from),
        (b"peer".as_slice(), peer.local_addr().unwrap())
    );
}

/// A datagram past what the receiver offers is cut to it, as a socket's
/// receive cuts it, or dropped under Salamander, whose salt must be read
/// whole; the next one that fits arrives.
#[tokio::test]
async fn a_long_datagram_is_cut_or_dropped() {
    let mut buf = [0; 1000];
    let noise_only = HysteriaCarrierConfig {
        salamander_password: None,
        ..masks(false)
    };
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = masked(peer.local_addr().unwrap(), &noise_only).await;
    peer.send_to(&[0x5a; 3000], socket.local_addr().unwrap())
        .await
        .unwrap();
    let (n, _) = timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], &[0x5a; 1000]);

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = masked(peer.local_addr().unwrap(), &masks(false)).await;
    let local = socket.local_addr().unwrap();
    peer.send_to(&salamander(&[0x5a; 3000], [3; 8]), local)
        .await
        .unwrap();
    peer.send_to(&salamander(b"fits", [4; 8]), local)
        .await
        .unwrap();
    let (n, _) = timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"fits");
}

/// A datagram to a port no one holds draws an ICMP error, which the
/// connected socket reports on a later call: it fails neither the next send
/// nor the receive, as on a flow without masks.
#[tokio::test]
async fn a_refused_datagram_is_loss() {
    let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = closed.local_addr().unwrap();
    drop(closed);
    let socket = masked(peer, &masks(false)).await;
    let mut buf = [0; 64];
    for payload in [b"first".as_slice(), b"second"] {
        socket.send(payload).await.unwrap();
        assert!(timeout(Duration::from_millis(100), socket.recv(&mut buf))
            .await
            .is_err());
    }
}

/// Hopping needs a QUIC carrier's driver.
#[test]
fn udphop_is_refused() {
    let hop = HysteriaCarrierConfig {
        udp_hop: crate::stream::H3UdpHopConfig {
            ports: vec![4000, 4001],
            interval_min: Duration::from_secs(30),
            interval_max: Duration::from_secs(30),
            local: true,
            ..Default::default()
        },
        ..masks(false)
    };
    assert!(hop.udp_hop.is_active());
    assert_eq!(
        MaskedUdpSocket::validate(&hop).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(MaskedUdpSocket::validate(&masks(true)).is_ok());
}
