use super::*;
use crate::{
    header_custom::{CustomItem, HeaderCustomUdpConfig},
    hysteria::{carrier::key, HeaderCustomCarrier},
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

/// A standalone header-custom mask: "hello" alone, answered by "world".
fn standalone() -> HysteriaCarrierConfig {
    let item = |packet: &[u8]| CustomItem {
        delay: (0, 0),
        rand: 0,
        rand_range: (0, 255),
        packet: packet.to_vec(),
        capture: String::new(),
        reuse: String::new(),
        transform: None,
    };
    HysteriaCarrierConfig {
        header_custom: Some(HeaderCustomCarrier {
            config: Arc::new(HeaderCustomUdpConfig {
                standalone: true,
                client: vec![item(b"hello")],
                server: vec![item(b"world")],
            }),
            before_salamander: false,
            before_noise: false,
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

/// A standalone header holds the first send until the server answers, and
/// no receiver runs meanwhile, as in a freedom flow: the send takes the
/// answer in itself. A reply that came before the answer reaches the next
/// receive, ahead of what follows.
#[tokio::test]
async fn a_held_send_takes_the_answer_in_itself() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = masked(peer.local_addr().unwrap(), &standalone()).await;
    let local = socket.local_addr().unwrap();
    let server = async {
        assert_eq!(recv(&peer).await, (b"hello".to_vec(), local));
        peer.send_to(b"early reply", local).await.unwrap();
        peer.send_to(b"world", local).await.unwrap();
        recv(&peer).await.0
    };
    let (sent, payload) = tokio::join!(
        timeout(Duration::from_secs(2), socket.send(b"payload")),
        server
    );
    sent.expect("the send takes the answer in").unwrap();
    assert_eq!(payload, b"payload");

    peer.send_to(b"late reply", local).await.unwrap();
    let mut buf = [0; 64];
    for expected in [b"early reply".as_slice(), b"late reply"] {
        let (n, from) = timeout(Duration::from_secs(2), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((&buf[..n], from), (expected, peer.local_addr().unwrap()));
    }
}

/// A held send waits on the socket's receive in the place of a receiver in
/// another task, as WireGuard's is. Once the send is through, the receiver
/// waits there again and takes the next datagram.
#[tokio::test]
async fn a_receiver_in_another_task_waits_again_after_a_held_send() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = Arc::new(masked(peer.local_addr().unwrap(), &standalone()).await);
    let local = socket.local_addr().unwrap();
    let (received, mut taken) = tokio::sync::mpsc::unbounded_channel();
    let receiver = tokio::spawn({
        let socket = socket.clone();
        async move {
            let mut buf = [0; 64];
            while let Ok((n, _)) = socket.recv(&mut buf).await {
                let _ = received.send(buf[..n].to_vec());
            }
        }
    });
    // The receiver waits on the socket before the send does.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let server = async {
        assert_eq!(recv(&peer).await.0, b"hello");
        peer.send_to(b"world", local).await.unwrap();
        recv(&peer).await.0
    };
    let (sent, payload) = tokio::join!(
        timeout(Duration::from_secs(2), socket.send(b"payload")),
        server
    );
    sent.expect("the send takes the answer in").unwrap();
    assert_eq!(payload, b"payload");

    peer.send_to(b"after", local).await.unwrap();
    let after = timeout(Duration::from_secs(2), taken.recv())
        .await
        .expect("the receiver wakes again");
    assert_eq!(after.unwrap(), b"after");
    receiver.abort();
}

/// A reply a held send read in place of a receiver in another task reaches
/// that receiver while the send still waits for its answer.
#[tokio::test]
async fn a_receiver_in_another_task_takes_what_a_held_send_read() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = Arc::new(masked(peer.local_addr().unwrap(), &standalone()).await);
    let local = socket.local_addr().unwrap();
    let (received, mut taken) = tokio::sync::mpsc::unbounded_channel();
    let receiver = tokio::spawn({
        let socket = socket.clone();
        async move {
            let mut buf = [0; 64];
            while let Ok((n, _)) = socket.recv(&mut buf).await {
                let _ = received.send(buf[..n].to_vec());
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let server = async {
        assert_eq!(recv(&peer).await.0, b"hello");
        peer.send_to(b"data", local).await.unwrap();
        let data = timeout(Duration::from_millis(500), taken.recv())
            .await
            .expect("the receiver takes the reply before the answer");
        assert_eq!(data.unwrap(), b"data");
        peer.send_to(b"world", local).await.unwrap();
        recv(&peer).await.0
    };
    let (sent, payload) = tokio::join!(
        timeout(Duration::from_secs(2), socket.send(b"payload")),
        server
    );
    sent.expect("the send takes the answer in").unwrap();
    assert_eq!(payload, b"payload");
    receiver.abort();
}

/// A held send keeps what it reads up to the budget and drops the rest;
/// what it kept comes out cut to the receiver's buffer, and a drained queue
/// keeps no storage.
#[test]
fn held_datagrams_stop_at_the_budget() {
    let from: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let mut held = Held::default();
    let datagram = [0x5a; 1000];
    let mut kept = 0;
    while held.keep(&datagram, from) {
        kept += 1;
    }
    assert_eq!(kept, HELD_BYTES / datagram.len());
    let rest = HELD_BYTES - held.bytes;
    assert!(
        held.keep(&datagram[..rest], from),
        "what still fits is kept"
    );
    assert!(!held.keep(&[0], from));
    let mut buf = [0; 100];
    assert_eq!(held.take(&mut buf), Some((100, from)));
    while held.take(&mut buf).is_some() {}
    assert_eq!((held.bytes, held.datagrams.capacity()), (0, 0));
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
