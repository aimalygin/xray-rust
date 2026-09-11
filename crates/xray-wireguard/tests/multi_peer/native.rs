//! Bridge test packets to an unchanged official wireguard-go device.
#[path = "../support/mod.rs"]
mod reference;

use super::{key, RawPeer};
use bytes::BytesMut;
use gotatun::packet::{Ip, Packet};
use tokio::{
    net::UnixDatagram,
    sync::{mpsc, oneshot},
};
use x25519_dalek::{PublicKey, StaticSecret};
use xray_wireguard::PeerConfig;

pub(super) async fn start(seed: u8, ipv6: bool, prefixes: &[&str]) -> RawPeer {
    let secret = StaticSecret::from([seed; 32]);
    let psk = [seed + 1; 32];
    let reference = reference::Reference::start_raw(
        &secret,
        &PublicKey::from(&StaticSecret::from([0x42; 32])),
        &psk,
        if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap(),
    )
    .await;
    let config = PeerConfig {
        public_key: key(PublicKey::from(&secret).as_bytes()),
        preshared_key: Some(key(&psk)),
        endpoint: reference.address,
        allowed_ips: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
        keepalive: 0,
    };
    let socket = UnixDatagram::bind(reference.directory.join("client.sock")).unwrap();
    socket
        .connect(reference.directory.join("server.sock"))
        .unwrap();
    let (tx, received) = mpsc::channel(8);
    let (inject, mut rx) = mpsc::channel::<Packet<Ip>>(8);
    let (stop, mut stopped) = oneshot::channel();
    let done = tokio::spawn(async move {
        // The process guard outlives the packet loop, including cancellation.
        let _reference = reference;
        let mut bytes = [0; 1421];
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                packet = rx.recv() => {
                    let Some(packet) = packet else { break };
                    let packet = packet.into_bytes();
                    tokio::select! {
                        _ = &mut stopped => break,
                        sent = socket.send(&packet) => assert_eq!(sent.unwrap(), packet.len()),
                    }
                },
                count = socket.recv(&mut bytes) => {
                    let count = count.unwrap();
                    assert!(count <= 1420);
                    let packet = Packet::from_bytes(BytesMut::from(&bytes[..count]))
                        .try_into_ip().expect("official peer delivered a valid IP packet");
                    // Match the bounded/lossy IP boundary of the in-process peer.
                    let _ = tx.try_send(packet);
                }
            }
        }
    });
    RawPeer {
        config,
        received,
        inject,
        stop: Some(stop),
        done: Some(done),
    }
}
