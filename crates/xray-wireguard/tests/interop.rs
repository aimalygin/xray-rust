mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
use x25519_dalek::{PublicKey, StaticSecret};
use xray_proxy::wireguard::KeyMaterial;
use xray_transport::{SocketHandle, SocketProtector};
use xray_wireguard::{Client, Config};

struct Protector(AtomicUsize);
impl SocketProtector for Protector {
    fn protect(&self, _: SocketHandle) -> std::io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn config(endpoint: SocketAddr, peer: &PublicKey) -> Config {
    Config {
        secret_key: KeyMaterial::parse(&STANDARD.encode([0x42; 32])).unwrap(),
        peers: vec![xray_wireguard::PeerConfig {
            public_key: KeyMaterial::parse(&STANDARD.encode(peer.as_bytes())).unwrap(),
            preshared_key: None,
            endpoint,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            keepalive: 0,
        }],
        addresses: vec!["10.44.0.2".parse().unwrap(), "fd44::2".parse().unwrap()],
        mtu: 1420,
    }
}
#[tokio::test]
#[ignore = "requires pinned reference; use check-wireguard-runtime.sh or check-native-wireguard-interop.sh"]
async fn pinned_reference_tcp_udp_ipv4_ipv6_and_half_close() {
    roundtrip(None).await;
}
#[tokio::test]
#[ignore = "requires pinned reference; use check-wireguard-runtime.sh or check-native-wireguard-interop.sh"]
async fn pinned_reference_psk_tcp_udp_ipv4_ipv6_and_half_close() {
    roundtrip(Some([0x64; 32])).await;
}
async fn roundtrip(psk: Option<[u8; 32]>) {
    timeout(Duration::from_secs(40), async {
        let server = StaticSecret::from([0x53; 32]);
        let public = PublicKey::from(&StaticSecret::from([0x42; 32]));
        let reference = match psk.as_ref() {
            Some(key) => support::Reference::start_with_psk(&server, &public, Some(key)).await,
            None => support::Reference::start(&server, &public).await,
        };
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();
        let echo_tcp = tokio::spawn(async move {
            loop {
                let (mut socket, _) = tcp.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut read, mut write) = socket.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                    let _ = write.shutdown().await;
                });
            }
        });
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        let echo_udp = tokio::spawn(async move {
            let mut data = [0; 2048];
            loop {
                let (n, addr) = udp.recv_from(&mut data).await.unwrap();
                udp.send_to(&data[..n], addr).await.unwrap();
            }
        });
        let protector = Arc::new(Protector(AtomicUsize::new(0)));
        let mut client_config = config(reference.address, &PublicKey::from(&server));
        client_config.peers[0].preshared_key =
            psk.map(|key| KeyMaterial::parse(&STANDARD.encode(key)).unwrap());
        let client = Client::start(client_config, Some(protector.clone()))
            .await
            .unwrap();
        for ip in ["198.51.100.7", "2001:db8::7"] {
            let stream = client
                .connect(SocketAddr::new(ip.parse().unwrap(), tcp_port))
                .await
                .unwrap();
            let (mut read, mut write) = tokio::io::split(stream);
            let sent: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
            let sender = async {
                write.write_all(&sent).await.unwrap();
                write.shutdown().await.unwrap();
            };
            let receiver = async {
                let mut got = Vec::new();
                read.read_to_end(&mut got).await.unwrap();
                assert_eq!(got, sent);
            };
            tokio::join!(sender, receiver);
            drop((read, write));
            let session = client
                .open_udp(SocketAddr::new(ip.parse().unwrap(), udp_port))
                .await
                .unwrap();
            let max_payload = if session.peer_addr().is_ipv4() {
                1392
            } else {
                1372
            };
            let payload = vec![0x5a; max_payload];
            session.send(&payload).await.unwrap();
            assert_eq!(&session.recv().await.unwrap()[..], payload);
            assert!(matches!(
                session.send(&vec![0x5a; max_payload + 1]).await,
                Err(xray_wireguard::Error::PacketTooLarge)
            ));
        }
        // Keep completed one-shot sessions alive as a TUN does until its UDP
        // idle timeout. The old 16-slot budget rejected the seventeenth port.
        // Stay below the native oracle's shared 32-flow forwarding budget,
        // which also retains the earlier UDP requests until its idle timeout.
        let mut idle_udp = Vec::new();
        for index in 0..24 {
            let ip = if index % 2 == 0 {
                "198.51.100.7"
            } else {
                "2001:db8::7"
            };
            let session = client
                .open_udp(SocketAddr::new(ip.parse().unwrap(), udp_port))
                .await
                .unwrap();
            let payload = vec![index as u8; 128];
            session.send(&payload).await.unwrap();
            assert_eq!(&session.recv().await.unwrap()[..], payload);
            idle_udp.push(session);
        }
        assert_eq!(
            protector.0.load(Ordering::SeqCst),
            1,
            "shared engine protects one socket"
        );
        timeout(Duration::from_secs(3), client.shutdown())
            .await
            .expect("shutdown while workers wait");
        assert!(!client.is_live());
        assert_eq!(client.available_tcp_slots(), 16);
        assert_eq!(client.available_udp_slots(), 512);
        echo_tcp.abort();
        echo_udp.abort();
        let _ = tokio::join!(echo_tcp, echo_udp);
    })
    .await
    .expect("WireGuard live test deadline");
}

#[tokio::test]
#[ignore = "requires pinned reference; use check-wireguard-runtime.sh or check-native-wireguard-interop.sh"]
async fn pinned_reference_wrong_keys_or_psk_never_deliver_application_data_and_recover() {
    timeout(Duration::from_secs(60), async {
        let server = StaticSecret::from([0x53;32]);
        let client_public = PublicKey::from(&StaticSecret::from([0x42;32]));
        let reference = support::Reference::start_with_psk(&server, &client_public, Some(&[0x64;32])).await;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST,0)).await.unwrap();
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST,0)).await.unwrap();
        let tcp_target = SocketAddr::new("198.51.100.7".parse().unwrap(),tcp.local_addr().unwrap().port());
        let udp_target = SocketAddr::new("198.51.100.7".parse().unwrap(),udp.local_addr().unwrap().port());
        for (bad, private_seed, server_seed) in [
            (None, 0x42, 0x53),
            (Some([0x65;32]), 0x42, 0x53),
            (Some([0x64;32]), 0x43, 0x53),
            (Some([0x64;32]), 0x42, 0x54),
        ] {
            let mut cfg = config(reference.address,&PublicKey::from(&server));
            cfg.secret_key = KeyMaterial::parse(&STANDARD.encode([private_seed;32])).unwrap();
            cfg.peers[0].public_key = KeyMaterial::parse(&STANDARD.encode(
                PublicKey::from(&StaticSecret::from([server_seed;32])).as_bytes()
            )).unwrap();
            cfg.peers[0].preshared_key = bad.map(|key| KeyMaterial::parse(&STANDARD.encode(key)).unwrap());
            let client = Client::start(cfg,None).await.unwrap();
            let session = client.open_udp(udp_target).await.unwrap();
            session.send(b"must not escape failed authentication").await.unwrap();
            let mut bytes = [0;128];
            tokio::select! {
                result = client.connect(tcp_target) => assert!(matches!(result, Err(xray_wireguard::Error::Timeout))),
                _ = tcp.accept() => panic!("TCP reached application with incorrect key or PSK"),
                _ = udp.recv(&mut bytes) => panic!("UDP reached application with incorrect key or PSK"),
            }
            timeout(Duration::from_secs(2),client.shutdown()).await.unwrap();
            assert_eq!(client.available_tcp_slots(),16);
            assert_eq!(client.available_udp_slots(),512);
        }
        // A fresh device with the matching key works; failed-device pending
        // packets must not be replayed into the new authenticated session.
        let mut cfg = config(reference.address,&PublicKey::from(&server));
        cfg.peers[0].preshared_key = Some(KeyMaterial::parse(&STANDARD.encode([0x64;32])).unwrap());
        let client = Client::start(cfg,None).await.unwrap();
        let mut stream = client.connect(tcp_target).await.unwrap();
        stream.write_all(b"valid PSK").await.unwrap();
        let (mut accepted,_) = tcp.accept().await.unwrap();
        let mut payload = [0;9]; accepted.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload,b"valid PSK");
        let session = client.open_udp(udp_target).await.unwrap();
        session.send(b"fresh UDP").await.unwrap();
        let mut payload = [0;128]; let n = udp.recv(&mut payload).await.unwrap();
        assert_eq!(&payload[..n],b"fresh UDP");
        client.shutdown().await;
    }).await.unwrap();
}

#[path = "multi_peer/interop.rs"]
mod multi;
