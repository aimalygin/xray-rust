#[path = "support/relay.rs"]
mod relay;
mod support;

use relay::{no_delivery, Echo, Event, Relay, WAIT};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time::{timeout, Instant};
use x25519_dalek::{PublicKey, StaticSecret};
use xray_proxy::wireguard::KeyMaterial;
use xray_transport::{SocketHandle, SocketProtector};
use xray_wireguard::{Client, Config, PeerConfig};

#[derive(Default)]
struct Protector(AtomicUsize);
impl SocketProtector for Protector {
    fn protect(&self, _: SocketHandle) -> std::io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn key(bytes: &[u8; 32]) -> KeyMaterial {
    KeyMaterial::parse(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap()
}
async fn setup(ip: IpAddr, keepalive: u16) -> (support::Reference, Relay, Client, Arc<Protector>) {
    assert!(
        std::env::var_os("NATIVE_WIREGUARD_BINARY").is_some(),
        "use check-native-wireguard-interop.sh for the official reference"
    );
    let server = StaticSecret::from([0x53; 32]);
    let reference = support::Reference::start_custom(
        &server,
        &PublicKey::from(&StaticSecret::from([0x42; 32])),
        Some(&[0x64; 32]),
        ip,
        0,
    )
    .await;
    let relay = Relay::start(reference.address).await;
    let protector = Arc::new(Protector::default());
    let client = Client::start(
        Config {
            secret_key: key(&[0x42; 32]),
            peers: vec![PeerConfig {
                public_key: key(PublicKey::from(&server).as_bytes()),
                preshared_key: Some(key(&[0x64; 32])),
                endpoint: relay.address(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                keepalive,
            }],
            addresses: vec!["10.44.0.2".parse().unwrap(), "fd44::2".parse().unwrap()],
            mtu: 1420,
        },
        Some(protector.clone()),
    )
    .await
    .unwrap();
    (reference, relay, client, protector)
}
async fn shutdown(client: &Client, protector: &Protector) {
    assert_eq!(
        protector.0.load(Ordering::SeqCst),
        1,
        "reuse the protected socket"
    );
    timeout(WAIT, client.shutdown()).await.unwrap();
    assert!(!client.is_live());
    assert_eq!(client.available_tcp_slots(), 16);
    assert_eq!(client.available_udp_slots(), 512);
}

#[tokio::test]
#[ignore = "requires official wireguard-go; use check-native-wireguard-interop.sh"]
async fn native_ipv4_roaming_replay_and_forgery_do_not_redirect_the_peer() {
    roaming("127.0.0.1".parse().unwrap()).await;
}
#[tokio::test]
#[ignore = "requires official wireguard-go; use check-native-wireguard-interop.sh"]
async fn native_ipv6_roaming_replay_and_forgery_do_not_redirect_the_peer() {
    roaming("::1".parse().unwrap()).await;
}
async fn roaming(outer: IpAddr) {
    timeout(Duration::from_secs(25), async {
        let (_reference, mut relay, client, protector) = setup(outer, 0).await;
        let echo = Echo::udp().await;
        for ip in ["198.51.100.7", "2001:db8::7"] {
            let session = client
                .open_udp(SocketAddr::new(ip.parse().unwrap(), echo.port))
                .await
                .unwrap();
            relay.exchange(&session, b"original", 0).await;
            let replay = relay.last_reply.clone();

            // A valid, previously accepted ciphertext must neither deliver twice
            // nor move the endpoint when replayed from a different UDP port.
            relay.inject(1, &replay).await;
            no_delivery(&session).await;
            relay.exchange(&session, b"no replay roaming", 0).await;

            let held = relay.hold_reply(&session, b"authentic held reply").await;
            let mut forged = held.clone();
            *forged.last_mut().unwrap() ^= 1;
            relay.inject(1, &forged).await;
            no_delivery(&session).await;
            relay.exchange(&session, b"no forged roaming", 0).await;
            // Failed authentication must not consume a counter. The original
            // packet remains deliverable out of order within the replay window.
            relay.inject(0, &held).await;
            assert_eq!(
                &timeout(WAIT, session.recv()).await.unwrap().unwrap()[..],
                b"authentic held reply"
            );

            let valid = relay.hold_reply(&session, b"authenticated move").await;
            relay.response_front = 1;
            relay.inject(1, &valid).await;
            assert_eq!(
                &timeout(WAIT, session.recv()).await.unwrap().unwrap()[..],
                b"authenticated move"
            );
            relay.exchange(&session, b"new endpoint", 1).await;

            relay.inject(0, &replay).await;
            relay.inject(0, &valid).await;
            no_delivery(&session).await;
            relay.exchange(&session, b"still new endpoint", 1).await;

            let back = relay.hold_reply(&session, b"authenticated return").await;
            relay.response_front = 0;
            relay.inject(0, &back).await;
            assert_eq!(
                &timeout(WAIT, session.recv()).await.unwrap().unwrap()[..],
                b"authenticated return"
            );
            relay
                .exchange(&session, b"original endpoint again", 0)
                .await;
        }
        shutdown(&client, &protector).await;
    })
    .await
    .expect("roaming deadline");
}

#[tokio::test]
#[ignore = "requires official wireguard-go; use check-native-wireguard-interop.sh"]
async fn native_server_crash_recovers_existing_udp_sessions_without_restarting_client() {
    timeout(Duration::from_secs(100), async {
        for outer in ["127.0.0.1", "::1"] {
            let (mut reference, mut relay, client, protector) =
                setup(outer.parse().unwrap(), 1).await;
            let echo = Echo::udp().await;
            let v4 = client
                .open_udp(SocketAddr::new("198.51.100.7".parse().unwrap(), echo.port))
                .await
                .unwrap();
            let v6 = client
                .open_udp(SocketAddr::new("2001:db8::7".parse().unwrap(), echo.port))
                .await
                .unwrap();
            relay.exchange(&v4, b"before crash v4", 0).await;
            relay.exchange(&v6, b"before crash v6", 0).await;
            let handshakes = relay.handshakes;
            reference.crash();
            // Explicitly send an encrypted request into the dead server.
            v4.send(b"lost during crash").await.unwrap();
            timeout(WAIT, async {
                loop {
                    if let Event::Client { packet, .. } = relay.step(true).await {
                        if relay::data(&packet) {
                            break;
                        }
                    }
                }
            })
            .await
            .unwrap();
            no_delivery(&v4).await;
            reference.restart().await;
            let started = Instant::now();
            timeout(Duration::from_secs(40), async {
                let mut retry = tokio::time::interval(Duration::from_millis(500));
                loop {
                    tokio::select! {
                        _ = retry.tick() => v4.send(b"recovered").await.unwrap(),
                        _ = relay.step(true) => {},
                        result = v4.recv() => {
                            assert_eq!(&result.unwrap()[..], b"recovered");
                            break;
                        },
                    }
                }
            })
            .await
            .expect("same client must handshake with the restarted server");
            assert!(
                relay.handshakes > handshakes,
                "recovery requires fresh session keys"
            );
            eprintln!(
                "native WireGuard {outer} crash recovery: {:?}",
                started.elapsed()
            );
            relay.exchange(&v6, b"same IPv6 flow after crash", 0).await;
            shutdown(&client, &protector).await;
        }
    })
    .await
    .expect("crash recovery deadline");
}

#[tokio::test]
#[ignore = "requires official wireguard-go and real 120-second rekey timer; use check-native-wireguard-interop.sh"]
async fn native_persistent_keepalive_and_timed_rekey_preserve_the_live_flow() {
    timeout(Duration::from_secs(150), async {
        let (_reference, mut relay, client, protector) =
            setup("127.0.0.1".parse().unwrap(), 1).await;
        let echo = Echo::udp().await;
        let session = client
            .open_udp(SocketAddr::new("198.51.100.7".parse().unwrap(), echo.port))
            .await
            .unwrap();
        relay.exchange(&session, b"before timed rekey", 0).await;
        let old = relay.last_reply.clone();
        let handshakes = relay.handshakes;
        let initiations = relay.initiations;
        let started = Instant::now();

        // Observe two distinct idle transport keepalives after the application
        // reply, rather than counting the empty handshake confirmation packet.
        timeout(Duration::from_secs(5), async {
            let mut first = None;
            loop {
                match relay.step(true).await {
                    Event::Client { packet, .. }
                        if relay::transport(&packet) && packet.len() == 32 =>
                    {
                        if let Some(previous) = first {
                            assert!(Instant::now() - previous >= Duration::from_millis(700));
                            break;
                        }
                        first = Some(Instant::now());
                    }
                    Event::Client { packet, .. } => {
                        assert!(!relay::data(&packet), "idle client sent application data")
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("persistent keepalive deadline");
        assert_eq!(relay.handshakes, handshakes);
        assert_eq!(relay.initiations, initiations);

        // Keep real traffic flowing across the unmodified production timer.
        // No fake clock, engine hook or shortened reference timer is involved.
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        while relay.handshakes == handshakes {
            tokio::select! {
                _ = tick.tick() => relay.exchange(&session, b"traffic across timed rekey", 0).await,
                _ = relay.step(true) => {},
            }
        }
        assert!(
            started.elapsed() >= Duration::from_secs(119),
            "unexpected early handshake"
        );
        assert!(
            relay.initiations > initiations,
            "the client must initiate the timed rekey"
        );
        relay.exchange(&session, b"after timed rekey", 0).await;
        assert_ne!(
            &relay.last_reply[4..8],
            &old[4..8],
            "new WireGuard receiver index"
        );
        relay.inject(0, &old).await;
        no_delivery(&session).await;
        relay
            .exchange(&session, b"healthy after old session replay", 0)
            .await;
        eprintln!("native WireGuard timed rekey: {:?}", started.elapsed());
        shutdown(&client, &protector).await;
    })
    .await
    .expect("real-time rekey deadline");
}
