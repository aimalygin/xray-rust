use super::{
    network_change::Relay,
    support::{self, ReferenceServer, Task, DEADLINE, SALAMANDER_PASSWORD},
};
use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    hysteria::{GeckoPacketSize, HysteriaClient},
    SocketHandle, SocketProtector,
};

#[derive(Default)]
struct Protector {
    calls: AtomicUsize,
    reject: AtomicBool,
}
impl SocketProtector for Protector {
    fn protect(&self, _: SocketHandle) -> std::io::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.reject.load(Ordering::Acquire) {
            Err(std::io::Error::other("synthetic protection rejection"))
        } else {
            Ok(())
        }
    }
}

/// Gecko's packet sizes in the native Hysteria reference's own tests.
const GECKO: (u16, u16) = (100, 1200);

async fn scenario(salamander: bool, hopping: bool) {
    scenario_with(salamander, None, hopping).await;
}

async fn scenario_with(salamander: bool, gecko: Option<(u16, u16)>, hopping: bool) {
    timeout(Duration::from_secs(35), async {
        let server = match gecko {
            Some((min, max)) => ReferenceServer::start_with_gecko(min, max).await,
            None => ReferenceServer::start_with_carrier(true, salamander).await,
        };
        // Each visible hop port forwards to the same server, as a server-side
        // UDP port redirect does. Every source gets a distinct upstream socket:
        // the real reference must handle QUIC path migration itself.
        let first = Relay::start(server.address).await;
        let second = Relay::start(server.address).await;
        let protector = Arc::new(Protector::default());
        let tls = server
            .connector
            .clone()
            .with_socket_protector(protector.clone());
        let mut config = server.config();
        if salamander {
            config.carrier.salamander_password = Some(Arc::new(zeroize::Zeroizing::new(
                SALAMANDER_PASSWORD.into(),
            )));
        }
        config.carrier.gecko = gecko.map(|(min, max)| GeckoPacketSize::new(min, max).unwrap());
        if hopping {
            // The nominal destination port is deliberately unused. Even the
            // first QUIC Initial must use one of the configured hop ports.
            let reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            config.remote_addr = reservation.local_addr().unwrap();
            config.carrier.udp_hop.ports = vec![first.address.port(), second.address.port()];
            config.carrier.udp_hop.local = true;
            config.carrier.udp_hop.remote = true;
            config.carrier.udp_hop.interval_min = Duration::from_secs(5);
            config.carrier.udp_hop.interval_max = Duration::from_secs(5);
            drop(reservation);
        }
        let client = HysteriaClient::connect(config, &tls).await.unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let inner_tls = support::identity();
        let acceptor = inner_tls.acceptor;
        let _echo = Task(tokio::spawn(async move {
            // Exactly two application connections throughout all carrier changes:
            // one plain TCP and one independently authenticated inner TLS flow.
            let (plain, _) = listener.accept().await.unwrap();
            let plain = Task(tokio::spawn(async move {
                let (mut r, mut w) = plain.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            }));
            let (tls, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tls).await.unwrap();
            let (mut r, mut w) = tokio::io::split(&mut tls);
            let _ = tokio::io::copy(&mut r, &mut w).await;
            drop(plain);
        }));
        let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
        let mut tcp = client.open_tcp(&target).await.unwrap();
        // Trigger Xray's deferred outbound dial before opening the TLS flow.
        tcp.write_all(b"initial").await.unwrap();
        let mut initial = [0; 7];
        timeout(DEADLINE, tcp.read_exact(&mut initial))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&initial, b"initial");
        let stream = client.open_tcp(&target).await.unwrap();
        let mut inner = inner_tls
            .connector
            .connect_stream(Box::new(stream), &support::tls_settings())
            .await
            .unwrap();
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let udp_target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Udp);
        let _udp = Task(tokio::spawn(async move {
            let mut bytes = [0; 8192];
            loop {
                let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
                socket.send_to(&bytes[..n], peer).await.unwrap();
            }
        }));
        let udp = client.open_udp().unwrap();
        let session = udp.session_id();
        for phase in 0..3 {
            if phase > 0 {
                let old = client.local_addr().unwrap();
                if phase == 1 && hopping {
                    // Exercise the automatic timer, not just manual rebinding.
                } else {
                    assert!(client.rebind());
                }
                timeout(Duration::from_secs(7), async {
                    while client.local_addr().unwrap() == old {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("carrier changes without a new session");
            }
            let payload = vec![0x30 + phase; 32768];
            for stream in [
                &mut tcp as &mut dyn xray_transport::TransportStream,
                &mut *inner,
            ] {
                let mut reply = vec![0; payload.len()];
                timeout(DEADLINE, async {
                    let (mut r, mut w) = tokio::io::split(stream);
                    let (write, read) =
                        tokio::join!(w.write_all(&payload), r.read_exact(&mut reply));
                    write.unwrap();
                    read.unwrap();
                })
                .await
                .unwrap();
                assert_eq!(reply, payload);
            }
            let packet = vec![phase; 4000];
            timeout(DEADLINE, async {
                loop {
                    udp.send(&udp_target, &packet).await.unwrap();
                    if let Ok(reply) = timeout(Duration::from_millis(300), udp.recv()).await {
                        let reply = reply.unwrap();
                        assert_eq!(reply.source, udp_target);
                        assert_eq!(reply.payload, packet);
                        break;
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(udp.session_id(), session);
            assert_eq!(client.active_udp_sessions(), 1);
        }
        assert!(protector.calls.load(Ordering::SeqCst) >= 3);
        if hopping {
            // The first socket, the timer's hop and the rebind alternate
            // between the two hop ports: each hop starts from the port in use.
            let (a, b) = (first.sources(), second.sources());
            let (starter, other) = if a.first() < b.first() && !a.is_empty() {
                (a, b)
            } else {
                (b, a)
            };
            assert_eq!((starter.len(), other.len()), (2, 1));
            assert!(starter[0] < other[0] && other[0] < starter[1]);
        }
        protector.reject.store(true, Ordering::Release);
        assert!(client.rebind());
        timeout(DEADLINE, async {
            while client.is_live() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!client.rebind());
        client.close();
    })
    .await
    .expect("bounded Salamander/hop interoperability scenario");
}

#[tokio::test]
#[ignore = "requires pinned Xray/native Hysteria; use the interop scripts"]
async fn salamander_tcp_inner_tls_udp_and_rebind() {
    scenario(true, false).await;
}

#[tokio::test]
#[ignore = "requires pinned Xray/native Hysteria; use the interop scripts"]
async fn hopping_tcp_inner_tls_udp_and_rebind() {
    scenario(false, true).await;
}

#[tokio::test]
#[ignore = "requires pinned Xray/native Hysteria; use the interop scripts"]
async fn salamander_and_hopping_tcp_inner_tls_udp_and_rebind() {
    scenario(true, true).await;
}

#[tokio::test]
#[ignore = "requires pinned Xray/native Hysteria; use the interop scripts"]
async fn gecko_and_hopping_tcp_inner_tls_udp_and_rebind() {
    scenario_with(true, Some(GECKO), true).await;
}

#[tokio::test]
#[ignore = "requires pinned Xray/native Hysteria; use the interop scripts"]
async fn gecko_and_plain_salamander_cannot_complete_a_handshake() {
    // Gecko frames are not QUIC packets, and Gecko drops unframed long
    // headers, so a handshake succeeds only when both sides use Gecko.
    for (server_gecko, client_gecko) in [(true, false), (false, true)] {
        let server = if server_gecko {
            ReferenceServer::start_with_gecko(GECKO.0, GECKO.1).await
        } else {
            ReferenceServer::start_with_carrier(true, true).await
        };
        let mut config = server.config();
        config.limits.operation_timeout = Duration::from_millis(500);
        config.carrier.salamander_password = Some(Arc::new(zeroize::Zeroizing::new(
            SALAMANDER_PASSWORD.into(),
        )));
        config.carrier.gecko =
            client_gecko.then(|| GeckoPacketSize::new(GECKO.0, GECKO.1).unwrap());
        assert!(
            HysteriaClient::connect(config, &server.connector)
                .await
                .is_err(),
            "server Gecko {server_gecko}, client Gecko {client_gecko}"
        );
    }
}

#[tokio::test]
#[ignore = "requires pinned Xray/native Hysteria; use the interop scripts"]
async fn gecko_padding_past_the_carrier_budget_still_connects() {
    // The reference pads its fragments up to 2,048 bytes; ours stop at 1,452.
    let server = ReferenceServer::start_with_gecko(1500, 2048).await;
    let mut config = server.config();
    config.carrier.salamander_password = Some(Arc::new(zeroize::Zeroizing::new(
        SALAMANDER_PASSWORD.into(),
    )));
    config.carrier.gecko = GeckoPacketSize::new(1500, 2048);
    let client = HysteriaClient::connect(config, &server.connector)
        .await
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let _echo = Task(tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut r, mut w) = stream.into_split();
        let _ = tokio::io::copy(&mut r, &mut w).await;
    }));
    let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
    let mut tcp = client.open_tcp(&target).await.unwrap();
    tcp.write_all(b"gecko").await.unwrap();
    let mut reply = [0; 5];
    timeout(DEADLINE, tcp.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"gecko");
    client.close();
}

#[tokio::test]
#[ignore = "requires pinned Xray/native Hysteria; use the interop scripts"]
async fn wrong_salamander_password_cannot_fall_back_to_plain_quic() {
    let server = ReferenceServer::start_with_carrier(true, true).await;
    for password in [None, Some("wrong-synthetic-password")] {
        let mut config = server.config();
        config.limits.operation_timeout = Duration::from_millis(500);
        config.carrier.salamander_password =
            password.map(|p| Arc::new(zeroize::Zeroizing::new(p.into())));
        assert!(HysteriaClient::connect(config, &server.connector)
            .await
            .is_err());
    }
}
