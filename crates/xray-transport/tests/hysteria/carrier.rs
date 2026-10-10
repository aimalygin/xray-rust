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
use xray_transport::{hysteria::HysteriaClient, SocketHandle, SocketProtector};

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

async fn scenario(salamander: bool, hopping: bool) {
    timeout(Duration::from_secs(35), async {
        let server = ReferenceServer::start_with_carrier(true, salamander).await;
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
        if hopping {
            // The nominal destination port is deliberately unused. Even the
            // first QUIC Initial must use one of the configured hop ports.
            let reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            config.remote_addr = reservation.local_addr().unwrap();
            config.carrier.udp_hop.ports = vec![first.address.port(), second.address.port()];
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
