//! A stale carrier stays blackholed even after the new path becomes available.
//! Each client source port gets a distinct upstream socket, so the reference
//! server must really migrate its QUIC peer address, not just see one relay NAT.
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::support::{ReferenceServer, Task, DEADLINE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::hysteria::HysteriaClient;
use xray_transport::{SocketHandle, SocketProtector};

struct Relay {
    address: SocketAddr,
    blocked: Arc<AtomicU16>,
    _driver: Task,
}
impl Relay {
    async fn start(server: SocketAddr) -> Self {
        let front = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let address = front.local_addr().unwrap();
        let blocked = Arc::new(AtomicU16::new(0));
        let filter = blocked.clone();
        let driver = Task(tokio::spawn(async move {
            let mut paths: HashMap<SocketAddr, (Arc<UdpSocket>, Task)> = HashMap::new();
            let mut buffer = [0; 65535];
            loop {
                let (n, client) = front.recv_from(&mut buffer).await.unwrap();
                if client.port() == filter.load(Ordering::Acquire) {
                    continue;
                }
                if !paths.contains_key(&client) {
                    assert!(paths.len() < 3, "bounded synthetic path count");
                    let upstream =
                        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
                    upstream.connect(server).await.unwrap();
                    let source = upstream.clone();
                    let output = front.clone();
                    let dropped = filter.clone();
                    let reply = Task(tokio::spawn(async move {
                        let mut data = [0; 65535];
                        loop {
                            let n = source.recv(&mut data).await.unwrap();
                            if client.port() != dropped.load(Ordering::Acquire) {
                                output.send_to(&data[..n], client).await.unwrap();
                            }
                        }
                    }));
                    paths.insert(client, (upstream, reply));
                }
                paths[&client].0.send(&buffer[..n]).await.unwrap();
            }
        }));
        Self {
            address,
            blocked,
            _driver: driver,
        }
    }
}

#[derive(Default)]
struct Protector(AtomicUsize);
impl SocketProtector for Protector {
    fn protect(&self, _: SocketHandle) -> std::io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires pinned Xray/native Hysteria; use the interop scripts"]
async fn blackholed_old_path_recovers_existing_tcp_udp_without_idle_timeout() {
    timeout(Duration::from_secs(25), async {
        let server = ReferenceServer::start().await;
        let relay = Relay::start(server.address).await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tcp_target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp);
        let _tcp = Task(tokio::spawn(async move {
            // Exactly one application connection for the entire test.
            let (mut socket, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = socket.split();
            tokio::io::copy(&mut r, &mut w).await.unwrap();
        }));
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let udp_target = Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Udp);
        let _udp = Task(tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
                socket.send_to(&buffer[..n], peer).await.unwrap();
            }
        }));
        let protector = Arc::new(Protector::default());
        let tls = server
            .connector
            .clone()
            .with_socket_protector(protector.clone());
        let mut config = server.config();
        config.remote_addr = relay.address;
        let client = HysteriaClient::connect(config, &tls).await.unwrap();
        let mut tcp = client.open_tcp(&tcp_target).await.unwrap();
        let udp = client.open_udp().unwrap();
        let session = udp.session_id();
        tcp.write_all(b"before").await.unwrap();
        let mut before = [0; 6];
        timeout(DEADLINE, tcp.read_exact(&mut before))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&before, b"before");
        udp.send(&udp_target, b"before").await.unwrap();
        assert_eq!(
            timeout(DEADLINE, udp.recv())
                .await
                .unwrap()
                .unwrap()
                .payload,
            b"before"
        );

        for burst in 1..=2 {
            let old = client.local_addr().unwrap();
            relay.blocked.store(old.port(), Ordering::Release);
            udp.send(&udp_target, b"lost on stale path").await.unwrap();
            assert!(timeout(Duration::from_millis(300), udp.recv())
                .await
                .is_err());
            assert!(client.is_live(), "QUIC has not reached its idle timeout");
            assert_eq!(client.local_addr().unwrap(), old);
            let start = Instant::now();
            for _ in 0..20 {
                assert!(client.rebind());
            }
            timeout(Duration::from_secs(2), async {
                while client.local_addr().unwrap() == old {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let payload = vec![burst as u8; 32768];
            let mut reply = vec![0; payload.len()];
            timeout(DEADLINE, async {
                let (mut r, mut w) = tokio::io::split(&mut tcp);
                let (sent, received) =
                    tokio::join!(w.write_all(&payload), r.read_exact(&mut reply));
                sent.unwrap();
                received.unwrap();
                assert_eq!(reply, payload);
                loop {
                    udp.send(&udp_target, b"same UDP lease").await.unwrap();
                    if let Ok(value) = timeout(Duration::from_millis(200), udp.recv()).await {
                        assert_eq!(value.unwrap().payload, b"same UDP lease");
                        break;
                    }
                }
            })
            .await
            .expect("rebind must recover before the 30-second idle timeout");
            assert_eq!(udp.session_id(), session);
            assert_eq!(protector.0.load(Ordering::SeqCst), burst + 1);
            eprintln!(
                "Hysteria existing-flow carrier recovery burst {burst}: {:?}",
                start.elapsed()
            );
        }
        client.close();
        assert!(!client.rebind());
        assert_eq!(client.active_udp_sessions(), 0);
    })
    .await
    .expect("bounded carrier recovery scenario");
}
