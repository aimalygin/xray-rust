//! The OS network changed under live connections on UDP sockets of their
//! own: QUIC carriers and mKCP.

use std::sync::Arc;

use tokio::sync::watch;

/// One core's signal that the OS network changed. A QUIC connection dialed
/// with it takes a fresh protected socket on every change and keeps its
/// streams, as a Hysteria client does on its own rebind. A connection that
/// cannot move, behind a `realm`, `xdns` or `xicmp` mask, is left alone. An
/// mKCP connection on its own UDP socket cannot move either: its server
/// knows a session by the client's address. It fails at once if its
/// datagrams leave from another address now; otherwise it waits a short
/// while for its peer, and fails if the peer is not heard.
#[derive(Clone, Debug)]
pub struct NetworkChanges(Arc<watch::Sender<u64>>);

impl Default for NetworkChanges {
    fn default() -> Self {
        Self(Arc::new(watch::channel(0).0))
    }
}

impl NetworkChanges {
    /// Tells every connection that follows these changes of one: a QUIC
    /// connection takes a fresh socket, an mKCP connection fails or starts
    /// waiting for its peer. Returns how many follow them, of either kind: neither
    /// paths validated nor connections that will survive. An mKCP connection
    /// is counted until its driver is gone, a while after its stream.
    pub fn notify(&self) -> u64 {
        self.0
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        self.0.receiver_count() as u64
    }

    pub(crate) fn follow(&self) -> watch::Receiver<u64> {
        self.0.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One signal for a core: a dialer made from another by cloning shares
    /// it, so a notification on the first reaches whoever follows the second.
    #[test]
    fn dialers_made_from_one_share_its_changes() {
        let base = crate::TransportDialer::system().unwrap();
        let derived = base
            .clone()
            .with_socket_options(Arc::new(crate::SocketOptions::default()));
        assert_eq!(base.network_changes().notify(), 0);
        let follower = derived.network_changes().follow();
        assert!(!follower.has_changed().unwrap());
        assert_eq!(base.network_changes().notify(), 1);
        assert!(follower.has_changed().unwrap());
        drop(follower);
        assert_eq!(base.network_changes().notify(), 0);

        let other = crate::TransportDialer::system().unwrap();
        let _stranger = other.network_changes().follow();
        assert_eq!(base.network_changes().notify(), 0);
    }

    /// The two networks of [`TwoPathRelay`]: how long a datagram takes to
    /// the server and back from it.
    #[derive(Clone, Copy)]
    struct PathDelay {
        up: std::time::Duration,
        down: std::time::Duration,
    }

    /// A UDP relay in front of a QUIC server. Every client socket gets an
    /// upstream socket of its own, so the server sees a path per socket;
    /// the first one travels the old network, every later one the new one.
    async fn two_path_relay(
        server: std::net::SocketAddr,
        old: PathDelay,
        new: PathDelay,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use std::net::{Ipv4Addr, SocketAddr};
        use tokio::net::UdpSocket;
        use tokio::sync::mpsc;
        use tokio::time::Instant;
        type Queue = mpsc::UnboundedSender<(Instant, Vec<u8>)>;
        let front = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let address = front.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut paths = std::collections::HashMap::<SocketAddr, (Queue, PathDelay)>::new();
            let mut buffer = [0; 65535];
            while let Ok((n, client)) = front.recv_from(&mut buffer).await {
                if !paths.contains_key(&client) {
                    let delay = if paths.is_empty() { old } else { new };
                    let upstream =
                        Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
                    upstream.connect(server).await.unwrap();
                    let (up, mut up_queue) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
                    let (down, mut down_queue) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
                    let to_server = upstream.clone();
                    tokio::spawn(async move {
                        while let Some((at, data)) = up_queue.recv().await {
                            tokio::time::sleep_until(at).await;
                            let _ = to_server.send(&data).await;
                        }
                    });
                    let to_client = front.clone();
                    tokio::spawn(async move {
                        while let Some((at, data)) = down_queue.recv().await {
                            tokio::time::sleep_until(at).await;
                            let _ = to_client.send_to(&data, client).await;
                        }
                    });
                    tokio::spawn(async move {
                        let mut data = [0; 65535];
                        while let Ok(n) = upstream.recv(&mut data).await {
                            if down
                                .send((Instant::now() + delay.down, data[..n].to_vec()))
                                .is_err()
                            {
                                return;
                            }
                        }
                    });
                    paths.insert(client, (up, delay));
                }
                let (queue, delay) = &paths[&client];
                let _ = queue.send((Instant::now() + delay.up, buffer[..n].to_vec()));
            }
        });
        (address, task)
    }

    /// A QUIC connection that takes a fresh socket, as every connection
    /// that follows [`NetworkChanges`] does, still receives what is on its
    /// way to the old one. The old network is the slower one here, as
    /// cellular was for an iPhone back on Wi-Fi (2026-11-15): the answers
    /// to its DNS queries of the last tenth of a second before the change
    /// came in after the first packet over Wi-Fi. Quinn closed the old
    /// socket on that packet, and read what had reached it earlier only
    /// then, as its receive loop left the socket without a wake-up. Each
    /// reply here is a datagram of its own, which nothing sends again.
    #[tokio::test]
    async fn datagrams_on_their_way_to_the_old_socket_arrive_after_a_fresh_one() {
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::net::{Ipv4Addr, SocketAddr};
        use std::time::Duration;
        use tokio::time::Instant;

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["network-change.test".to_owned()]).unwrap();
        let certificate = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap();
        server_tls.alpn_protocols = vec![b"echo".to_vec()];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"echo".to_vec()];

        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(server_tls).unwrap(),
            )),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            while let Ok(datagram) = connection.read_datagram().await {
                let _ = connection.send_datagram(datagram);
            }
        });

        // The old network is four times as slow as the new one. The delays
        // are long so that a slow runner's scheduling stays small against
        // them.
        let old = PathDelay {
            up: Duration::from_millis(100),
            down: Duration::from_millis(300),
        };
        let new = PathDelay {
            up: Duration::from_millis(50),
            down: Duration::from_millis(50),
        };
        let (relay, relay_task) = two_path_relay(server_addr, old, new).await;
        // Without connection IDs of its own the client takes a packet by its
        // peer's address, whichever of its sockets it reaches: a server that
        // moves to another of the client's connection IDs with the path, as
        // Quinn's does, would have the late packets of the old path dropped
        // for their retired ID before they are any socket's business.
        let mut endpoint = quinn::EndpointConfig::default();
        endpoint.cid_generator(|| Box::new(quinn_proto::RandomConnectionIdGenerator::new(0)));
        let client = quinn::Endpoint::new(
            endpoint,
            None,
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let connection = client
            .connect_with(
                quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap())),
                relay,
                "network-change.test",
            )
            .unwrap()
            .await
            .unwrap();
        connection.send_datagram(vec![0].into()).unwrap();
        let warm_up = tokio::time::timeout(Duration::from_secs(5), connection.read_datagram())
            .await
            .expect("an echo before the change")
            .unwrap();
        assert_eq!(&warm_up[..], [0]);

        // Requests from 350 ms before the change on. Each reaches the server
        // before it hears of the new socket, 50 ms after the change, so its
        // reply takes the old path: due on the old socket from 50 ms to
        // 300 ms after the change, while the first packet on the new socket
        // is due about 100 ms after it. The last request leaves from the new
        // socket.
        let change = Instant::now() + Duration::from_millis(500);
        let requests: [(u8, i64); 6] = [
            (1, -350),
            (2, -280),
            (3, -210),
            (4, -150),
            (5, -100),
            (6, 150),
        ];
        let send = async {
            for (id, offset) in requests {
                let at = if offset < 0 {
                    change - Duration::from_millis(offset.unsigned_abs())
                } else {
                    change + Duration::from_millis(offset as u64)
                };
                tokio::time::sleep_until(at).await;
                connection.send_datagram(vec![id].into()).unwrap();
            }
        };
        let rebind = async {
            tokio::time::sleep_until(change).await;
            client
                .rebind(std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
                .unwrap();
        };
        let receive = async {
            let mut arrived = Vec::new();
            let deadline = change + Duration::from_millis(3000);
            while arrived.len() < requests.len() {
                match tokio::time::timeout_at(deadline, connection.read_datagram()).await {
                    Ok(Ok(datagram)) => {
                        arrived.push((datagram[0], Instant::now().duration_since(change)))
                    }
                    _ => break,
                }
            }
            arrived
        };
        let ((), (), arrived) = tokio::join!(send, rebind, receive);
        let mut ids: Vec<u8> = arrived.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        assert_eq!(ids, [1, 2, 3, 4, 5, 6], "every reply arrives: {arrived:?}");
        // Each reply about its path's round trip after the request, not when
        // a later packet on the new socket wakes the endpoint: 400 ms over
        // the old network, 100 ms over the new one.
        for (id, offset) in requests {
            let round_trip = if offset < 0 { 400 } else { 100 };
            let due = Duration::from_millis((offset + round_trip) as u64);
            let at = arrived.iter().find(|(reply, _)| *reply == id).unwrap().1;
            assert!(
                at <= due + Duration::from_millis(250),
                "reply {id} is due {due:?} after the change and came after {at:?}: {arrived:?}"
            );
        }
        connection.close(0u32.into(), b"done");
        relay_task.abort();
        echo.abort();
    }
}
