//! A bounded loopback wire relay. It never decrypts or manufactures WireGuard
//! traffic: only the official server and the production client hold sessions.
use std::{net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::timeout};
use xray_wireguard::UdpSession;

pub const WAIT: Duration = Duration::from_secs(5);

pub enum Event {
    Client { front: usize, packet: Vec<u8> },
    Server(Vec<u8>),
}
pub fn transport(packet: &[u8]) -> bool {
    packet.len() >= 32 && packet[..4] == [4, 0, 0, 0]
}
pub fn data(packet: &[u8]) -> bool {
    transport(packet) && packet.len() > 32
}

pub struct Relay {
    fronts: [UdpSocket; 2],
    backend: UdpSocket,
    server: SocketAddr,
    client: Option<SocketAddr>,
    pub response_front: usize,
    pub last_reply: Vec<u8>,
    pub initiations: usize,
    pub handshakes: usize,
    pending: Option<Event>,
}
impl Relay {
    pub async fn start(server: SocketAddr) -> Self {
        assert!(server.ip().is_loopback());
        let bind = SocketAddr::new(server.ip(), 0);
        Self {
            fronts: [
                UdpSocket::bind(bind).await.unwrap(),
                UdpSocket::bind(bind).await.unwrap(),
            ],
            backend: UdpSocket::bind(bind).await.unwrap(),
            server,
            client: None,
            response_front: 0,
            last_reply: Vec::new(),
            initiations: 0,
            handshakes: 0,
            pending: None,
        }
    }
    pub fn address(&self) -> SocketAddr {
        self.fronts[0].local_addr().unwrap()
    }
    pub async fn inject(&self, front: usize, packet: &[u8]) {
        assert_eq!(
            self.fronts[front]
                .send_to(packet, self.client.unwrap())
                .await
                .unwrap(),
            packet.len()
        );
    }
    pub async fn step(&mut self, deliver_data: bool) -> Event {
        // The surrounding test selects this pump against application reads and
        // timer ticks. Retain a received packet across a cancelled socket send.
        if self.pending.is_none() {
            self.pending = Some(self.receive().await);
        }
        match self.pending.as_ref().unwrap() {
            Event::Client { packet, .. } => {
                assert_eq!(
                    self.backend.send_to(packet, self.server).await.unwrap(),
                    packet.len()
                );
            }
            Event::Server(packet) if deliver_data || !data(packet) => {
                self.inject(self.response_front, packet).await;
            }
            Event::Server(_) => {}
        }
        self.pending.take().unwrap()
    }
    async fn receive(&mut self) -> Event {
        let (mut a, mut b, mut c) = ([0; 2048], [0; 2048], [0; 2048]);
        let (front, count, source, packet) = tokio::select! {
            r = self.fronts[0].recv_from(&mut a) => { let (n,s) = r.unwrap(); (Some(0),n,s,a) },
            r = self.fronts[1].recv_from(&mut b) => { let (n,s) = r.unwrap(); (Some(1),n,s,b) },
            r = self.backend.recv_from(&mut c) => { let (n,s) = r.unwrap(); (None,n,s,c) },
        };
        assert!(
            count < packet.len(),
            "relay buffer must not truncate packets"
        );
        let packet = &packet[..count];
        if let Some(front) = front {
            assert!(source.ip().is_loopback());
            if let Some(client) = self.client {
                assert_eq!(source, client, "client socket must survive the transition");
            }
            self.client = Some(source);
            if packet.starts_with(&[1, 0, 0, 0]) {
                self.initiations += 1;
            }
            Event::Client {
                front,
                packet: packet.to_vec(),
            }
        } else {
            assert_eq!(source, self.server);
            if packet.starts_with(&[2, 0, 0, 0]) {
                self.handshakes += 1;
            }
            if data(packet) {
                self.last_reply = packet.to_vec();
            }
            Event::Server(packet.to_vec())
        }
    }
    pub async fn exchange(&mut self, session: &UdpSession, payload: &[u8], front: usize) {
        timeout(WAIT, async {
            session.send(payload).await.unwrap();
            let mut sent = false;
            loop {
                tokio::select! {
                    received = session.recv() => {
                        assert_eq!(&received.unwrap()[..], payload);
                        assert!(sent, "must observe the client's encrypted request");
                        break;
                    },
                    event = self.step(true) => if let Event::Client { front: actual, packet } = event {
                        if data(&packet) {
                            assert_eq!(actual, front, "authenticated endpoint selection");
                            sent = true;
                        }
                    },
                }
            }
        }).await.expect("roundtrip deadline");
    }
    pub async fn hold_reply(&mut self, session: &UdpSession, payload: &[u8]) -> Vec<u8> {
        timeout(WAIT, async {
            session.send(payload).await.unwrap();
            loop {
                if let Event::Server(packet) = self.step(false).await {
                    if data(&packet) {
                        return packet;
                    }
                }
            }
        })
        .await
        .expect("capture deadline")
    }
}

pub async fn no_delivery(session: &UdpSession) {
    assert!(
        timeout(Duration::from_millis(150), session.recv())
            .await
            .is_err(),
        "unauthenticated or replayed packet reached the application"
    );
}

pub struct Echo {
    task: tokio::task::JoinHandle<()>,
    pub port: u16,
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Echo {
    pub async fn udp() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut packet = [0; 2048];
            loop {
                let (n, source) = socket.recv_from(&mut packet).await.unwrap();
                assert_eq!(socket.send_to(&packet[..n], source).await.unwrap(), n);
            }
        });
        Self { task, port }
    }
}
