//! The bridge side of the VLESS reverse proxy against a portal written here
//! from Xray-core v26.10.31's VLESS inbound and Mux client: the tunnel, the
//! sessions routed as from the reverse tag, freedom's default refusal, and
//! the monitor replacing drained and lost tunnels.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{timeout, Instant};
use xray_core_rs::Core;
use xray_proxy::mux::{self, Status};
use xray_proxy::reverse::{encode_control, ControlState};
use xray_routing::{Network, Target, TargetAddr};

const ID: &str = "27848739-7e62-4138-9fd3-098a63964b6b";
const TAG: &str = "r-in";
/// The monitor's first run, the held header and some slack.
const TUNNEL_WAIT: Duration = Duration::from_secs(10);

fn tcp(addr: SocketAddr) -> Target {
    Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Tcp)
}

fn udp(addr: SocketAddr) -> Target {
    Target::new(TargetAddr::Ip(addr.ip()), addr.port(), Network::Udp)
}

fn endpoint_bytes(target: &Target, out: &mut Vec<u8>) {
    out.push(match target.network {
        Network::Tcp => 1,
        Network::Udp => 2,
    });
    out.extend(target.port.to_be_bytes());
    match &target.addr {
        TargetAddr::Ip(std::net::IpAddr::V4(ip)) => {
            out.push(1);
            out.extend(ip.octets());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(ip)) => {
            out.push(3);
            out.extend(ip.octets());
        }
        TargetAddr::Domain(name) => {
            out.extend([2, name.len() as u8]);
            out.extend(name.as_bytes());
        }
    }
}

/// A frame as the portal's Mux client writes it on a reverse connection.
fn frame(
    id: u16,
    status: Status,
    target: Option<&Target>,
    source: Option<&Target>,
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let mut meta = id.to_be_bytes().to_vec();
    meta.extend([status as u8, u8::from(payload.is_some())]);
    if let Some(target) = target {
        endpoint_bytes(target, &mut meta);
    }
    if let Some(source) = source {
        endpoint_bytes(source, &mut meta);
        endpoint_bytes(&tcp("203.0.113.1:443".parse().unwrap()), &mut meta);
    }
    let mut wire = (meta.len() as u16).to_be_bytes().to_vec();
    wire.extend(meta);
    if let Some(payload) = payload {
        wire.extend((payload.len() as u16).to_be_bytes());
        wire.extend(payload);
    }
    wire
}

/// The portal's end of one tunnel.
struct Tunnel {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl Tunnel {
    async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
    }

    async fn open_control(&mut self) {
        let control = Target::new(TargetAddr::Domain("reverse".into()), 0, Network::Udp);
        self.send(&frame(1, Status::New, Some(&control), None, None))
            .await;
        self.control(ControlState::Active).await;
    }

    async fn control(&mut self, state: ControlState) {
        self.send(&frame(
            1,
            Status::Keep,
            None,
            None,
            Some(&encode_control(state, &[0x5a; 13])),
        ))
        .await;
    }

    async fn open(&mut self, id: u16, target: &Target, source: &str, payload: &[u8]) {
        let source = tcp(source.parse().unwrap());
        self.send(&frame(
            id,
            Status::New,
            Some(target),
            Some(&source),
            Some(payload),
        ))
        .await;
    }

    /// The next frame from the bridge, as the portal's client worker reads
    /// it; `None` once the bridge closed the tunnel or `wait` passed.
    async fn next(
        &mut self,
        wait: Duration,
    ) -> Option<(u16, Status, bool, Option<Target>, Vec<u8>)> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some((frame, n)) = mux::decode(&self.buffer).unwrap() {
                let decoded = (
                    frame.session_id,
                    frame.status,
                    frame.error,
                    frame.target.clone(),
                    frame.payload.unwrap_or_default().to_vec(),
                );
                self.buffer.drain(..n);
                return Some(decoded);
            }
            let mut chunk = [0; 16384];
            let n = match tokio::time::timeout_at(deadline, self.stream.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return None,
            };
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }
}

/// A portal: Xray-core's VLESS inbound for one user with `reverse`.
struct Portal {
    listener: TcpListener,
}

impl Portal {
    async fn start() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    /// Takes the next tunnel: the VLESS reverse request, which names no
    /// address, then the response header.
    async fn accept(&self, wait: Duration) -> Option<Tunnel> {
        let (mut stream, _) = timeout(wait, self.listener.accept()).await.ok()?.ok()?;
        let accepted = Instant::now();
        let mut head = [0; 18];
        stream.read_exact(&mut head).await.ok()?;
        // The header waits 500 ms for a payload that never comes first.
        assert!(accepted.elapsed() >= Duration::from_millis(450));
        assert_eq!(head[0], 0, "VLESS version");
        assert_eq!(&head[1..17], uuid::Uuid::parse_str(ID).unwrap().as_bytes());
        let mut addons = vec![0; usize::from(head[17])];
        stream.read_exact(&mut addons).await.ok()?;
        assert_eq!(stream.read_u8().await.ok()?, 0x04, "the reverse command");
        stream.write_all(&[0, 0]).await.ok()?;
        Some(Tunnel {
            stream,
            buffer: Vec::new(),
        })
    }
}

/// A TCP echo that counts the connections it takes.
async fn tcp_echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    (addr, accepted)
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0; 65536];
        while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..n], from).await;
        }
    });
    addr
}

fn bridge_config(portal: SocketAddr, freedom: Value, rules: Value) -> Value {
    json!({
        "outbounds": [
            {"tag": "portal", "protocol": "vless", "settings": {
                "address": "127.0.0.1", "port": portal.port(), "id": ID,
                "encryption": "none", "email": "bridge@example.com",
                "reverse": {"tag": TAG}}},
            {"tag": "direct", "protocol": "freedom", "settings": freedom},
            {"tag": "block", "protocol": "blackhole"}
        ],
        "routing": {"rules": rules}
    })
}

fn allow(addrs: &[SocketAddr]) -> Value {
    let ports: Vec<String> = addrs.iter().map(|addr| addr.port().to_string()).collect();
    json!({"finalRules": [{"action": "allow", "ip": ["127.0.0.1"], "port": ports.join(",")}]})
}

async fn start(config: Value) -> Core {
    let config = xray_config::parse_xray_json(&config.to_string())
        .unwrap_or_else(|error| panic!("{:?}", error.diagnostics))
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

#[tokio::test]
async fn sessions_reach_the_services_freedom_allows() {
    let portal = Portal::start().await;
    let (tcp_addr, _) = tcp_echo().await;
    let udp_addr = udp_echo().await;
    let mut core = start(bridge_config(
        portal.addr(),
        allow(&[tcp_addr, udp_addr]),
        json!([{"inboundTag": [TAG], "outboundTag": "direct"}]),
    ))
    .await;
    let started = Instant::now();
    let mut tunnel = portal.accept(TUNNEL_WAIT).await.expect("a tunnel");
    // Xray-core's monitor runs first 2 seconds after the start.
    assert!(started.elapsed() >= Duration::from_millis(1900));
    tunnel.open_control().await;

    tunnel
        .open(2, &tcp(tcp_addr), "198.51.100.7:40000", b"hello")
        .await;
    let (id, status, _, _, payload) = tunnel.next(Duration::from_secs(5)).await.unwrap();
    assert_eq!(
        (id, status, payload.as_slice()),
        (2, Status::Keep, &b"hello"[..])
    );
    // Xray-core's portal writes a stream in frames of at most 8 KiB.
    for _ in 0..4 {
        tunnel
            .send(&frame(2, Status::Keep, None, None, Some(&[9; 5000])))
            .await;
    }
    let mut echoed = 0;
    while echoed < 20000 {
        let (id, status, _, _, payload) = tunnel.next(Duration::from_secs(5)).await.unwrap();
        assert_eq!((id, status), (2, Status::Keep));
        assert!(payload.iter().all(|&b| b == 9));
        echoed += payload.len();
    }
    assert_eq!(core.connection_snapshot().connections.len(), 1);
    assert_eq!(
        core.connection_snapshot().connections[0]
            .inbound_tag
            .as_deref(),
        Some(TAG)
    );

    tunnel
        .open(3, &udp(udp_addr), "198.51.100.7:40001", b"ping")
        .await;
    let (id, status, _, source, payload) = tunnel.next(Duration::from_secs(5)).await.unwrap();
    assert_eq!(
        (id, status, payload.as_slice()),
        (3, Status::Keep, &b"ping"[..])
    );
    assert_eq!(source, Some(udp(udp_addr)));
    tunnel
        .send(&frame(
            3,
            Status::Keep,
            Some(&udp(udp_addr)),
            None,
            Some(b"pong"),
        ))
        .await;
    let (id, _, _, _, payload) = tunnel.next(Duration::from_secs(5)).await.unwrap();
    assert_eq!((id, payload.as_slice()), (3, &b"pong"[..]));

    tunnel.send(&frame(2, Status::End, None, None, None)).await;
    core.stop().await.unwrap();
    // Stopping closes the tunnel.
    while tunnel.next(Duration::from_secs(5)).await.is_some() {}
    assert!(tunnel.stream.read_u8().await.is_err());
}

#[tokio::test]
async fn freedom_refuses_reverse_sessions_its_final_rules_do_not_allow() {
    let portal = Portal::start().await;
    let (allowed, _) = tcp_echo().await;
    let (other, other_accepted) = tcp_echo().await;
    let (plain, plain_accepted) = tcp_echo().await;
    let mut core = start(json!({
        "outbounds": [
            {"tag": "portal", "protocol": "vless", "settings": {
                "address": "127.0.0.1", "port": portal.addr().port(), "id": ID,
                "encryption": "none", "reverse": {"tag": TAG}}},
            {"tag": "direct", "protocol": "freedom", "settings": allow(&[allowed])},
            {"tag": "plain", "protocol": "freedom"}
        ],
        "routing": {"rules": [
            {"inboundTag": [TAG], "port": plain.port().to_string(), "outboundTag": "plain"},
            {"inboundTag": [TAG], "outboundTag": "direct"}
        ]}
    }))
    .await;
    let mut tunnel = portal.accept(TUNNEL_WAIT).await.expect("a tunnel");
    tunnel.open_control().await;
    tunnel
        .open(2, &tcp(other), "198.51.100.7:40000", b"knock")
        .await;
    tunnel
        .open(3, &tcp(plain), "198.51.100.7:40001", b"knock")
        .await;
    tunnel
        .open(4, &tcp(allowed), "198.51.100.7:40002", b"open")
        .await;
    // Only the allowed service answers; the others are held, not dialed.
    let (id, status, _, _, payload) = tunnel.next(Duration::from_secs(5)).await.unwrap();
    assert_eq!(
        (id, status, payload.as_slice()),
        (4, Status::Keep, &b"open"[..])
    );
    assert!(tunnel.next(Duration::from_secs(1)).await.is_none());
    assert_eq!(other_accepted.load(Ordering::SeqCst), 0);
    assert_eq!(plain_accepted.load(Ordering::SeqCst), 0);
    // UDP too: the datagram is dropped, not sent.
    let refused = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let refused_addr = refused.local_addr().unwrap();
    tunnel
        .open(5, &udp(refused_addr), "198.51.100.7:40003", b"knock")
        .await;
    let mut buffer = [0; 64];
    assert!(
        timeout(Duration::from_secs(1), refused.recv_from(&mut buffer))
            .await
            .is_err()
    );
    assert!(tunnel.next(Duration::from_millis(200)).await.is_none());
    core.stop().await.unwrap();
}

#[tokio::test]
async fn routing_sees_the_tag_the_portals_client_and_the_email() {
    let portal = Portal::start().await;
    let (service, _) = tcp_echo().await;
    let mut core = start(bridge_config(
        portal.addr(),
        allow(&[service]),
        json!([
            {"inboundTag": [TAG], "source": ["198.51.100.7"], "user": ["bridge@example.com"],
             "outboundTag": "direct"},
            {"inboundTag": [TAG], "outboundTag": "block"}
        ]),
    ))
    .await;
    let mut tunnel = portal.accept(TUNNEL_WAIT).await.expect("a tunnel");
    tunnel.open_control().await;
    tunnel
        .open(2, &tcp(service), "198.51.100.8:40000", b"stranger")
        .await;
    // The blackhole closes at once, with nothing sent back.
    let (id, status, error, _, _) = tunnel.next(Duration::from_secs(5)).await.unwrap();
    assert_eq!((id, status, error), (2, Status::End, false));
    tunnel
        .open(3, &tcp(service), "198.51.100.7:40000", b"friend")
        .await;
    let (id, status, _, _, payload) = tunnel.next(Duration::from_secs(5)).await.unwrap();
    assert_eq!(
        (id, status, payload.as_slice()),
        (3, Status::Keep, &b"friend"[..])
    );
    core.stop().await.unwrap();
}

#[tokio::test]
async fn a_drained_tunnel_is_replaced_and_finishes_its_sessions() {
    let portal = Portal::start().await;
    let (service, _) = tcp_echo().await;
    let mut core = start(bridge_config(
        portal.addr(),
        allow(&[service]),
        json!([{"inboundTag": [TAG], "outboundTag": "direct"}]),
    ))
    .await;
    let mut first = portal.accept(TUNNEL_WAIT).await.expect("a tunnel");
    first.open_control().await;
    first
        .open(2, &tcp(service), "198.51.100.7:40000", b"a")
        .await;
    assert!(first.next(Duration::from_secs(5)).await.is_some());
    // No second tunnel while the first is active and lightly used.
    assert!(portal.accept(Duration::from_secs(3)).await.is_none());

    first.control(ControlState::Drain).await;
    first.send(&frame(1, Status::End, None, None, None)).await;
    let mut second = portal.accept(TUNNEL_WAIT).await.expect("a second tunnel");
    second.open_control().await;
    // The drained tunnel still carries its session.
    first
        .send(&frame(2, Status::Keep, None, None, Some(b"still here")))
        .await;
    let (id, _, _, _, payload) = first.next(Duration::from_secs(5)).await.unwrap();
    assert_eq!((id, payload.as_slice()), (2, &b"still here"[..]));
    second
        .open(2, &tcp(service), "198.51.100.7:40001", b"b")
        .await;
    let (id, _, _, _, payload) = second.next(Duration::from_secs(5)).await.unwrap();
    assert_eq!((id, payload.as_slice()), (2, &b"b"[..]));
    core.stop().await.unwrap();
}

#[tokio::test]
async fn a_lost_tunnel_is_replaced() {
    let portal = Portal::start().await;
    let (service, _) = tcp_echo().await;
    let mut core = start(bridge_config(
        portal.addr(),
        allow(&[service]),
        json!([{"inboundTag": [TAG], "outboundTag": "direct"}]),
    ))
    .await;
    let first = portal.accept(TUNNEL_WAIT).await.expect("a tunnel");
    drop(first);
    let mut second = portal.accept(TUNNEL_WAIT).await.expect("a new tunnel");
    second.open_control().await;
    second
        .open(2, &tcp(service), "198.51.100.7:40000", b"back")
        .await;
    let (_, _, _, _, payload) = second.next(Duration::from_secs(5)).await.unwrap();
    assert_eq!(payload, b"back");
    core.stop().await.unwrap();
}

#[tokio::test]
async fn a_bridge_alone_starts_and_a_core_without_inbound_or_bridge_does_not() {
    let config = |reverse: Value| {
        json!({"outbounds": [{"protocol": "vless", "settings": {
            "address": "127.0.0.1", "port": 9, "id": ID, "encryption": "none",
            "reverse": reverse}}]})
    };
    let parsed = xray_config::parse_xray_json(&config(json!({"tag": TAG})).to_string())
        .unwrap()
        .config;
    let mut core = Core::new(parsed).unwrap();
    core.start().await.unwrap();
    core.stop().await.unwrap();

    let parsed = xray_config::parse_xray_json(&config(Value::Null).to_string())
        .unwrap()
        .config;
    let mut core = Core::new(parsed).unwrap();
    assert!(core.start().await.is_err());
}
