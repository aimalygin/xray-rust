//! Isolated adoption probe, built inside checksum-pinned GotaTun sources.
//! No system TUN, routes, production dependency or custom WireGuard crypto.
use base64::{Engine, engine::general_purpose::STANDARD};
use gotatun::{
    device::{DeviceBuilder, DeviceLimits, Peer},
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
    x25519::{PublicKey, StaticSecret},
};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{sleep, timeout},
};

const MTU: usize = 1420;
const WAIT: Duration = Duration::from_secs(5);
#[derive(Default)]
struct Probe {
    binds: AtomicUsize,
    sent: AtomicUsize,
    reject: AtomicBool,
    socket: Mutex<Weak<UdpSocket>>,
    last_data: Mutex<Vec<u8>>,
}
struct Factory(Arc<Probe>);
#[derive(Clone)]
struct Udp(Arc<UdpSocket>, Arc<Probe>);
impl UdpTransportFactory for Factory {
    type Send = Udp;
    type Recv = Udp;
    async fn bind(&mut self, params: &UdpTransportFactoryParams) -> io::Result<(Udp, Udp)> {
        assert_eq!(params.port, 0);
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        // The real adapter will call the embedding SocketProtector here, while
        // the socket is owned and before Tokio registration or any I/O.
        self.0.binds.fetch_add(1, Ordering::SeqCst);
        if self.0.reject.load(Ordering::SeqCst) {
            return Err(io::Error::other("synthetic protector rejection"));
        }
        socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        *self.0.socket.lock().unwrap() = Arc::downgrade(&socket);
        let udp = Udp(socket, self.0.clone());
        Ok((udp.clone(), udp))
    }
}
impl UdpSend for Udp {
    type SendManyBuf = ();
    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        assert!(packet.len() <= MTU + 80);
        if packet.first() == Some(&4) && packet.len() > 32 {
            *self.1.last_data.lock().unwrap() = packet.to_vec();
        }
        let sent = self.0.send_to(&packet, destination).await?;
        if sent != packet.len() {
            return Err(io::Error::other("short UDP write"));
        }
        self.1.sent.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
impl UdpRecv for Udp {
    type RecvManyBuf = ();
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        loop {
            let mut packet = pool.get();
            let (n, source) = self.0.recv_from(&mut packet).await?;
            if n > MTU + 80 {
                continue;
            }
            packet.truncate(n);
            return Ok((packet, source));
        }
    }
}
struct IpTx(mpsc::Sender<Packet<Ip>>);
struct IpRx(mpsc::Receiver<Packet<Ip>>);
impl IpSend for IpTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.0
            .send(packet)
            .await
            .map_err(|_| io::Error::other("IP sink closed"))
    }
}
impl IpRecv for IpRx {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self
            .0
            .recv()
            .await
            .ok_or_else(|| io::Error::other("IP source closed"))?;
        Ok(std::iter::once(packet))
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(MTU as u16)
    }
}
fn ip_pair() -> (
    IpTx,
    IpRx,
    mpsc::Sender<Packet<Ip>>,
    mpsc::Receiver<Packet<Ip>>,
) {
    let (input, rx) = mpsc::channel(8);
    let (tx, output) = mpsc::channel(8);
    (IpTx(tx), IpRx(rx), input, output)
}

struct Reference {
    child: Child,
    directory: PathBuf,
    address: SocketAddr,
}
impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "{}",
                std::fs::read_to_string(self.directory.join("log")).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Reference {
    async fn start(server_secret: &StaticSecret, client_public: &PublicKey) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "xray-wg-probe-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = reservation.local_addr().unwrap();
        // All keys are synthetic public test vectors. Xray gVisor rejects inner
        // loopback destinations, so use a documentation IP and redirect to the
        // local echo server. No packet is sent to the documentation address.
        let config = format!(
            r#"{{"log":{{"loglevel":"debug"}},"inbounds":[{{"listen":"127.0.0.1","port":{},"protocol":"wireguard","settings":{{"secretKey":"{}","address":["10.44.0.1/32"],"mtu":1420,"peers":[{{"publicKey":"{}","allowedIPs":["10.44.0.2/32"]}}]}}}}],"outbounds":[{{"protocol":"freedom","settings":{{"redirect":"127.0.0.1:0","finalRules":[{{"action":"allow","ip":["127.0.0.0/8"]}}]}}}}]}}"#,
            address.port(),
            STANDARD.encode(server_secret.to_bytes()),
            STANDARD.encode(client_public.as_bytes())
        );
        std::fs::write(directory.join("config.json"), config).unwrap();
        drop(reservation);
        let log = std::fs::File::create(directory.join("log")).unwrap();
        let child = Command::new(
            std::env::var_os("XRAY_WIREGUARD_BINARY")
                .expect("run scripts/check-wireguard-adapter-prototype.sh"),
        )
        .arg("run")
        .arg("-config")
        .arg(directory.join("config.json"))
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
        let mut reference = Self {
            child,
            directory,
            address,
        };
        timeout(WAIT, async {
            loop {
                assert!(
                    reference.child.try_wait().unwrap().is_none(),
                    "reference exited"
                );
                if std::fs::read_to_string(reference.directory.join("log"))
                    .unwrap()
                    .contains("core: Xray 26.7.28 started")
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        reference
    }
}
fn packet(source: [u8; 4], port: u16, payload: &[u8]) -> Packet<Ip> {
    assert!(payload.len() + 28 <= MTU);
    let mut raw = vec![0; 28 + payload.len()];
    raw[0] = 0x45;
    raw[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    raw[8] = 64;
    raw[9] = 17;
    raw[12..16].copy_from_slice(&source);
    raw[16..20].copy_from_slice(&[198, 51, 100, 7]);
    let mut sum = raw[..20]
        .chunks_exact(2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as u32)
        .sum::<u32>();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    raw[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    raw[20..22].copy_from_slice(&49155_u16.to_be_bytes());
    raw[22..24].copy_from_slice(&port.to_be_bytes());
    raw[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    raw[28..].copy_from_slice(payload);
    Packet::copy_from(raw.as_slice()).try_into_ip().unwrap()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    timeout(Duration::from_secs(45), run())
        .await
        .expect("prototype deadline");
}
async fn run() {
    let secret = StaticSecret::from([0x42; 32]);
    let public = PublicKey::from(&secret);
    let server_secret = StaticSecret::from([0x53; 32]);
    let server_public = PublicKey::from(&server_secret);
    let reference = Reference::start(&server_secret, &public).await;
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let echo_count = Arc::new(AtomicUsize::new(0));
    let observed = echo_count.clone();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0; 2048];
        loop {
            let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
            echo.send_to(&buf[..n], peer).await.unwrap();
        }
    });
    let peer = Peer::new(server_public)
        .with_endpoint(reference.address)
        .with_allowed_ip("0.0.0.0/0".parse().unwrap());
    let probe = Arc::new(Probe::default());
    let (tx, rx, input, mut output) = ip_pair();
    let device = DeviceBuilder::new()
        .with_limits(DeviceLimits::mobile())
        .with_udp(Factory(probe.clone()))
        .with_ip_pair(tx, rx)
        .with_private_key(secret)
        .with_peers([peer.clone()])
        .build()
        .await
        .unwrap();
    assert_eq!(probe.binds.load(Ordering::SeqCst), 1);
    for payload in [b"wireguard adapter probe".to_vec(), vec![0xa5; 1392]] {
        input
            .send(packet([10, 44, 0, 2], echo_port, &payload))
            .await
            .unwrap();
        let reply = timeout(WAIT, output.recv())
            .await
            .unwrap()
            .unwrap()
            .into_bytes();
        assert_eq!(&reply[12..16], &[198, 51, 100, 7]);
        assert_eq!(&reply[16..20], &[10, 44, 0, 2]);
        assert_eq!(&reply[28..], payload);
    }
    // A replayed authenticated data message must never produce a second echo.
    let encrypted = probe.last_data.lock().unwrap().clone();
    let socket = probe.socket.lock().unwrap().upgrade().unwrap();
    socket.send_to(&encrypted, reference.address).await.unwrap();
    drop(socket);
    assert!(
        timeout(Duration::from_millis(150), output.recv())
            .await
            .is_err()
    );
    assert_eq!(echo_count.load(Ordering::SeqCst), 2);
    // Correct encryption key does not authorize another inner source address.
    input
        .send(packet([10, 44, 0, 99], echo_port, b"spoofed source"))
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(150), output.recv())
            .await
            .is_err()
    );
    assert_eq!(echo_count.load(Ordering::SeqCst), 2);
    // Leave the application receive queue undrained while flooding the real
    // encrypted path. Packet admission must plateau and recover after draining.
    let stalled = timeout(Duration::from_secs(2), async {
        for _ in 0..10_000 {
            input
                .send(packet([10, 44, 0, 2], echo_port, &[0xa5; 1392]))
                .await
                .unwrap();
        }
    })
    .await
    .is_err();
    let pressure = device.memory_snapshot().await.unwrap();
    assert!(pressure.peak_reservations <= 64, "{pressure:?}");
    assert!(
        stalled || pressure.admission_drops > 0,
        "flood must exercise queue or admission pressure: {pressure:?}"
    );
    timeout(WAIT, async {
        loop {
            // Do not wait for input capacity while the output queue needs draining.
            let _ = input.try_send(packet([10, 44, 0, 2], echo_port, b"after pressure"));
            let until = tokio::time::Instant::now() + Duration::from_millis(100);
            while let Ok(Some(reply)) = tokio::time::timeout_at(until, output.recv()).await {
                if &reply.into_bytes()[28..] == b"after pressure" {
                    return;
                }
            }
        }
    })
    .await
    .expect("encrypted tunnel recovers after backpressure");
    println!("WireGuard pressure counters: {pressure:?}");
    device.suspend().await;
    let sent = probe.sent.load(Ordering::SeqCst);
    sleep(Duration::from_millis(30)).await;
    assert_eq!(probe.sent.load(Ordering::SeqCst), sent);
    // The app may still hold admitted replies; drain those before checking zero.
    while output.try_recv().is_ok() {}
    timeout(WAIT, async {
        while device.memory_snapshot().await.unwrap().reservations != 0 {
            while output.try_recv().is_ok() {}
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("suspend releases packet storage");
    device.resume().await.unwrap();
    assert_eq!(
        probe.binds.load(Ordering::SeqCst),
        2,
        "resume must reapply protection"
    );
    input
        .send(packet([10, 44, 0, 2], echo_port, b"after resume"))
        .await
        .unwrap();
    let reply = timeout(WAIT, output.recv())
        .await
        .unwrap()
        .unwrap()
        .into_bytes();
    assert_eq!(&reply[28..], b"after resume");
    drop(reply);
    device.stop().await;
    timeout(WAIT, async {
        while probe.socket.lock().unwrap().upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let rejection = Arc::new(Probe::default());
    rejection.reject.store(true, Ordering::SeqCst);
    let (tx, rx, _input, _output) = ip_pair();
    let refused = DeviceBuilder::new()
        .with_limits(DeviceLimits::mobile())
        .with_udp(Factory(rejection.clone()))
        .with_ip_pair(tx, rx)
        .with_private_key(StaticSecret::from([0x42; 32]))
        .with_peers([peer])
        .build()
        .await;
    assert!(refused.is_err());
    assert_eq!(rejection.sent.load(Ordering::SeqCst), 0);
    assert_eq!(rejection.binds.load(Ordering::SeqCst), 1);
    echo_task.abort();
    let _ = echo_task.await;
    println!(
        "PASS: pinned Xray WireGuard IPv4 UDP/MTU, replay, source authorization, bounded memory under pressure, recovery, suspend/resume, socket release and protector rejection"
    );
    println!(
        "Prototype only: bounded packet admission is opt-in; this is not a process RSS ceiling or a registered core outbound."
    );
}
