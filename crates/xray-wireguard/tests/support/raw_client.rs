//! Identical plaintext IP boundary for three independent child processes.
use bytes::BytesMut;
use serde_json::json;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket};
use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    net::UnixDatagram,
    time::{sleep, timeout},
};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct RawClient {
    child: Child,
    directory: PathBuf,
    pub socket: UnixDatagram,
}
impl RawClient {
    pub async fn start(engine: &str, endpoint: SocketAddr) -> Self {
        let directory = PathBuf::from(format!(
            "/tmp/xray-wg-raw-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let socket = UnixDatagram::bind(directory.join("host.sock")).unwrap();
        let (binary, args) = if engine == "wireguard-go" {
            let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let config = json!({
                "listen": reservation.local_addr().unwrap().to_string(),
                "privateKey": hex(&[0x42; 32]),
                "peerKey": hex(PublicKey::from(&StaticSecret::from([0x53; 32])).as_bytes()),
                "packetSocket": directory.join("engine.sock"),
                "packetClient": directory.join("host.sock"),
                "endpoint": endpoint.to_string(),
            });
            let path = directory.join("config.json");
            std::fs::write(&path, config.to_string()).unwrap();
            (
                std::env::var_os("NATIVE_WIREGUARD_BINARY").unwrap(),
                vec![path.into_os_string()],
            )
        } else {
            let variable = match engine {
                "gotatun-pristine" => "PRISTINE_GOTATUN_BINARY",
                "gotatun-patched" => "PATCHED_GOTATUN_BINARY",
                _ => panic!("unknown engine"),
            };
            (
                std::env::var_os(variable).expect("use check-wireguard-timeouts.py"),
                vec![
                    endpoint.to_string().into(),
                    directory.join("engine.sock").into_os_string(),
                    directory.join("host.sock").into_os_string(),
                ],
            )
        };
        let log = std::fs::File::create(directory.join("log")).unwrap();
        let child = Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut client = Self {
            child,
            directory,
            socket,
        };
        timeout(Duration::from_secs(5), async {
            loop {
                assert!(
                    client.child.try_wait().unwrap().is_none(),
                    "raw client exited"
                );
                if std::fs::read_to_string(client.directory.join("log"))
                    .unwrap()
                    .contains("ready")
                {
                    break;
                }
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        client
            .socket
            .connect(client.directory.join("engine.sock"))
            .unwrap();
        client
    }
    pub async fn send(&self, ipv6: bool, port: u16, payload: &[u8]) {
        let offset = if ipv6 { 40 } else { 20 };
        let mut bytes = BytesMut::zeroed(offset + 8 + payload.len());
        let (source, destination): (IpAddress, IpAddress) = if ipv6 {
            let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(6);
            ip.set_payload_len((8 + payload.len()) as u16);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_hop_limit(64);
            ip.set_src_addr("fd44::2".parse().unwrap());
            ip.set_dst_addr("2001:db8::7".parse().unwrap());
            (ip.src_addr().into(), ip.dst_addr().into())
        } else {
            let n = bytes.len();
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(4);
            ip.set_header_len(20);
            ip.set_total_len(n as u16);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_hop_limit(64);
            ip.set_src_addr("10.44.0.2".parse().unwrap());
            ip.set_dst_addr("198.51.100.7".parse().unwrap());
            ip.fill_checksum();
            (ip.src_addr().into(), ip.dst_addr().into())
        };
        let mut udp = UdpPacket::new_unchecked(&mut bytes[offset..]);
        udp.set_src_port(44444);
        udp.set_dst_port(port);
        udp.set_len((8 + payload.len()) as u16);
        udp.payload_mut().copy_from_slice(payload);
        udp.fill_checksum(&source, &destination);
        assert_eq!(self.socket.send(&bytes).await.unwrap(), bytes.len());
    }
    pub async fn receive(&self, ipv6: bool, port: u16) -> Vec<u8> {
        let mut buf = [0; 1421];
        let n = self.socket.recv(&mut buf).await.unwrap();
        assert!(n <= 1420);
        let payload = if ipv6 {
            let ip = Ipv6Packet::new_checked(&buf[..n]).unwrap();
            assert_eq!(ip.next_header(), IpProtocol::Udp);
            assert_eq!(
                ip.src_addr(),
                "2001:db8::7".parse::<std::net::Ipv6Addr>().unwrap()
            );
            assert_eq!(
                ip.dst_addr(),
                "fd44::2".parse::<std::net::Ipv6Addr>().unwrap()
            );
            ip.payload()
        } else {
            let ip = Ipv4Packet::new_checked(&buf[..n]).unwrap();
            assert!(ip.verify_checksum());
            assert_eq!(ip.next_header(), IpProtocol::Udp);
            assert_eq!(
                ip.src_addr(),
                "198.51.100.7".parse::<std::net::Ipv4Addr>().unwrap()
            );
            assert_eq!(
                ip.dst_addr(),
                "10.44.0.2".parse::<std::net::Ipv4Addr>().unwrap()
            );
            ip.payload()
        };
        let udp = UdpPacket::new_checked(payload).unwrap();
        assert_eq!(udp.src_port(), port);
        assert_eq!(udp.dst_port(), 44444);
        udp.payload().to_vec()
    }
}
impl Drop for RawClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "raw client log: {}",
                std::fs::read_to_string(self.directory.join("log")).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
