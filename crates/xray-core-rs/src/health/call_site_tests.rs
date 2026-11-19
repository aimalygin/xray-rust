//! The inbound call sites that report failed opens to the observatory: SOCKS
//! and HTTP `CONNECT` (`socks.rs`), HTTP forwarding (`http_forward.rs`), TUN
//! TCP and VLESS UDP (`tun.rs`), and the other TUN UDP outbounds
//! (`tun/datagram.rs`), each through a running core.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::tests::{parse, socks, socks_connect};
use crate::Core;

const TUN_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 2);
const TARGET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const VLESS_ID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";

/// A core whose SOCKS, HTTP and TUN inbounds all go to the one outbound
/// `proxy`, with a one-second handshake policy. The test watches `proxy`'s
/// failures as an observatory would, and nothing consumes the reports.
struct Harness {
    core: Core,
    slot: usize,
    next_port: u16,
}

impl Harness {
    async fn start(outbound: Value) -> Self {
        let config = parse(&json!({
            "inbounds": [
                {"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
                    "settings": {"auth": "noauth", "udp": true}},
                {"tag": "http-in", "protocol": "http", "listen": "127.0.0.1", "port": 0},
                {"tag": "tun-in", "protocol": "tun"},
            ],
            "outbounds": [outbound],
            "policy": {"levels": {"0": {"handshake": 1}}},
        }));
        let mut core = Core::new(config).expect("build core");
        core.start().await.expect("start core");
        let proxy = core
            .outbound_router
            .graph()
            .node_for_tag("proxy")
            .expect("proxy outbound");
        let selection = core.outbound_router.selection();
        let slot = selection.leaf_index(proxy).expect("proxy is a leaf");
        selection.failure_reports().watch(slot, true);
        Self {
            core,
            slot,
            next_port: 40_000,
        }
    }

    fn reported(&self) -> bool {
        self.core
            .outbound_router
            .selection()
            .failure_reports()
            .is_pending(self.slot)
    }

    /// Waits for `path` to report `proxy`, and clears the report.
    async fn expect_report(&self, path: &str) {
        tokio::time::timeout(Duration::from_secs(4), async {
            while !self.reported() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{path} should report the failed open"));
        self.core
            .outbound_router
            .selection()
            .failure_reports()
            .clear(self.slot);
    }

    fn inbound(&self, tag: &str) -> SocketAddr {
        self.core.inbound_addr(Some(tag)).expect("inbound listens")
    }

    async fn socks_connect(&self) {
        assert_ne!(socks_connect(self.inbound("socks-in")).await, 0);
    }

    async fn http_connect(&self) {
        http_exchange(
            self.inbound("http-in"),
            "CONNECT 192.0.2.10:80 HTTP/1.1\r\nHost: 192.0.2.10:80\r\n\r\n",
        )
        .await;
    }

    async fn http_forward(&self) {
        http_exchange(
            self.inbound("http-in"),
            "GET http://192.0.2.10/ HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n",
        )
        .await;
    }

    fn port(&mut self) -> u16 {
        self.next_port += 1;
        self.next_port
    }

    async fn tun_tcp(&mut self) {
        let packet = tcp_syn(self.port());
        self.core
            .tun()
            .push_inbound(packet)
            .await
            .expect("TUN takes the SYN");
    }

    async fn tun_udp(&mut self) {
        let packet = udp(self.port(), b"synthetic");
        self.core
            .tun()
            .push_inbound(packet)
            .await
            .expect("TUN takes the datagram");
    }

    async fn stop(mut self) {
        self.core.stop().await.expect("stop core");
    }
}

/// Sends `request` and reads the answer, if any, to its end.
async fn http_exchange(inbound: SocketAddr, request: &str) {
    let mut client = TcpStream::connect(inbound)
        .await
        .expect("reach HTTP inbound");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(4), client.read_to_end(&mut answer)).await;
}

/// A port nothing listens on: every open through it is refused.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// A server that accepts connections and never answers, holding them open:
/// every open through it times out.
async fn silent_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    (port, server)
}

fn vless(port: u16) -> Value {
    json!({"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{
        "address": "127.0.0.1", "port": port, "users": [{"id": VLESS_ID}]}]}})
}

#[tokio::test]
async fn every_inbound_reports_an_open_its_server_refused() {
    let mut harness = Harness::start(socks("proxy", "127.0.0.1", closed_port().await)).await;
    harness.socks_connect().await;
    harness.expect_report("SOCKS CONNECT").await;
    harness.http_connect().await;
    harness.expect_report("HTTP CONNECT").await;
    harness.http_forward().await;
    harness.expect_report("HTTP forwarding").await;
    harness.tun_tcp().await;
    harness.expect_report("TUN TCP").await;
    harness.tun_udp().await;
    harness.expect_report("TUN UDP").await;
    harness.stop().await;

    let mut harness = Harness::start(vless(closed_port().await)).await;
    harness.tun_udp().await;
    harness.expect_report("TUN VLESS UDP").await;
    harness.stop().await;
}

#[tokio::test]
async fn every_inbound_reports_an_open_that_timed_out() {
    let (port, server) = silent_server().await;
    let mut harness = Harness::start(socks("proxy", "127.0.0.1", port)).await;
    harness.socks_connect().await;
    harness.expect_report("SOCKS CONNECT").await;
    harness.http_forward().await;
    harness.expect_report("HTTP forwarding").await;
    harness.tun_tcp().await;
    harness.expect_report("TUN TCP").await;
    harness.tun_udp().await;
    harness.expect_report("TUN UDP").await;
    harness.stop().await;
    server.abort();
}

/// The server answers and refuses the flow's target: that is the target's
/// failure, not the server's.
#[tokio::test]
async fn a_target_the_server_refuses_is_not_reported() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await?;
                stream.write_all(&[5, 0]).await?;
                let mut request = [0; 10];
                stream.read_exact(&mut request).await?;
                // REP 5: connection refused by the destination host.
                stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                stream.flush().await
            });
        }
    });
    let harness = Harness::start(socks("proxy", "127.0.0.1", port)).await;
    // The inbound reports before it answers its client.
    harness.socks_connect().await;
    assert!(!harness.reported());
    harness.stop().await;
    server.abort();
}

fn tcp_syn(source_port: u16) -> Bytes {
    let mut tcp = vec![0; 20];
    tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
    tcp[4..8].copy_from_slice(&1u32.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    ipv4(6, tcp, 16)
}

fn udp(source_port: u16, payload: &[u8]) -> Bytes {
    let mut udp = vec![0; 8];
    udp[0..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&5_000u16.to_be_bytes());
    udp[4..6].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
    udp.extend_from_slice(payload);
    ipv4(17, udp, 6)
}

/// `transport` from the TUN client to the target, with its checksum at
/// `checksum_at` filled in.
fn ipv4(protocol: u8, mut transport: Vec<u8>, checksum_at: usize) -> Bytes {
    let length = u16::try_from(transport.len()).expect("small packet");
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&TUN_CLIENT.octets());
    pseudo.extend_from_slice(&TARGET.octets());
    pseudo.extend_from_slice(&[0, protocol]);
    pseudo.extend_from_slice(&length.to_be_bytes());
    let mut sum = checksum(&[&pseudo, &transport]);
    if protocol == 17 && sum == 0 {
        sum = u16::MAX;
    }
    transport[checksum_at..checksum_at + 2].copy_from_slice(&sum.to_be_bytes());

    let mut header = [0; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&(20 + length).to_be_bytes());
    header[8] = 64;
    header[9] = protocol;
    header[12..16].copy_from_slice(&TUN_CLIENT.octets());
    header[16..20].copy_from_slice(&TARGET.octets());
    let sum = checksum(&[&header]);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    Bytes::from([header.as_slice(), &transport].concat())
}

/// The internet checksum of `chunks`, all but the last of even length.
fn checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for chunk in chunks {
        for pair in chunk.chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
