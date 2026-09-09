#![allow(dead_code)]
#[path = "../../../xray-transport/tests/hysteria/support.rs"]
mod server;
use async_trait::async_trait;
use serde_json::{json, Value};
pub use server::{Task, XrayServer, AUTH, DEADLINE};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use xray_core_rs::Core;
use xray_transport::{DnsResolver, SocketHandle, SocketProtector, TransportDialer, TransportError};

pub fn profile(address: SocketAddr) -> Value {
    let mut config: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/configs/hysteria2.json"
    ))
    .unwrap();
    config["inbounds"] = json!([
        {"tag":"socks-in", "protocol":"socks", "listen":"127.0.0.1", "port":0,"settings":{"auth":"noauth","udp":true}},
        {"tag":"http-in", "protocol":"http", "listen":"127.0.0.1", "port":0},
        {"tag":"tun-in", "protocol":"tun"}
    ]);
    config["outbounds"][0]["settings"]["address"] = json!("bootstrap.example");
    config["outbounds"][0]["settings"]["port"] = json!(address.port());
    config["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"] = json!("localhost");
    config["outbounds"][0]["streamSettings"]["hysteriaSettings"]["auth"] = json!(AUTH);
    config
}

#[derive(Default)]
pub struct Protector(pub AtomicUsize);
impl SocketProtector for Protector {
    fn protect(&self, _socket: SocketHandle) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Default)]
pub struct Bootstrap(pub AtomicUsize);
#[async_trait]
impl DnsResolver for Bootstrap {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        assert_eq!(
            domain, "bootstrap.example",
            "destination DNS must stay on the Hysteria server"
        );
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    }
}

pub fn core(server: &XrayServer) -> (Core, Arc<Protector>, Arc<Bootstrap>, Arc<TransportDialer>) {
    let protector = Arc::new(Protector::default());
    let bootstrap = Arc::new(Bootstrap::default());
    let dialer = Arc::new(
        TransportDialer::with_tls_connector(server.connector.clone())
            .with_socket_protector(protector.clone()),
    );
    let config = xray_config::parse_xray_json(&profile(server.address).to_string())
        .unwrap()
        .config;
    (
        Core::with_runtime_dependencies(config, bootstrap.clone(), dialer.clone()).unwrap(),
        protector,
        bootstrap,
        dialer,
    )
}

pub async fn tcp_echo() -> (SocketAddr, Task) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = Task(tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (socket, _) = accepted.unwrap();
                    connections.spawn(async move {
                        let (mut read, mut write) = socket.into_split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                },
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }));
    (address, task)
}

pub async fn udp_echo() -> (SocketAddr, Task) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = Task(tokio::spawn(async move {
        let mut buffer = [0; 8192];
        loop {
            let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(&buffer[..n], peer).await.unwrap();
        }
    }));
    (address, task)
}

pub async fn socks(
    proxy: SocketAddr,
    command: u8,
    domain: &str,
    port: u16,
) -> (TcpStream, SocketAddr) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut hello = [0; 2];
    stream.read_exact(&mut hello).await.unwrap();
    assert_eq!(hello, [5, 0]);
    let mut request = vec![5, command, 0, 3, domain.len() as u8];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut response = [0; 10];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..4], &[5, 0, 0, 1]);
    let address = SocketAddr::from((
        [response[4], response[5], response[6], response[7]],
        u16::from_be_bytes([response[8], response[9]]),
    ));
    (stream, address)
}

pub async fn echo(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    let mut received = vec![0; payload.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);
}
