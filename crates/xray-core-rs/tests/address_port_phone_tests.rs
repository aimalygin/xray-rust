//! `sockopt.addressPortStrategy` as a phone runs it, from a client's flow to
//! the proxy server. Android, iOS and tvOS have no `/etc/resolv.conf`, so the
//! lookup asks the core's `dns.servers`; a desktop runs that path here through
//! the dialer's test hook. The parts are real: a started core, its SOCKS
//! inbound and outbound, a UDP DNS server and a TCP proxy server.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use xray_config::parse_xray_json;
use xray_core_rs::{Core, TunRuntimeOptions};
use xray_transport::TransportDialer;

/// The outbound's configured server: a name nothing resolves, on a port
/// nothing serves, so a flow only opens through the server the record names.
const SERVER_NAME: &str = "proxy.phone.test";
const TYPE_TXT: u16 = 16;

type Questions = Arc<Mutex<Vec<(String, u16)>>>;

/// A UDP DNS server that answers the TXT question for [`SERVER_NAME`] with
/// `record` and every other question with NXDOMAIN, and remembers them all.
async fn dns_server(record: String) -> (SocketAddr, Questions) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let asked = Questions::default();
    let seen = Arc::clone(&asked);
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let query = &buffer[..length];
            let Some((name, qtype, question_end)) = question(query) else {
                continue;
            };
            let answers = name == SERVER_NAME && qtype == TYPE_TXT;
            seen.lock().unwrap().push((name, qtype));
            let mut response = Vec::with_capacity(length + 64);
            response.extend_from_slice(&query[..2]);
            response.extend_from_slice(&[0x81, if answers { 0x80 } else { 0x83 }]);
            response.extend_from_slice(&[0, 1, 0, u8::from(answers), 0, 0, 0, 0]);
            response.extend_from_slice(&query[12..question_end]);
            if answers {
                // The question's name again, TXT, IN, 60 seconds, one string.
                response.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60]);
                response.extend_from_slice(&(record.len() as u16 + 1).to_be_bytes());
                response.push(record.len() as u8);
                response.extend_from_slice(record.as_bytes());
            }
            let _ = socket.send_to(&response, peer).await;
        }
    });
    (address, asked)
}

/// The name and type of a query's question, and where the question ends.
fn question(query: &[u8]) -> Option<(String, u16, usize)> {
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*query.get(offset)?);
        offset += 1;
        if length == 0 {
            break;
        }
        let label = query.get(offset..offset + length)?;
        labels.push(std::str::from_utf8(label).ok()?.to_owned());
        offset += length;
    }
    let qtype = u16::from_be_bytes([*query.get(offset)?, *query.get(offset + 1)?]);
    query.get(offset + 3)?;
    Some((labels.join("."), qtype, offset + 4))
}

/// A SOCKS5 server that accepts every CONNECT and echoes what follows it.
/// Counts the connections it took.
async fn proxy_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = serve_proxy(&mut stream).await;
            });
        }
    });
    (address, connections)
}

async fn serve_proxy(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let mut methods = vec![0u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[5, 0]).await?;
    read_socks_address(stream).await?;
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        stream.write_all(&buffer[..read]).await?;
    }
}

/// Reads a SOCKS5 request or reply through its address and port; returns
/// its second byte, the command or the reply code.
async fn read_socks_address(stream: &mut TcpStream) -> std::io::Result<u8> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let address = match head[3] {
        1 => 4,
        4 => 16,
        _ => usize::from(stream.read_u8().await?),
    };
    let mut rest = vec![0u8; address + 2];
    stream.read_exact(&mut rest).await?;
    Ok(head[1])
}

/// Opens a flow to `host:80` through the core's SOCKS inbound.
async fn connect_through(inbound: SocketAddr, host: &str) -> TcpStream {
    let mut stream = TcpStream::connect(inbound).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&80u16.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let reply = read_socks_address(&mut stream).await.unwrap();
    assert_eq!(reply, 0, "the inbound opened the flow");
    stream
}

/// A phone has no `/etc/resolv.conf`. Its core asks `dns.servers` for the
/// TXT record of the outbound's server and dials the address the record
/// names, although that configuration routes the DNS module's own queries
/// into the very outbound being opened: asked through routing, the lookup
/// would wait for the outbound it is part of opening.
#[tokio::test]
async fn a_phone_dials_the_server_its_dns_servers_name() {
    timeout(Duration::from_secs(20), async {
        let (proxy, proxy_connections) = proxy_server().await;
        let (dns, asked) = dns_server(format!("127.0.0.1:{}", proxy.port())).await;
        let config = json!({
            "dns": {
                "tag": "dns",
                "servers": [{"address": dns.ip().to_string(), "port": dns.port()}]
            },
            "inbounds": [{
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 0,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": false}
            }],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "socks",
                "settings": {"servers": [{"address": SERVER_NAME, "port": 9}]},
                "streamSettings": {"sockopt": {"addressPortStrategy": "TxtPortAndAddress"}}
            }],
            "routing": {
                "rules": [{"type": "field", "inboundTag": ["dns"], "outboundTag": "proxy"}]
            }
        });
        let config = parse_xray_json(&config.to_string())
            .expect("the configuration parses")
            .config;
        let dialer = TransportDialer::system()
            .unwrap()
            .with_resolver_configuration("/nonexistent/xray-rust/resolv.conf", true);
        let mut core = Core::with_transport_dialer_and_tun_options(
            config,
            Arc::new(dialer),
            TunRuntimeOptions::default(),
        )
        .unwrap();
        core.start().await.unwrap();
        let inbound = core.inbound_addr(Some("socks-in")).unwrap();

        let mut stream = connect_through(inbound, "echo.test").await;
        let sent = b"through the server the record names";
        stream.write_all(sent).await.unwrap();
        let mut echoed = vec![0u8; sent.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, sent);

        assert_eq!(proxy_connections.load(Ordering::SeqCst), 1);
        let asked = asked.lock().unwrap().clone();
        assert_eq!(asked, [(SERVER_NAME.to_owned(), TYPE_TXT)]);

        drop(stream);
        core.stop().await.unwrap();
    })
    .await
    .expect("the flow opens through the named server in time");
}
