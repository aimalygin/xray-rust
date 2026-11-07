//! The `socks` and `http` outbounds over every transport and its security,
//! against Xray-core's own SOCKS and HTTP inbounds behind the same transport.
//!
//! Xray-core's SOCKS server answers `UDP ASSOCIATE` with a relay on plain UDP
//! beside the transport and admits only datagrams from the control
//! connection's source IP, so the UDP half of each SOCKS case also checks that
//! the relay socket and the control connection agree on it. Its HTTP server
//! reads HTTP/1.1 only, which every one of these transports carries.
use super::xhttp_download::json_process;
use super::*;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use xray_proxy::inbound::{encode_socks5_udp_datagram, parse_socks5_udp_datagram};
use xray_routing::{Network as RouteNetwork, Target, TargetAddr as RouteAddr};
use xray_transport::{SocketHandle, SocketProtector};

const SERVER: &str = "proxy-carrier.test";
pub(super) const USER: &str = "synthetic-proxy-carrier-user";
pub(super) const PASS: &str = "synthetic-proxy-carrier-pass";
const REALITY_NAME: &str = "encryption-oracle.test";

struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Default)]
struct Protected(AtomicUsize);
impl SocketProtector for Protected {
    fn protect(&self, _: SocketHandle) -> std::io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Resolves the outbound's server name and nothing else.
struct Resolver;
#[async_trait::async_trait]
impl DnsResolver for Resolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        assert_eq!(domain, SERVER);
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    }
}

/// `protocol` is `socks` or `http`, with an account either way.
pub(super) fn proxy_inbound(config: &mut Value, protocol: &str) {
    config["log"]["loglevel"] = "debug".into();
    if config["inbounds"][0]["streamSettings"]["security"] == "reality" {
        config["inbounds"][0]["streamSettings"]["realitySettings"]["show"] = false.into();
    }
    config["inbounds"][0]["protocol"] = protocol.into();
    config["inbounds"][0]["settings"] = match protocol {
        "socks" => json!({"auth":"password","udp":true,"accounts":[{"user":USER,"pass":PASS}]}),
        _ => json!({"accounts":[{"user":USER,"pass":PASS}]}),
    };
}

fn profile(protocol: &str, port: u16, stream: &Value) -> Value {
    json!({
        "inbounds":[{"tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":0,
            "settings":{"udp":true}}],
        "outbounds":[{"tag":"proxy","protocol":protocol,
            "settings":{"address":SERVER,"port":port,"user":USER,"pass":PASS},
            "streamSettings":stream}]
    })
}

/// A no-auth request to the core's own SOCKS inbound; returns the stream and
/// the bound address of the reply.
async fn socks(
    proxy: SocketAddr,
    command: u8,
    destination: SocketAddr,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, command, 0, 1, 127, 0, 0, 1];
    request.extend(destination.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await?;
    if reply[..4] != [5, 0, 0, 1] {
        return Err(std::io::Error::other("SOCKS request rejected"));
    }
    Ok((
        stream,
        SocketAddr::from((
            [reply[4], reply[5], reply[6], reply[7]],
            u16::from_be_bytes([reply[8], reply[9]]),
        )),
    ))
}

/// The `pinnedPeerCertSha256` of the server's generated certificate, so the
/// outbound dials through the shaped TLS path a profile takes.
pub(super) fn certificate_pin(server: &XrayServer) -> String {
    let pem = fs::read_to_string(server._temp_dir.path.join("server.crt.pem")).unwrap();
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One server-first TCP flow with a 128 KiB echo, then, with `datagram`, one
/// UDP association echoing three sizes.
async fn exercise(config: Value, datagram: bool) -> std::io::Result<()> {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = tcp.local_addr()?;
    let payload: Vec<u8> = (0..131_077).map(|n| (n * 197 + 31) as u8).collect();
    let _echo = Task(tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        stream.write_all(b"greeting").await.unwrap();
        let (mut reader, mut writer) = stream.split();
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
    }));
    let protector = Arc::new(Protected::default());
    let dialer = TransportDialer::system_with_socket_protector(Some(protector.clone())).unwrap();
    let mut core = Core::with_runtime_dependencies(
        parse_xray_json(&config.to_string()).unwrap().config,
        Arc::new(Resolver),
        Arc::new(dialer),
    )
    .unwrap();
    core.start().await.unwrap();
    let result = async {
        let proxy = core.inbound_addr(Some("socks-in")).unwrap();
        let (mut stream, _) = socks(proxy, 1, address).await?;
        let mut greeting = [0; 8];
        stream.read_exact(&mut greeting).await?;
        assert_eq!(&greeting, b"greeting");
        let (mut reader, mut writer) = stream.split();
        let mut response = vec![0; payload.len()];
        tokio::try_join!(
            async {
                writer.write_all(&payload).await?;
                writer.flush().await
            },
            async { reader.read_exact(&mut response).await.map(|_| ()) }
        )?;
        assert_eq!(response, payload);
        if datagram {
            let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let target = Target::new(
                RouteAddr::Ip(Ipv4Addr::LOCALHOST.into()),
                echo.local_addr()?.port(),
                RouteNetwork::Udp,
            );
            let _udp = Task(tokio::spawn(async move {
                let mut bytes = [0; 8192];
                loop {
                    let (n, peer) = echo.recv_from(&mut bytes).await.unwrap();
                    echo.send_to(&bytes[..n], peer).await.unwrap();
                }
            }));
            let (_control, relay) =
                socks(proxy, 3, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            for size in [1, 1200, 4096] {
                let bytes = vec![0x5a; size];
                udp.send_to(&encode_socks5_udp_datagram(&target, &bytes).unwrap(), relay)
                    .await?;
                let mut response = [0; 8192];
                let n = udp.recv(&mut response).await?;
                let packet = parse_socks5_udp_datagram(&response[..n]).unwrap();
                assert_eq!(packet.target, target);
                assert_eq!(packet.payload.as_ref(), bytes);
            }
        }
        assert!(protector.0.load(Ordering::SeqCst) > 0);
        Ok(())
    }
    .await;
    core.stop().await.unwrap();
    assert!(core.connection_snapshot().connections.is_empty());
    result
}

#[tokio::test]
#[ignore = "requires local pinned oracles; run check-v08-carrier-interop.sh"]
async fn socks_carrier_every_transport_and_security_tcp_and_udp() {
    every_transport_and_security("socks", true).await;
}

#[tokio::test]
#[ignore = "requires local pinned oracles; run check-v08-carrier-interop.sh"]
async fn http_carrier_every_transport_and_security_tcp() {
    every_transport_and_security("http", false).await;
}

/// Runs `protocol`'s outbound against its inbound over each transport and
/// security, with a UDP association too when `datagram`.
async fn every_transport_and_security(protocol: &str, datagram: bool) {
    let checkout = resolve_xray_checkout();
    let origin_binary = env::var_os("XRAY_VLESS_ENCRYPTION_ORACLE").unwrap();
    let (_origin, origin) = json_process(&origin_binary, &["origin"]);
    let xhttp = |path: &str, mode: &str| {
        json!({"path":path,"mode":mode,"xPaddingBytes":64,"scMaxEachPostBytes":4096,
            "scMinPostsIntervalMs":1,"xmux":{"maxConnections":1}})
    };
    let cases = [
        (
            XrayInboundSecurity::None,
            XrayInboundTransport::WebSocket { path: "/proxy-ws" },
            json!({"network":"ws","wsSettings":{"path":"/proxy-ws"}}),
        ),
        (
            XrayInboundSecurity::None,
            XrayInboundTransport::HttpUpgrade { path: "/proxy-hu" },
            json!({"network":"httpupgrade","httpupgradeSettings":{"path":"/proxy-hu"}}),
        ),
        (
            XrayInboundSecurity::None,
            XrayInboundTransport::Grpc {
                service_name: "proxy",
            },
            json!({"network":"grpc","grpcSettings":{"serviceName":"proxy"}}),
        ),
        (
            XrayInboundSecurity::None,
            XrayInboundTransport::Xhttp {
                path: "/proxy-x/",
                mode: "auto",
                tls_alpn: None,
            },
            json!({"network":"xhttp","xhttpSettings":xhttp("/proxy-x/","packet-up")}),
        ),
        (
            XrayInboundSecurity::Tls,
            XrayInboundTransport::WebSocket { path: "/proxy-ws" },
            json!({"network":"ws","security":"tls","tlsSettings":{"serverName":TLS_SERVER_NAME},
                "wsSettings":{"path":"/proxy-ws"}}),
        ),
        (
            XrayInboundSecurity::Tls,
            XrayInboundTransport::HttpUpgrade { path: "/proxy-hu" },
            json!({"network":"httpupgrade","security":"tls","tlsSettings":{"serverName":TLS_SERVER_NAME},
                "httpupgradeSettings":{"path":"/proxy-hu"}}),
        ),
        (
            XrayInboundSecurity::Tls,
            XrayInboundTransport::Grpc {
                service_name: "proxy",
            },
            json!({"network":"grpc","security":"tls","tlsSettings":{"serverName":TLS_SERVER_NAME},
                "grpcSettings":{"serviceName":"proxy"}}),
        ),
        (
            XrayInboundSecurity::Tls,
            XrayInboundTransport::Xhttp {
                path: "/proxy-x/",
                mode: "auto",
                tls_alpn: Some("h2"),
            },
            json!({"network":"xhttp","security":"tls",
                "tlsSettings":{"serverName":TLS_SERVER_NAME,"alpn":["h2"]},
                "xhttpSettings":xhttp("/proxy-x/","stream-up")}),
        ),
        (
            XrayInboundSecurity::Reality,
            XrayInboundTransport::Raw,
            json!({"network":"raw"}),
        ),
        (
            XrayInboundSecurity::Reality,
            XrayInboundTransport::Grpc {
                service_name: "proxy",
            },
            json!({"network":"grpc","grpcSettings":{"serviceName":"proxy"}}),
        ),
        (
            XrayInboundSecurity::Reality,
            XrayInboundTransport::Xhttp {
                path: "/proxy-x/",
                mode: "auto",
                tls_alpn: None,
            },
            json!({"network":"xhttp","xhttpSettings":xhttp("/proxy-x/","stream-one")}),
        ),
    ];
    for (security, transport, mut stream) in cases {
        let reality = security == XrayInboundSecurity::Reality;
        let server = start_xray_vless_server_customized(
            &checkout,
            XrayVlessServerConfig {
                security,
                transport,
                flow: None,
            },
            |config| {
                proxy_inbound(config, protocol);
                if reality {
                    let settings = &mut config["inbounds"][0]["streamSettings"]["realitySettings"];
                    settings["dest"] = origin["address"].clone();
                    settings["serverNames"] = json!([REALITY_NAME]);
                }
            },
        )
        .await;
        if security == XrayInboundSecurity::Tls {
            stream["tlsSettings"]["pinnedPeerCertSha256"] = certificate_pin(&server).into();
        }
        if reality {
            stream["security"] = "reality".into();
            stream["realitySettings"] = json!({"serverName":REALITY_NAME,"fingerprint":"chrome",
                "publicKey":REALITY_PUBLIC_KEY_BASE64,"shortId":REALITY_SHORT_ID_HEX});
            // The pinned server's fresh cover-origin detector may consume its
            // first connection, so one bounded warmup comes first.
            let _ = timeout(
                Duration::from_secs(30),
                exercise(profile(protocol, server.addr.port(), &stream), false),
            )
            .await;
        }
        eprintln!("{protocol} over {stream}");
        let result = timeout(
            Duration::from_secs(30),
            exercise(profile(protocol, server.addr.port(), &stream), datagram),
        )
        .await;
        assert!(
            matches!(result, Ok(Ok(()))),
            "{stream}: {result:?}; {}",
            server.logs()
        );
    }
}
