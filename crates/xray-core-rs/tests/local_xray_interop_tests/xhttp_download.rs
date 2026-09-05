use super::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::sync::Mutex;
use xray_core_rs::{
    open_vless_tcp_stream_with_resolver_and_dialer, open_vless_udp_stream_with_resolver_and_dialer,
    OutboundRouter, TcpOutbound, VlessTcpOutbound, VlessUdpFraming,
};
use xray_routing::{Network as RouteNetwork, Target, TargetAddr as RouteAddr};
use xray_transport::{SocketHandle, SocketProtector};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn json_process(binary: &std::ffi::OsStr, args: &[&str]) -> (Process, Value) {
    let mut process = Process(
        Command::new(binary)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(process.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let value = serde_json::from_str(&line).expect("oracle process must report ready endpoints");
    (process, value)
}

#[derive(Default)]
struct Resolver(Mutex<Vec<String>>);
#[async_trait::async_trait]
impl DnsResolver for Resolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        assert!(matches!(domain, "upload.test" | "download.test"));
        self.0.lock().unwrap().push(domain.to_owned());
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
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
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn greeting_echo(outbound: &VlessTcpOutbound, resolver: &Resolver, dialer: &TransportDialer) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let payload: Vec<u8> = (0..16387).map(|n| (n * 197 + 31) as u8).collect();
    let size = payload.len();
    let _server = Task(tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"greeting").await.unwrap();
        let mut buffer = vec![0; size];
        stream.read_exact(&mut buffer).await.unwrap();
        stream.write_all(&buffer).await.unwrap();
    }));
    let target = Target::new(RouteAddr::Ip(addr.ip()), addr.port(), RouteNetwork::Tcp);
    let mut stream =
        open_vless_tcp_stream_with_resolver_and_dialer(outbound, &target, resolver, dialer)
            .await
            .unwrap();
    let mut greeting = [0; 8];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"greeting");
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut received = vec![0; size];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received.as_ref(), payload);
}

async fn datagram(outbound: &VlessTcpOutbound, resolver: &Resolver, dialer: &TransportDialer) {
    use xray_proxy::vless::{
        encode_udp_packet, encode_xudp_new_packet, read_udp_packet, read_xudp_packet,
    };
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = socket.local_addr().unwrap();
    let _server = Task(tokio::spawn(async move {
        let mut buf = [0; 1024];
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        socket.send_to(&buf[..n], peer).await.unwrap();
    }));
    let target = Target::new(RouteAddr::Ip(addr.ip()), addr.port(), RouteNetwork::Udp);
    let (mut stream, framing) =
        open_vless_udp_stream_with_resolver_and_dialer(outbound, &target, resolver, dialer)
            .await
            .unwrap();
    let payload = b"independent download UDP";
    let wire = if framing == VlessUdpFraming::Xudp {
        encode_xudp_new_packet(&target, payload, [0; 8]).unwrap()
    } else {
        encode_udp_packet(payload).unwrap()
    };
    stream.write_all(&wire).await.unwrap();
    stream.flush().await.unwrap();
    let received = if framing == VlessUdpFraming::Xudp {
        read_xudp_packet(&mut stream).await.unwrap().payload
    } else {
        read_udp_packet(&mut stream).await.unwrap()
    };
    assert_eq!(received.as_ref(), payload);
}

#[tokio::test]
#[ignore = "requires guarded Xray, local TLS H1/H2/H3 bridge and REALITY origin; run scripts/check-xhttp-download-oracle.sh"]
async fn full_xray_download_carrier_matrix() {
    let checkout = resolve_xray_checkout();
    let bridge_binary = env::var_os("XRAY_DOWNLOAD_ORACLE").expect("guarded download oracle");
    let encryption_oracle =
        env::var_os("XRAY_VLESS_ENCRYPTION_ORACLE").expect("guarded encryption oracle");
    let (_origin, origin) = json_process(&encryption_oracle, &["origin"]);
    let output = Command::new(&encryption_oracle)
        .args(["keypair", "x25519"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let keys: Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut profiles = 0;
    for protection in ["plain", "tls", "reality"] {
        for encryption_flow in ["none", "encrypted", "vision"] {
            let encrypted = encryption_flow != "none";
            let vision = encryption_flow == "vision";
            let xray = start_xray_vless_server_customized(
                &checkout,
                XrayVlessServerConfig {
                    security: if protection == "reality" {
                        XrayInboundSecurity::Reality
                    } else {
                        XrayInboundSecurity::None
                    },
                    transport: XrayInboundTransport::Xhttp {
                        path: "/split/",
                        mode: "auto",
                        tls_alpn: None,
                    },
                    flow: vision.then_some("xtls-rprx-vision"),
                },
                |config| {
                    if encrypted {
                        config["inbounds"][0]["settings"]["decryption"] = format!(
                            "mlkem768x25519plus.random.600s.{}",
                            keys["private"].as_str().unwrap()
                        )
                        .into();
                    }
                    if protection == "reality" {
                        let r = &mut config["inbounds"][0]["streamSettings"]["realitySettings"];
                        r["dest"] = origin["address"].clone();
                        r["serverNames"] = json!(["encryption-oracle.test"]);
                        r["show"] = false.into();
                    }
                },
            )
            .await;
            let bridge = (protection == "tls")
                .then(|| json_process(&bridge_binary, &["bridge", &xray.addr.to_string()]));
            let versions = if protection == "tls" {
                vec!["http/1.1", "h2", "h3"]
            } else if protection == "reality" {
                vec!["h2"]
            } else {
                vec!["http/1.1"]
            };
            for up_version in &versions {
                for down_version in &versions {
                    for mode in ["packet-up", "stream-up"] {
                        eprintln!("checking {protection}/{encryption_flow}/{mode}/{up_version}->{down_version}");
                        let endpoint = |version: &str, down: bool| -> Value {
                            let mut s = json!({"network":"xhttp","security": "none", "xhttpSettings":{"path":"/split/", "xPaddingBytes":64,"scMaxEachPostBytes":4096,"scMinPostsIntervalMs":1, "xmux":{"maxConnections":1}}});
                            let port = if let Some((_, bridge)) = &bridge {
                                let addr: SocketAddr = bridge
                                    [if version == "h3" { "h3" } else { "tcp" }]
                                .as_str()
                                .unwrap()
                                .parse()
                                .unwrap();
                                s["security"] = "tls".into();
                                s["tlsSettings"] = json!({"serverName":"download-oracle.test","alpn":[version],"pinnedPeerCertSha256":bridge["pin"]});
                                s["xhttpSettings"]["path"] =
                                    if down { "/download/" } else { "/upload/" }.into();
                                addr.port()
                            } else {
                                if protection == "reality" {
                                    s["security"] = "reality".into();
                                    s["realitySettings"] = json!({"serverName":"encryption-oracle.test","fingerprint":"chrome","publicKey":REALITY_PUBLIC_KEY_BASE64,"shortId":REALITY_SHORT_ID_HEX});
                                }
                                xray.addr.port()
                            };
                            s["address"] =
                                if down { "download.test" } else { "upload.test" }.into();
                            s["port"] = port.into();
                            s
                        };
                        let mut upload = endpoint(up_version, false);
                        let port = upload.as_object_mut().unwrap().remove("port").unwrap();
                        upload.as_object_mut().unwrap().remove("address");
                        upload["xhttpSettings"]["mode"] = mode.into();
                        upload["xhttpSettings"]["downloadSettings"] = endpoint(down_version, true);
                        let encryption = if encrypted {
                            format!(
                                "mlkem768x25519plus.random.0rtt.{}",
                                keys["public"].as_str().unwrap()
                            )
                        } else {
                            "none".to_owned()
                        };
                        let mut user = json!({"id":TEST_UUID,"encryption":encryption});
                        if vision {
                            user["flow"] = "xtls-rprx-vision".into();
                        }
                        let parsed = parse_xray_json(&json!({"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"upload.test","port":port,"users":[user]}]},"streamSettings":upload}]}).to_string()).unwrap();
                        let TcpOutbound::Vless(outbound) =
                            OutboundRouter::new(Arc::new(parsed.config))
                                .select_tcp_outbound()
                                .unwrap()
                        else {
                            panic!("VLESS")
                        };
                        let resolver = Resolver::default();
                        let protector = Arc::new(Protector::default());
                        let dialer =
                            TransportDialer::system_with_socket_protector(Some(protector.clone()))
                                .unwrap();
                        let result = timeout(Duration::from_secs(25), async {
                            // First flow obtains a ticket. Later flows reuse both pools and the
                            // authenticated ticket; simultaneous flows exercise separate leases.
                            greeting_echo(&outbound, &resolver, &dialer).await;
                            tokio::join!(
                                greeting_echo(&outbound, &resolver, &dialer),
                                greeting_echo(&outbound, &resolver, &dialer)
                            );
                            datagram(&outbound, &resolver, &dialer).await;
                        })
                        .await;
                        assert!(result.is_ok(),"{protection}/{encryption_flow}/{mode}/{up_version}->{down_version}: {}",xray.logs());
                        let queries = resolver.0.lock().unwrap();
                        assert_eq!(queries.iter().filter(|q| *q == "upload.test").count(), 4);
                        assert_eq!(queries.iter().filter(|q| *q == "download.test").count(), 4);
                        assert!(
                            protector.0.load(Ordering::SeqCst) >= 2,
                            "both carriers must use socket protection"
                        );
                        profiles += 1;
                        eprintln!("split profile {profiles}: {protection}/{encryption_flow}/{mode}/{up_version}->{down_version} passed");
                    }
                }
            }
        }
    }
    assert_eq!(profiles, 66);
    eprintln!(
        "XHTTP download full-Xray matrix: {profiles} profiles, {} application flows passed",
        profiles * 4
    );
}
