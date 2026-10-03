use super::xhttp_download::json_process;
use super::*;
use serde_json::{json, Value};
use tokio::net::UdpSocket;
use xray_proxy::inbound::{encode_socks5_udp_datagram, parse_socks5_udp_datagram};
use xray_routing::{Network as RouteNetwork, Target, TargetAddr as RouteAddr};
use xray_transport::{SocketHandle, SocketProtector};

const PASSWORD: &str = "synthetic-v08-carrier-test";
const PSK: &str = "AQEBAQEBAQEBAQEBAQEBAQ==";
const PROTOCOLS: [&str; 3] = ["trojan", "shadowsocks", "vmess"];

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
struct Resolver;
#[async_trait::async_trait]
impl DnsResolver for Resolver {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        assert!(matches!(domain, "upload.test" | "download.test"));
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    }
}
fn settings(protocol: &str, port: u16) -> Value {
    match protocol {
        "trojan" => json!({"address":"upload.test","port":port,"password":PASSWORD}),
        "shadowsocks" => {
            json!({"address":"upload.test","port":port,"method":"2022-blake3-aes-128-gcm","password":PSK})
        }
        "vmess" => {
            json!({"address":"upload.test","port":port,"id":TEST_UUID,"security":"aes-128-gcm"})
        }
        _ => unreachable!(),
    }
}
fn inbound(config: &mut Value, protocol: &str) {
    config["log"]["loglevel"] = "debug".into();
    if config["inbounds"][0]["streamSettings"]["security"] == "reality" {
        config["inbounds"][0]["streamSettings"]["realitySettings"]["show"] = false.into();
    }
    config["inbounds"][0]["protocol"] = protocol.into();
    config["inbounds"][0]["settings"] = match protocol {
        "trojan" => json!({"clients":[{"password":PASSWORD}]}),
        "shadowsocks" => {
            json!({"method":"2022-blake3-aes-128-gcm","password":PSK,"network":"tcp,udp"})
        }
        "vmess" => json!({"clients":[{"id":TEST_UUID}]}),
        _ => unreachable!(),
    };
}
fn profile(protocol: &str, port: u16, stream: Value) -> Value {
    json!({"inbounds":[{"protocol":"socks","tag":"socks-in","listen":"127.0.0.1","port":0,"settings":{"udp":true}}],
        "outbounds":[{"tag":"proxy","protocol":protocol,"settings":settings(protocol,port),"streamSettings":stream}]})
}
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
    let dialer =
        Arc::new(TransportDialer::system_with_socket_protector(Some(protector.clone())).unwrap());
    let mut core = Core::with_runtime_dependencies(
        parse_xray_json(&config.to_string()).unwrap().config,
        Arc::new(Resolver),
        dialer,
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
                let bytes = vec![0xa5; size];
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
async fn v08_carrier_reality_raw_grpc_xhttp_and_udp_mux() {
    let checkout = resolve_xray_checkout();
    let origin_binary = env::var_os("XRAY_VLESS_ENCRYPTION_ORACLE").unwrap();
    let (_origin, origin) = json_process(&origin_binary, &["origin"]);
    for protocol in PROTOCOLS {
        for network in ["raw", "grpc", "xhttp"] {
            let transport = match network {
                "raw" => XrayInboundTransport::Raw,
                "grpc" => XrayInboundTransport::Grpc {
                    service_name: "v08",
                },
                _ => XrayInboundTransport::Xhttp {
                    path: "/split/",
                    mode: "auto",
                    tls_alpn: None,
                },
            };
            let server = start_xray_vless_server_customized(
                &checkout,
                XrayVlessServerConfig {
                    security: XrayInboundSecurity::Reality,
                    transport,
                    flow: None,
                },
                |config| {
                    inbound(config, protocol);
                    config["inbounds"][0]["streamSettings"]["realitySettings"]["dest"] =
                        origin["address"].clone();
                    config["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"] =
                        json!(["encryption-oracle.test"]);
                },
            )
            .await;
            let mut stream = json!({"network":network,"security":"reality","realitySettings":{"serverName":"encryption-oracle.test","fingerprint":"chrome","publicKey":REALITY_PUBLIC_KEY_BASE64,"shortId":REALITY_SHORT_ID_HEX}});
            if network == "grpc" {
                stream["grpcSettings"] = json!({"serviceName":"v08"});
            }
            if network == "xhttp" {
                stream["xhttpSettings"] = json!({"path":"/split/","mode":"stream-one","xPaddingBytes":64,"scMaxEachPostBytes":4096,"scMinPostsIntervalMs":1,"xmux":{"maxConnections":1}});
            }
            // The pinned server's fresh cover-origin detector may consume its
            // first connection. One bounded warmup precedes measured profiles.
            let _ = timeout(
                Duration::from_secs(30),
                exercise(profile(protocol, server.addr.port(), stream.clone()), false),
            )
            .await;
            for mux in [false, true] {
                eprintln!("v08 REALITY {protocol}/{network}, Mux={mux}");
                let mut config = profile(protocol, server.addr.port(), stream.clone());
                if mux {
                    config["outbounds"][0]["mux"] = json!({"enabled":true,"concurrency":if network=="xhttp" {-1} else {4},"xudpConcurrency":4});
                }
                let result = timeout(Duration::from_secs(30), exercise(config, true)).await;
                assert!(
                    matches!(result, Ok(Ok(()))),
                    "{protocol}/{network}/{mux}: {result:?}; {}",
                    server.logs()
                );
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires local pinned oracles; run check-v08-carrier-interop.sh"]
async fn v08_carrier_xhttp_h1_h2_h3_upload_and_independent_download() {
    let checkout = resolve_xray_checkout();
    let bridge_binary = env::var_os("XRAY_DOWNLOAD_ORACLE").unwrap();
    let mut profiles = 0;
    for protocol in PROTOCOLS {
        let server = start_xray_vless_server_customized(
            &checkout,
            XrayVlessServerConfig {
                security: XrayInboundSecurity::None,
                transport: XrayInboundTransport::Xhttp {
                    path: "/split/",
                    mode: "auto",
                    tls_alpn: None,
                },
                flow: None,
            },
            |config| inbound(config, protocol),
        )
        .await;
        let (_bridge, bridge) = json_process(&bridge_binary, &["bridge", &server.addr.to_string()]);
        let endpoint = |version: &str, down: bool| {
            let address: SocketAddr = bridge[if version == "h3" { "h3" } else { "tcp" }]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            json!({"address":if down {"download.test"} else {"upload.test"},"port":address.port(),"network":"xhttp","security":"tls","tlsSettings":{"serverName":"download-oracle.test","alpn":[version],"pinnedPeerCertSha256":bridge["pin"]},"xhttpSettings":{"path":if down {"/download/"} else {"/upload/"},"xPaddingBytes":64,"scMaxEachPostBytes":4096,"scMinPostsIntervalMs":1,"xmux":{"maxConnections":1}}})
        };
        for up in ["http/1.1", "h2", "h3"] {
            for down in [None, Some("http/1.1"), Some("h2"), Some("h3")] {
                for mode in ["packet-up", "stream-up", "stream-one"] {
                    if down.is_some() && mode == "stream-one" {
                        continue;
                    }
                    eprintln!("v08 XHTTP {protocol}/{mode}/{up}->{down:?}");
                    let mut stream = endpoint(up, false);
                    let port = stream
                        .as_object_mut()
                        .unwrap()
                        .remove("port")
                        .unwrap()
                        .as_u64()
                        .unwrap() as u16;
                    stream.as_object_mut().unwrap().remove("address");
                    stream["xhttpSettings"]["mode"] = mode.into();
                    if let Some(down) = down {
                        stream["xhttpSettings"]["downloadSettings"] = endpoint(down, true);
                    }
                    let mut config = profile(protocol, port, stream);
                    // SS native UDP goes directly to Xray's UDP listener, not
                    // the HTTP frontend. A dedicated XUDP pool exercises both
                    // selected HTTP carriers for UDP with all three protocols.
                    config["outbounds"][0]["mux"] =
                        json!({"enabled":true,"concurrency":-1,"xudpConcurrency":4});
                    let result = timeout(Duration::from_secs(30), exercise(config, true)).await;
                    assert!(
                        matches!(result, Ok(Ok(()))),
                        "{protocol}/{mode}/{up}->{down:?}: {result:?}; {}",
                        server.logs()
                    );
                    profiles += 1;
                }
            }
        }
    }
    assert_eq!(profiles, 81);
}

#[tokio::test]
#[ignore = "requires local pinned oracles; run check-v08-carrier-interop.sh"]
async fn v08_carrier_cross_protocol_chains_preserve_server_first_and_large_streams() {
    let checkout = resolve_xray_checkout();
    for hop_protocol in PROTOCOLS {
        let hop = start_xray_vless_server_customized(
            &checkout,
            XrayVlessServerConfig {
                security: XrayInboundSecurity::None,
                transport: XrayInboundTransport::Raw,
                flow: None,
            },
            |config| inbound(config, hop_protocol),
        )
        .await;
        for protocol in PROTOCOLS {
            for network in ["raw", "ws", "grpc", "xhttp"] {
                let transport = match network {
                    "raw" => XrayInboundTransport::Raw,
                    "ws" => XrayInboundTransport::WebSocket { path: "/v08" },
                    "grpc" => XrayInboundTransport::Grpc {
                        service_name: "v08",
                    },
                    _ => XrayInboundTransport::Xhttp {
                        path: "/split/",
                        mode: "stream-one",
                        tls_alpn: None,
                    },
                };
                let server = start_xray_vless_server_customized(
                    &checkout,
                    XrayVlessServerConfig {
                        security: XrayInboundSecurity::None,
                        transport,
                        flow: None,
                    },
                    |config| inbound(config, protocol),
                )
                .await;
                let mut stream = json!({"network":network});
                match network {
                    "ws" => stream["wsSettings"] = json!({"path":"/v08"}),
                    "grpc" => stream["grpcSettings"] = json!({"serviceName":"v08"}),
                    "xhttp" => {
                        stream["xhttpSettings"] = json!({"path":"/split/","mode":"stream-one","xPaddingBytes":64,"scMaxEachPostBytes":4096,"scMinPostsIntervalMs":1,"xmux":{"maxConnections":1}})
                    }
                    _ => {}
                }
                for mux in [false, true] {
                    eprintln!("v08 chain {protocol}/{network} via {hop_protocol}, Mux={mux}");
                    let mut config = profile(protocol, server.addr.port(), stream.clone());
                    config["outbounds"][0]["settings"]["address"] = "127.0.0.1".into();
                    config["outbounds"][0]["proxySettings"] =
                        json!({"tag":"hop","transportLayer":true});
                    let mut hop = json!({"tag":"hop","protocol":hop_protocol,"settings":settings(hop_protocol,hop.addr.port())});
                    if mux {
                        hop["mux"] = json!({"enabled":true,"concurrency":4});
                        if network != "xhttp" {
                            config["outbounds"][0]["mux"] = json!({"enabled":true,"concurrency":4});
                        }
                    }
                    config["outbounds"].as_array_mut().unwrap().push(hop);
                    let result = timeout(Duration::from_secs(30), exercise(config, false)).await;
                    assert!(
                        matches!(result, Ok(Ok(()))),
                        "{protocol}/{network} via {hop_protocol}/{mux}: {result:?}; {}",
                        server.logs()
                    );
                }
            }
        }
    }
}
