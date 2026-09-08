use super::*;
use std::io::{BufRead, BufReader};
use xray_core_rs::{open_vless_tcp_stream_with_resolver_and_dialer, OutboundRouter, TcpOutbound};
use xray_routing::{Network, Target, TargetAddr};

struct Origin(Child);
impl Drop for Origin {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires guarded pinned Xray binary and local cover origin; run scripts/check-vless-encryption-oracle.sh"]
async fn full_xray_encrypted_raw_tls_reality() {
    let checkout = resolve_xray_checkout();
    assert_eq!(
        env::var(XRAY_CORE_EXPECTED_REVISION_ENV)
            .ok()
            .as_deref()
            .unwrap_or(PINNED_XRAY_CORE_REVISION),
        PINNED_XRAY_CORE_REVISION
    );
    let oracle = env::var_os("XRAY_VLESS_ENCRYPTION_ORACLE").expect("guarded oracle binary");
    let mut origin = Origin(
        Command::new(&oracle)
            .arg("origin")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(origin.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let address: serde_json::Value = serde_json::from_str(&line).unwrap();
    for security in [
        XrayInboundSecurity::None,
        XrayInboundSecurity::Tls,
        XrayInboundSecurity::Reality,
    ] {
        for mode in ["native", "xorpub", "random"] {
            for kind in ["x25519", "mlkem768"] {
                let keys = Command::new(&oracle)
                    .args(["keypair", kind])
                    .output()
                    .unwrap();
                assert!(
                    keys.status.success(),
                    "ephemeral test key generation failed"
                );
                let keys: serde_json::Value = serde_json::from_slice(&keys.stdout).unwrap();
                let encryption = format!(
                    "mlkem768x25519plus.{mode}.1rtt.{}",
                    keys["public"].as_str().unwrap()
                );
                let xray = start_xray_vless_server_customized(
                    &checkout,
                    XrayVlessServerConfig {
                        security,
                        transport: XrayInboundTransport::Raw,
                        flow: None,
                    },
                    |json| {
                        json["inbounds"][0]["settings"]["decryption"] = format!(
                            "mlkem768x25519plus.{mode}.0s.{}",
                            keys["private"].as_str().unwrap()
                        )
                        .into();
                        if security == XrayInboundSecurity::Reality {
                            let settings =
                                &mut json["inbounds"][0]["streamSettings"]["realitySettings"];
                            settings["dest"] = address["address"].clone();
                            settings["serverNames"] = serde_json::json!(["encryption-oracle.test"]);
                            settings["show"] = false.into();
                        }
                    },
                )
                .await;
                let stream_settings = match security {
                    XrayInboundSecurity::None => {
                        serde_json::json!({"network":"tcp", "security":"none"})
                    }
                    XrayInboundSecurity::Tls => {
                        serde_json::json!({"network":"tcp", "security":"tls", "tlsSettings":{"serverName":TLS_SERVER_NAME}})
                    }
                    XrayInboundSecurity::Reality => {
                        serde_json::json!({"network":"tcp", "security":"reality", "realitySettings":{"serverName":"encryption-oracle.test", "fingerprint":"chrome", "publicKey":REALITY_PUBLIC_KEY_BASE64, "shortId":REALITY_SHORT_ID_HEX}})
                    }
                };
                let json = serde_json::json!({"outbounds":[{"protocol":"vless", "settings":{"vnext":[{"address":"127.0.0.1", "port":xray.addr.port(), "users":[{"id":TEST_UUID, "encryption":encryption}]}]}, "streamSettings":stream_settings}]});
                let config = parse_xray_json(&json.to_string()).unwrap().config;
                let TcpOutbound::Vless(outbound) = OutboundRouter::new(Arc::new(config))
                    .select_tcp_outbound()
                    .unwrap()
                else {
                    panic!("VLESS required")
                };
                let dialer = match xray.tls_client_config.as_ref() {
                    Some(trust) => TransportDialer::with_tls_connector(
                        TlsConnector::with_pinned_client_config(Arc::clone(trust)),
                    ),
                    None => TransportDialer::system().unwrap(),
                };
                // A separate warm-up handshake trains REALITY's cover detector.
                // Its separate local target cannot consume the later echo socket.
                if security == XrayInboundSecurity::Reality {
                    let dummy =
                        Target::new(TargetAddr::Ip(Ipv4Addr::LOCALHOST.into()), 9, Network::Tcp);
                    let _ = timeout(
                        Duration::from_secs(5),
                        open_vless_tcp_stream_with_resolver_and_dialer(
                            &outbound,
                            &dummy,
                            &SystemDnsResolver,
                            &dialer,
                        ),
                    )
                    .await;
                }
                let (echo_addr, echo) = spawn_echo_server().await;
                let target = Target::new(
                    TargetAddr::Ip(echo_addr.ip()),
                    echo_addr.port(),
                    Network::Tcp,
                );
                let result = timeout(Duration::from_secs(15), async {
                    let mut stream = open_vless_tcp_stream_with_resolver_and_dialer(
                        &outbound,
                        &target,
                        &SystemDnsResolver,
                        &dialer,
                    )
                    .await
                    .map_err(std::io::Error::other)?;
                    let payload: Vec<u8> = (0..65539).map(|i| (i * 197 + 131) as u8).collect();
                    let (mut reader, mut writer) = tokio::io::split(&mut stream);
                    let send = async {
                        writer.write_all(&payload).await?;
                        writer.shutdown().await
                    };
                    let receive = async {
                        let mut actual = vec![0; payload.len()];
                        reader.read_exact(&mut actual).await?;
                        assert_eq!(actual, payload);
                        Ok::<_, std::io::Error>(())
                    };
                    tokio::try_join!(send, receive).map(|_| ())
                })
                .await;
                assert!(
                    matches!(result, Ok(Ok(()))),
                    "full Xray {security:?}/{mode}/{kind}: {result:?}"
                );
                timeout(Duration::from_secs(5), echo)
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
    }
}

struct FullMatrix {
    checkout: PathBuf,
    oracle: std::ffi::OsString,
    _origin: Origin,
    origin_address: serde_json::Value,
}

impl FullMatrix {
    fn new() -> Self {
        let checkout = resolve_xray_checkout();
        assert_eq!(
            expected_xray_checkout_revision(
                env::var(XRAY_CORE_EXPECTED_REVISION_ENV).ok().as_deref()
            )
            .unwrap(),
            PINNED_XRAY_CORE_REVISION
        );
        let oracle = env::var_os("XRAY_VLESS_ENCRYPTION_ORACLE").expect("guarded oracle binary");
        let mut origin = Origin(
            Command::new(&oracle)
                .arg("origin")
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        BufReader::new(origin.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let address: serde_json::Value = serde_json::from_str(&line).unwrap();
        Self {
            checkout,
            oracle,
            _origin: origin,
            origin_address: address["address"].clone(),
        }
    }

    async fn start(
        &self,
        security: XrayInboundSecurity,
        carrier: XrayInboundTransport,
        mode: &str,
        flow: Option<&'static str>,
        redirect: Option<SocketAddr>,
        multi: bool,
    ) -> (XrayServer, xray_core_rs::VlessTcpOutbound, TransportDialer) {
        // Both NFS key kinds and a mixed three-relay chain are represented in
        // every carrier/security/flow pairing across the three masking modes.
        let kinds: &[&str] = match mode {
            "native" => &["x25519"],
            "xorpub" => &["mlkem768"],
            _ => &["x25519", "mlkem768", "x25519"],
        };
        let mut public = Vec::new();
        let mut private = Vec::new();
        for kind in kinds {
            let keys = Command::new(&self.oracle)
                .args(["keypair", kind])
                .output()
                .unwrap();
            assert!(
                keys.status.success(),
                "ephemeral test key generation failed"
            );
            let keys: serde_json::Value = serde_json::from_slice(&keys.stdout).unwrap();
            public.push(keys["public"].as_str().unwrap().to_owned());
            private.push(keys["private"].as_str().unwrap().to_owned());
        }
        let rtt = "0rtt";
        let lifetime = "120s";
        let padding = "100-35-35.100-0-0.100-35-35";
        let encryption = format!(
            "mlkem768x25519plus.{mode}.{rtt}.{padding}.{}",
            public.join(".")
        );
        let xray = start_xray_vless_server_customized(
            &self.checkout,
            XrayVlessServerConfig {
                security,
                transport: carrier,
                flow: flow.map(|_| "xtls-rprx-vision"),
            },
            |json| {
                json["inbounds"][0]["settings"]["decryption"] = format!(
                    "mlkem768x25519plus.{mode}.{lifetime}.{padding}.{}",
                    private.join(".")
                )
                .into();
                if let Some(address) = redirect {
                    json["outbounds"][0]["settings"]["redirect"] = address.to_string().into();
                }
                if security == XrayInboundSecurity::Reality {
                    let settings = &mut json["inbounds"][0]["streamSettings"]["realitySettings"];
                    settings["dest"] = self.origin_address.clone();
                    settings["serverNames"] = serde_json::json!(["encryption-oracle.test"]);
                    settings["show"] = false.into();
                }
            },
        )
        .await;
        let mut stream = match security {
            XrayInboundSecurity::None => serde_json::json!({"security":"none"}),
            XrayInboundSecurity::Tls => {
                serde_json::json!({"security":"tls", "tlsSettings":{"serverName":TLS_SERVER_NAME}})
            }
            XrayInboundSecurity::Reality => {
                serde_json::json!({"security":"reality", "realitySettings":{"serverName":"encryption-oracle.test", "fingerprint":"chrome", "publicKey":REALITY_PUBLIC_KEY_BASE64, "shortId":REALITY_SHORT_ID_HEX}})
            }
        };
        match carrier {
            XrayInboundTransport::Raw => stream["network"] = "tcp".into(),
            XrayInboundTransport::WebSocket { path } => {
                stream["network"] = "ws".into();
                stream["wsSettings"] = serde_json::json!({"path":format!("{path}?ed=256")});
            }
            XrayInboundTransport::HttpUpgrade { path } => {
                stream["network"] = "httpupgrade".into();
                stream["httpupgradeSettings"] =
                    serde_json::json!({"path":format!("{path}?ed=256")});
            }
            XrayInboundTransport::Grpc { service_name } => {
                stream["network"] = "grpc".into();
                stream["grpcSettings"] =
                    serde_json::json!({"serviceName":service_name,"multiMode":multi});
            }
            XrayInboundTransport::Xhttp {
                path,
                mode,
                tls_alpn,
            } => {
                stream["network"] = "xhttp".into();
                stream["xhttpSettings"] = serde_json::json!({"path":path,"mode":mode,"xPaddingBytes":64,"scMaxEachPostBytes":4096,"scMinPostsIntervalMs":1,"xmux":{"maxConcurrency":1,"maxConnections":0,"hMaxRequestTimes":64,"hMaxReusableSecs":3600}});
                if let Some(alpn) = tls_alpn {
                    stream["tlsSettings"]["alpn"] = serde_json::json!([alpn]);
                }
            }
        }
        let config = serde_json::json!({"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":xray.addr.port(),"users":[{"id":TEST_UUID,"encryption":encryption,"flow":flow.unwrap_or("")}]}]},"streamSettings":stream}]});
        let parsed = parse_xray_json(&config.to_string()).unwrap();
        let TcpOutbound::Vless(outbound) = OutboundRouter::new(Arc::new(parsed.config))
            .select_tcp_outbound()
            .unwrap()
        else {
            panic!("VLESS required")
        };
        let dialer = match xray.tls_client_config.as_ref() {
            Some(trust) => {
                // An injected rustls config intentionally overrides every
                // config shape, so the fixture must supply the carrier ALPN.
                let mut trust = (**trust).clone();
                trust.alpn_protocols = match carrier {
                    XrayInboundTransport::Grpc { .. } => vec![b"h2".to_vec()],
                    XrayInboundTransport::Xhttp {
                        tls_alpn: Some(alpn),
                        ..
                    } => vec![alpn.as_bytes().to_vec()],
                    _ => Vec::new(),
                };
                TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(
                    Arc::new(trust),
                ))
            }
            None => TransportDialer::system().unwrap(),
        };
        if security == XrayInboundSecurity::Reality {
            let target = Target::new(TargetAddr::Ip(Ipv4Addr::LOCALHOST.into()), 9, Network::Tcp);
            let _ = timeout(
                Duration::from_secs(5),
                open_vless_tcp_stream_with_resolver_and_dialer(
                    &outbound,
                    &target,
                    &SystemDnsResolver,
                    &dialer,
                ),
            )
            .await;
        }
        (xray, *outbound, dialer)
    }
}

async fn matrix_tcp(
    outbound: &xray_core_rs::VlessTcpOutbound,
    dialer: &TransportDialer,
    inner_tls: bool,
) {
    let (address, trust, task) = if inner_tls {
        let (address, trust, task) = spawn_inner_tls_echo_server().await;
        (address, Some(trust), task)
    } else {
        let (address, task) = spawn_echo_server().await;
        (address, None, task)
    };
    let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
    let stream = open_vless_tcp_stream_with_resolver_and_dialer(
        outbound,
        &target,
        &SystemDnsResolver,
        dialer,
    )
    .await
    .unwrap();
    let mut stream: Box<dyn MatrixIo> = if let Some(trust) = trust {
        Box::new(
            tokio_rustls::TlsConnector::from(trust)
                .connect(
                    rustls::pki_types::ServerName::try_from(INNER_TLS_SERVER_NAME).unwrap(),
                    stream,
                )
                .await
                .expect("inner TLS through encrypted Vision"),
        )
    } else {
        Box::new(stream)
    };
    // More than one record in each direction and several writes *after* the
    // inner TLS handshake force Vision's Direct path, not just padding/End.
    let payload: Vec<u8> = (0..131_101).map(|i| (i * 197 + 131) as u8).collect();
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let send = async {
        for chunk in payload.chunks(4093) {
            writer.write_all(chunk).await.unwrap();
        }
        writer.flush().await.unwrap();
    };
    let receive = async {
        let mut actual = vec![0; payload.len()];
        reader.read_exact(&mut actual).await.unwrap();
        assert!(actual == payload, "full-Xray bulk payload differs");
    };
    tokio::join!(send, receive);
    drop(reader);
    drop(writer);
    stream.shutdown().await.unwrap();
    drop(stream);
    // Split HTTP and pooled gRPC do not necessarily propagate TCP half-close.
    task.abort();
    let _ = task.await;
}
trait MatrixIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> MatrixIo for T {}

async fn matrix_xudp(outbound: &xray_core_rs::VlessTcpOutbound, dialer: &TransportDialer) {
    use xray_core_rs::{open_vless_udp_stream_with_resolver_and_dialer, VlessUdpFraming};
    use xray_proxy::vless::{encode_xudp_keep_packet, encode_xudp_new_packet, read_xudp_packet};
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = socket.local_addr().unwrap();
    let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Udp);
    let echo = tokio::spawn(async move {
        for _ in 0..3 {
            let mut buffer = vec![0; 65535];
            let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(&buffer[..n], peer).await.unwrap();
        }
    });
    let (mut stream, framing) = open_vless_udp_stream_with_resolver_and_dialer(
        outbound,
        &target,
        &SystemDnsResolver,
        dialer,
    )
    .await
    .unwrap();
    assert_eq!(framing, VlessUdpFraming::Xudp);
    for (index, size) in [1, 1400, 4093].into_iter().enumerate() {
        let payload: Vec<u8> = (0..size).map(|i| (i * 197 + 131) as u8).collect();
        let packet = if index == 0 {
            encode_xudp_new_packet(&target, &payload, [0; 8])
        } else {
            encode_xudp_keep_packet(Some(&target), &payload)
        }
        .unwrap();
        stream.write_all(&packet).await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(
            read_xudp_packet(&mut stream)
                .await
                .unwrap()
                .payload
                .as_ref(),
            payload
        );
    }
    stream.shutdown().await.unwrap();
    echo.await.unwrap();
}

#[tokio::test]
#[ignore = "requires guarded pinned Xray binary; run scripts/check-vless-encryption-oracle.sh"]
async fn full_xray_encrypted_carrier_vision_application_matrix() {
    let matrix = FullMatrix::new();
    let mut completed = 0;
    for security in [
        XrayInboundSecurity::None,
        XrayInboundSecurity::Tls,
        XrayInboundSecurity::Reality,
    ] {
        let mut carriers = vec![(XrayInboundTransport::Raw, false)];
        if security != XrayInboundSecurity::Reality {
            carriers.extend([
                (
                    XrayInboundTransport::WebSocket {
                        path: "/encrypted-ws",
                    },
                    false,
                ),
                (
                    XrayInboundTransport::HttpUpgrade {
                        path: "/encrypted-upgrade",
                    },
                    false,
                ),
            ]);
        }
        carriers.extend([false, true].map(|multi| {
            (
                XrayInboundTransport::Grpc {
                    service_name: "encrypted",
                },
                multi,
            )
        }));
        for mode in ["packet-up", "stream-up", "stream-one"] {
            carriers.push((
                XrayInboundTransport::Xhttp {
                    path: "/encrypted-xhttp/",
                    mode,
                    tls_alpn: if security == XrayInboundSecurity::Tls {
                        Some("h2")
                    } else {
                        None
                    },
                },
                false,
            ));
            if security == XrayInboundSecurity::Tls {
                carriers.push((
                    XrayInboundTransport::Xhttp {
                        path: "/encrypted-xhttp/",
                        mode,
                        tls_alpn: Some("http/1.1"),
                    },
                    false,
                ));
            }
        }
        if security == XrayInboundSecurity::Tls {
            for mode in ["packet-up", "stream-up", "stream-one"] {
                carriers.push((
                    XrayInboundTransport::Xhttp {
                        path: "/encrypted-xhttp/",
                        mode,
                        tls_alpn: Some("h3"),
                    },
                    false,
                ));
            }
        }
        for (carrier, multi) in carriers {
            for mode in ["native", "xorpub", "random"] {
                for vision in [false, true] {
                    let label =
                        format!("{security:?}/{carrier:?}/multi={multi}/{mode}/vision={vision}");
                    eprintln!("full-Xray matrix: {label}");
                    timeout(Duration::from_secs(60), async {
                        // 0-RTT configurations make repeated application opens
                        // reuse one outbound's session; the oracle separately
                        // measures the handshake boundary to prove resumption.
                        let (_xray, outbound, dialer) = matrix
                            .start(
                                security,
                                carrier,
                                mode,
                                vision.then_some("xtls-rprx-vision"),
                                None,
                                multi,
                            )
                            .await;
                        matrix_tcp(&outbound, &dialer, false).await;
                        matrix_tcp(&outbound, &dialer, true).await;
                        matrix_xudp(&outbound, &dialer).await;
                    })
                    .await
                    .unwrap_or_else(|_| panic!("full-Xray matrix timed out: {label}"));
                    completed += 1;
                }
            }
        }
    }
    assert_eq!(completed, 168);
    eprintln!(
        "full-Xray matrix: {completed} profiles / {} application flows passed",
        completed * 3
    );
}

#[tokio::test]
#[ignore = "requires guarded pinned Xray binary; run scripts/check-vless-encryption-oracle.sh"]
async fn full_xray_encrypted_udp_and_vision_udp443() {
    use xray_core_rs::{open_vless_udp_stream_with_resolver_and_dialer, VlessUdpFraming};
    use xray_proxy::vless::{
        encode_udp_packet, encode_xudp_new_packet, read_udp_packet, read_xudp_packet,
    };
    let matrix = FullMatrix::new();
    for security in [
        XrayInboundSecurity::None,
        XrayInboundSecurity::Tls,
        XrayInboundSecurity::Reality,
    ] {
        for mode in ["native", "xorpub", "random"] {
            for vision in [false, true] {
                timeout(Duration::from_secs(30), async {
                    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                        .await
                        .unwrap();
                    let address = socket.local_addr().unwrap();
                    let (_xray, outbound, dialer) = matrix
                        .start(
                            security,
                            XrayInboundTransport::Raw,
                            mode,
                            vision.then_some("xtls-rprx-vision-udp443"),
                            Some(address),
                            false,
                        )
                        .await;
                    let target = Target::new(
                        TargetAddr::Ip(Ipv4Addr::LOCALHOST.into()),
                        if vision { 443 } else { 53 },
                        Network::Udp,
                    );
                    let (mut stream, framing) = open_vless_udp_stream_with_resolver_and_dialer(
                        &outbound,
                        &target,
                        &SystemDnsResolver,
                        &dialer,
                    )
                    .await
                    .unwrap();
                    let payload = b"full-Xray encrypted UDP";
                    let packet = if vision {
                        assert_eq!(framing, VlessUdpFraming::Xudp);
                        encode_xudp_new_packet(&target, payload, [0; 8]).unwrap()
                    } else {
                        assert_eq!(framing, VlessUdpFraming::LengthPrefixed);
                        encode_udp_packet(payload).unwrap()
                    };
                    stream.write_all(&packet).await.unwrap();
                    stream.flush().await.unwrap();
                    let mut received = [0; 128];
                    let (size, peer) = socket.recv_from(&mut received).await.unwrap();
                    assert_eq!(&received[..size], payload);
                    socket.send_to(&received[..size], peer).await.unwrap();
                    let echoed = if vision {
                        read_xudp_packet(&mut stream).await.unwrap().payload
                    } else {
                        read_udp_packet(&mut stream).await.unwrap()
                    };
                    assert_eq!(echoed.as_ref(), payload);
                    stream.shutdown().await.unwrap();
                })
                .await
                .unwrap_or_else(|_| {
                    panic!("full-Xray UDP timed out: {security:?}/{mode}/udp443={vision}")
                });
            }
        }
    }
}
