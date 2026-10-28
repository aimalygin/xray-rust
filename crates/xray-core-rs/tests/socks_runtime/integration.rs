//! TCP integration gaps from #79: authenticated TLS, real proxy hops and probes.
use super::*;
use std::sync::Mutex;
use xray_core_rs::{OutboundHealthFailure, OutboundProbeOutcome, StartupProbeOptions};

#[path = "../http_runtime/support.rs"]
mod http_support;

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-socks-interop.sh"]
async fn socks_runtime_tcp_tls_rejects_untrusted_cert_and_wrong_name() {
    timeout(DEADLINE * 2, async {
        let server = XrayServer::start_tls().await;
        let (echo, _echo) = tcp_echo().await;
        for wrong_name in [false, true] {
            let mut config = profile(
                outbound_settings(Form::Flat, server.password, Some((USER, PASS))),
                true,
            );
            // Either use ordinary roots (which do not trust the fixture), or
            // trust its certificate but request a name it does not cover.
            let connector = if wrong_name {
                config["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"] =
                    json!("wrong.socks-interop.test");
                server.connector.clone()
            } else {
                None
            };
            let (mut core, protector, _) = core_with_profile(config, connector);
            core.start().await.unwrap();
            let proxy = core.inbound_addr(Some("socks-in")).unwrap();
            let (_stream, reply) = connect(proxy, Destination::Ip(echo)).await;
            assert_ne!(
                reply, 0,
                "TLS verification must fail, wrong_name={wrong_name}"
            );
            assert!(protector.0.load(Ordering::SeqCst) > 0);
            core.stop().await.unwrap();
        }
    })
    .await
    .unwrap();
}

fn chained_profile(mut entry: Value, hop: Value, modern: bool) -> Value {
    if modern {
        entry["streamSettings"]["sockopt"]["dialerProxy"] = json!("hop");
    } else {
        entry["proxySettings"] = json!({"tag":"hop", "transportLayer":true});
    }
    json!({
        "inbounds": [{"tag":"socks-in", "protocol":"socks", "listen":"127.0.0.1",
            "port":0, "settings":{"auth":"noauth"}}],
        "outbounds": [{"tag":"blocked", "protocol":"blackhole"}, entry, hop],
        "routing": {"rules": [
            {"type":"field", "inboundTag":["socks-in"], "outboundTag":"entry"}
        ]}
    })
}

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-socks-interop.sh"]
async fn socks_runtime_chains_with_pinned_http_in_both_directions() {
    timeout(DEADLINE * 6, async {
        let (echo, _echo) = tcp_echo().await;
        let http = http_support::XrayServer::start().await;
        for tls in [false, true] {
            let socks = XrayServer::start_on(Ipv4Addr::LOCALHOST.into(), tls).await;
            for socks_is_entry in [false, true] {
                // Only the outer carrier is resolved locally. The hop resolves
                // the next proxy's domain, and the entry resolves the final
                // destination. Bootstrap panics if either leaks to the client.
                let mut socks_out = json!({
                    "tag": if socks_is_entry { "entry" } else { "hop" },
                    "protocol":"socks",
                    "settings":outbound_settings_at(Form::Flat,
                        if socks_is_entry { http_support::REMOTE_DOMAIN } else { "bootstrap.example" },
                        socks.password, Some((USER, PASS)))
                });
                if tls {
                    socks_out["streamSettings"] = json!({"network":"raw", "security":"tls",
                        "tlsSettings":{"serverName":"localhost"}});
                }
                let http_out = json!({
                    "tag": if socks_is_entry { "hop" } else { "entry" },
                    "protocol":"http", "settings":{
                        "address": if socks_is_entry { "bootstrap.example" } else { REMOTE_DOMAIN },
                        "port":http.password, "user":http_support::USER, "pass":http_support::PASS
                    }
                });
                let (entry, hop, destination, carrier_target) = if socks_is_entry {
                    (socks_out, http_out, REMOTE_DOMAIN,
                        format!("tcp:{}:{}", http_support::REMOTE_DOMAIN, socks.password))
                } else {
                    (http_out, socks_out, http_support::REMOTE_DOMAIN,
                        format!("tcp:{REMOTE_DOMAIN}:{}", http.password))
                };
                for modern in [false, true] {
                    let config = chained_profile(entry.clone(), hop.clone(), modern);
                    let (mut core, protector, bootstrap) =
                        core_with_profile(config.clone(), socks.connector.clone());
                    core.start().await.unwrap();
                    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
                    let (mut stream, reply) =
                        connect(proxy, Destination::Domain(destination, echo.port())).await;
                    assert_eq!(reply, 0, "SOCKS entry={socks_is_entry}, TLS={tls}, dialerProxy={modern}");
                    echo_round_trip(&mut stream, PAYLOAD_LEN).await;
                    assert!(protector.0.load(Ordering::SeqCst) > 0);
                    assert!(bootstrap.0.load(Ordering::SeqCst) > 0);
                    let snapshot = core.connection_snapshot();
                    assert_eq!(snapshot.connections.len(), 1);
                    assert_eq!(snapshot.connections[0].outbound_tag.as_deref(), Some("entry"));
                    let final_target = format!("tcp:{destination}:{}", echo.port());
                    let (entry_log, hop_log) = if socks_is_entry {
                        (socks.log(), http.log())
                    } else {
                        (http.log(), socks.log())
                    };
                    assert!(hop_log.contains(&carrier_target), "hop did not receive {carrier_target}");
                    assert!(entry_log.contains(&final_target), "entry did not receive {final_target}");
                    drop(stream);
                    core.stop().await.unwrap();

                    // Changing either password must break this same path,
                    // even though the echo endpoint is directly reachable.
                    for failed_hop in [1, 2] {
                        let mut bad = config.clone();
                        bad["outbounds"][failed_hop]["settings"]["pass"] = json!("synthetic-wrong-pass");
                        let (mut core, _, _) = core_with_profile(bad, socks.connector.clone());
                        core.start().await.unwrap();
                        let proxy = core.inbound_addr(Some("socks-in")).unwrap();
                        let (_stream, reply) =
                            connect(proxy, Destination::Domain(destination, echo.port())).await;
                        assert_ne!(reply, 0, "failed hop {failed_hop} must not fall back to direct");
                        core.stop().await.unwrap();
                    }
                    eprintln!("SOCKS/HTTP chain entry_socks={socks_is_entry}, TLS={tls}, dialerProxy={modern}: payload and both auth failures passed");
                }
            }
        }
    })
    .await
    .unwrap();
}

struct ProbeServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    _task: Task,
}

impl ProbeServer {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let task = Task(tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted.unwrap();
                        let captured = captured.clone();
                        connections.spawn(async move {
                            let mut request = Vec::new();
                            while !request.ends_with(b"\r\n\r\n") {
                                assert!(request.len() < 4096, "probe request exceeds fixture limit");
                                let Ok(byte) = stream.read_u8().await else { return; };
                                request.push(byte);
                            }
                            let request = String::from_utf8(request).unwrap();
                            let status = if request.starts_with("GET /healthy?check=socks ") {
                                "204 No Content"
                            } else {
                                "503 Service Unavailable"
                            };
                            captured.lock().unwrap().push(request);
                            let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                            let _ = stream.write_all(response.as_bytes()).await;
                        });
                    },
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap().unwrap();
                    }
                }
            }
        }));
        Self {
            address,
            requests,
            _task: task,
        }
    }
}

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-socks-interop.sh"]
async fn socks_runtime_outbound_probe_through_pinned_xray() {
    timeout(DEADLINE * 6, async {
        let endpoint = ProbeServer::start().await;
        for carrier in [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)] {
            let address = if carrier.is_ipv4() { "bootstrap.example" } else { "::1" };
            for tls in [false, true] {
                let server = XrayServer::start_on(carrier, tls).await;
                for form in [Form::Flat, Form::Servers] {
                    for (port, account) in [(server.password, Some((USER, PASS))), (server.noauth, None)] {
                        let mut config = profile(outbound_settings_at(form, address, port, account), tls);
                        // A probe must select the requested SOCKS outbound;
                        // accidentally using the default blackhole cannot pass.
                        config["outbounds"].as_array_mut().unwrap().insert(0,
                            json!({"tag":"blocked", "protocol":"blackhole"}));
                        let (mut core, protector, bootstrap) = core_with_profile(config, server.connector.clone());
                        core.start().await.unwrap();
                        for path in ["/healthy?check=socks", "/unavailable"] {
                            let before = endpoint.requests.lock().unwrap().len();
                            let outcome = core.probe_outbound_url(StartupProbeOptions {
                                url: format!("http://{REMOTE_DOMAIN}:{}{path}", endpoint.address.port()),
                                timeout: Duration::from_secs(5),
                                outbound_tag: Some("proxy".to_owned()),
                            }).await.unwrap();
                            if path.starts_with("/healthy") {
                                assert!(matches!(outcome, OutboundProbeOutcome::Reachable { .. }), "{outcome:?}");
                            } else {
                                assert_eq!(outcome, OutboundProbeOutcome::Failed(OutboundHealthFailure::HttpStatus(503)));
                            }
                            let requests = endpoint.requests.lock().unwrap();
                            assert_eq!(requests.len(), before + 1);
                            assert!(requests[before].starts_with(&format!("GET {path} HTTP/1.1\r\n")));
                            assert!(requests[before].contains(&format!("\r\nHost: {REMOTE_DOMAIN}:{}\r\n", endpoint.address.port())));
                        }
                        assert!(protector.0.load(Ordering::SeqCst) > 0);
                        assert_eq!(bootstrap.0.load(Ordering::SeqCst) > 0, carrier.is_ipv4());
                        assert!(server.log().contains(&format!("tcp:{REMOTE_DOMAIN}:{}", endpoint.address.port())));
                        core.stop().await.unwrap();
                    }
                    let before = endpoint.requests.lock().unwrap().len();
                    let (mut core, _, _) = core_with_tls(outbound_settings_at(form, address,
                        server.password, Some((USER, "synthetic-wrong-pass"))), server.connector.clone());
                    core.start().await.unwrap();
                    let outcome = core.probe_outbound_url(StartupProbeOptions {
                        url: format!("http://{REMOTE_DOMAIN}:{}/healthy?check=socks", endpoint.address.port()),
                        timeout: Duration::from_secs(5),
                        outbound_tag: Some("proxy".to_owned()),
                    }).await.unwrap();
                    assert_eq!(outcome, OutboundProbeOutcome::Failed(OutboundHealthFailure::Transport));
                    assert_eq!(endpoint.requests.lock().unwrap().len(), before, "failed auth must not reach the probe endpoint");
                    core.stop().await.unwrap();
                    eprintln!("SOCKS probe {form:?}, carrier={carrier}, TLS={tls}: 204/503 and auth failure passed");
                }
            }
        }
    })
    .await
    .unwrap();
}
