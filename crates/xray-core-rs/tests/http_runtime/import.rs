use super::*;
use xray_config::profile_import::{import_profile, ProfileFormat};

fn imported(text: &str) -> Value {
    let profile = import_profile(ProfileFormat::Http, text, None, &[]).unwrap();
    let mut config: Value = serde_json::from_str(&profile.config_json).unwrap();
    // Keep the imported TUN, DNS, routing, authentication and TLS policy intact.
    config["inbounds"].as_array_mut().unwrap().push(json!({
        "tag":"socks-in", "protocol":"socks", "listen":"127.0.0.1", "port":0,
        "settings":{"auth":"noauth"}
    }));
    config
}

#[tokio::test]
async fn http_runtime_imported_https_verifies_trust_name_and_alpn() {
    timeout(DEADLINE * 4, async {
        let (echo, _echo) = tcp_echo().await;
        for (names, trusted, succeeds) in [
            (
                vec!["bootstrap.example".into(), "127.0.0.1".into()],
                true,
                true,
            ),
            (vec!["wrong.example".into()], true, false),
            (vec!["bootstrap.example".into()], false, false),
        ] {
            let identity = tls_identity_for(names);
            let proxy =
                ScriptedProxy::start(Reply::Tunnel(b""), Some(identity.acceptor), echo.ip()).await;
            for host in ["bootstrap.example", "127.0.0.1"] {
                let config = imported(&format!(
                    "https://synthetic:p%40ss@{host}:{}",
                    proxy.address.port()
                ));
                let tls = trusted.then(|| identity.trusted_connector.clone());
                let (mut core, protector, bootstrap) = core_with_tls(config, tls);
                core.start().await.unwrap();
                let (mut stream, reply) = connect(
                    core.inbound_addr(Some("socks-in")).unwrap(),
                    Destination::Domain(REMOTE_DOMAIN, echo.port()),
                )
                .await;
                assert_eq!(reply == 0, succeeds);
                if succeeds {
                    echo_round_trip(&mut stream, PAYLOAD_LEN).await;
                    let captured = proxy.captured();
                    let request = captured.last().unwrap();
                    assert_eq!(request.alpn.as_deref(), Some(b"http/1.1".as_slice()));
                    assert!(request
                        .head
                        .contains(&format!("CONNECT {REMOTE_DOMAIN}:{} HTTP/1.1", echo.port())));
                    assert!(request
                        .head
                        .contains("Proxy-Authorization: Basic c3ludGhldGljOnBAc3M="));
                } else {
                    assert!(
                        proxy.captured().is_empty(),
                        "credentials must not reach an unverified server"
                    );
                }
                assert!(protector.0.load(Ordering::SeqCst) > 0);
                assert_eq!(
                    bootstrap.0.load(Ordering::SeqCst) > 0,
                    host == "bootstrap.example"
                );
                drop(stream);
                core.stop().await.unwrap();
            }
        }
    })
    .await
    .expect("imported HTTPS test timed out");
}

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-http-interop.sh"]
async fn http_runtime_imported_http_and_https_against_pinned_xray() {
    timeout(DEADLINE * 6, async {
        let (echo, _echo) = tcp_echo().await;
        for tls in [false, true] {
            let server = if tls {
                XrayServer::start_tls_for_import().await
            } else {
                XrayServer::start().await
            };
            let scheme = if tls { "https" } else { "http" };
            for host in ["bootstrap.example", "127.0.0.1"] {
                for (account, port, succeeds) in [
                    (String::new(), server.noauth, true),
                    (
                        format!("{}:{}@", USER.replace('-', "%2D"), PASS.replace('-', "%2D")),
                        server.password,
                        true,
                    ),
                    (format!("{USER}:wrong@"), server.password, false),
                    (String::new(), server.password, false),
                ] {
                    let config = imported(&format!("{scheme}://{account}{host}:{port}"));
                    let (mut core, protector, bootstrap) =
                        core_with_tls(config, server.trusted_connector.clone());
                    core.start().await.unwrap();
                    let (mut stream, reply) = connect(
                        core.inbound_addr(Some("socks-in")).unwrap(),
                        Destination::Domain(REMOTE_DOMAIN, echo.port()),
                    )
                    .await;
                    assert_eq!(reply == 0, succeeds);
                    if succeeds {
                        echo_round_trip(&mut stream, PAYLOAD_LEN).await;
                    }
                    assert!(protector.0.load(Ordering::SeqCst) > 0);
                    assert_eq!(
                        bootstrap.0.load(Ordering::SeqCst) > 0,
                        host == "bootstrap.example"
                    );
                    drop(stream);
                    core.stop().await.unwrap();
                }
            }
        }
    })
    .await
    .expect("imported HTTP/HTTPS interop timed out");
}
