use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use xray_config::profile_import::{import_profile, ProfileFormat};

#[tokio::test]
#[ignore = "requires pinned Xray-core; run scripts/check-socks-interop.sh"]
async fn socks_runtime_imported_links_preserve_auth_and_remote_dns() {
    timeout(DEADLINE * 6, async {
        let (echo, _echo) = tcp_echo().await;
        for carrier in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let server = XrayServer::start_on(carrier, false).await;
            let host = if carrier.is_ipv4() {
                "bootstrap.example"
            } else {
                "[::1]"
            };
            let encoded = STANDARD.encode(format!("{USER}:{PASS}"));
            for link in [
                format!("socks://{host}:{}", server.noauth),
                format!("socks5://Og==@{host}:{}", server.noauth),
                format!(
                    "socks5://{}:{}@{host}:{}",
                    USER.replace('-', "%2D"),
                    PASS.replace('-', "%2D"),
                    server.password
                ),
                format!("socks://{encoded}@{host}:{}", server.password),
            ] {
                let imported = import_profile(ProfileFormat::Socks, &link, None, &[]).unwrap();
                let mut config: Value = serde_json::from_str(&imported.config_json).unwrap();
                // Keep the imported TUN, DNS, routing and outbound intact. A
                // loopback test inbound drives TCP without a physical VPN.
                config["inbounds"].as_array_mut().unwrap().push(json!({
                    "tag":"socks-in", "protocol":"socks", "listen":"127.0.0.1", "port":0,
                    "settings":{"auth":"noauth"}
                }));
                let (mut core, protector, bootstrap) = core_with_profile(config, None);
                core.start().await.unwrap();
                let proxy = core.inbound_addr(Some("socks-in")).unwrap();
                let (mut stream, reply) =
                    connect(proxy, Destination::Domain(REMOTE_DOMAIN, echo.port())).await;
                assert_eq!(reply, 0);
                echo_round_trip(&mut stream, PAYLOAD_LEN).await;
                assert!(protector.0.load(Ordering::SeqCst) > 0);
                // Bootstrap rejects all other domains; destination DNS must
                // happen at the real Go proxy, including for imported links.
                assert_eq!(bootstrap.0.load(Ordering::SeqCst) > 0, carrier.is_ipv4());
                let snapshot = core.connection_snapshot();
                assert_eq!(snapshot.connections.len(), 1);
                assert!(snapshot
                    .connections
                    .iter()
                    .all(|c| c.outbound_tag.as_deref() == Some("proxy")));
                drop(stream);
                core.stop().await.unwrap();
            }
        }
    })
    .await
    .expect("imported SOCKS loopback test timed out");
}
