use super::*;
#[path = "support.rs"]
mod trojan_support;

fn mux_settings(server: &trojan_support::ReferenceServer) -> serde_json::Value {
    if server.stream["network"] == "xhttp" {
        serde_json::json!({"enabled":true,"concurrency":-1,"xudpConcurrency":8})
    } else {
        serde_json::json!({"enabled":true})
    }
}

async fn reference(protocol: &str, carrier: &str) -> trojan_support::ReferenceServer {
    match protocol {
        "trojan" => trojan_support::ReferenceServer::start(carrier).await,
        "shadowsocks" => {
            trojan_support::ReferenceServer::start_shadowsocks(
                carrier,
                "2022-blake3-chacha20-poly1305",
                false,
            )
            .await
        }
        "vmess" => {
            trojan_support::ReferenceServer::start_vmess(carrier, "chacha20-poly1305", "").await
        }
        _ => unreachable!(),
    }
}

async fn tun_tcp_udp_and_host_close(server: trojan_support::ReferenceServer, mux: bool) {
    timeout(trojan_support::DEADLINE, async {
        let (tcp_address, _tcp) = trojan_support::tcp_echo().await;
        let (udp_address, _udp) = trojan_support::udp_echo().await;
        let (_, protector, bootstrap, dialer) = server.core();
        let mut profile = server.profile();
        if mux {
            profile["outbounds"][0]["mux"] = mux_settings(&server);
        }
        let mut core = Core::with_runtime_dependencies(
            parse_xray_json(&profile.to_string()).unwrap().config,
            bootstrap.clone(),
            dialer,
        )
        .unwrap();
        core.start().await.unwrap();
        let mut client = TunTcpClient::new();
        client.connect(tcp_address);
        pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;
        let payload = b"tun tcp over selected protocol";
        client.send_payload(payload);
        let mut received = Vec::new();
        pump_tun_until(&mut client, core.tun(), |client| {
            received.extend_from_slice(&client.recv_available());
            received.len() >= payload.len()
        })
        .await;
        assert_eq!(received, payload);
        let client_ip = Ipv4Addr::new(10, 10, 0, 2);
        let udp_payload = vec![0xa5; 1200];
        core.tun()
            .push_inbound(Bytes::from(ipv4_udp_packet(
                client_ip,
                49154,
                Ipv4Addr::LOCALHOST,
                udp_address.port(),
                &udp_payload,
            )))
            .await
            .unwrap();
        let reply =
            poll_tun_outbound_until_with_timeout(core.tun(), trojan_support::DEADLINE, |packet| {
                ipv4_udp_payload(packet).is_some_and(|p| p == udp_payload)
            })
            .await;
        assert_ipv4_udp_packet(
            &reply,
            Ipv4Addr::LOCALHOST,
            udp_address.port(),
            client_ip,
            49154,
            &udp_payload,
        );
        assert_eq!(protector.0.load(Ordering::SeqCst), if mux { 1 } else { 2 });
        // Each flow resolves the endpoint before asking the pool for a child.
        assert_eq!(bootstrap.0.load(Ordering::SeqCst), 2);
        let connections = core.connection_snapshot().connections;
        assert_eq!(connections.len(), 2);
        for connection in connections {
            core.close_connection(connection.id).unwrap();
        }
        wait_for_empty_connection_snapshot(&core).await;
        let accounting = core.outbound_accounting_snapshot();
        let proxy = accounting
            .outbounds
            .iter()
            .find(|outbound| outbound.outbound_tag.as_deref() == Some("proxy"))
            .unwrap();
        assert_eq!(proxy.host_closed_connections, 2);
        assert_eq!(
            proxy.uplink_bytes,
            (payload.len() + udp_payload.len()) as u64
        );
        assert_eq!(proxy.downlink_bytes, proxy.uplink_bytes);
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

async fn tun_dns_wire_and_managed_destination_lookup(
    server: trojan_support::ReferenceServer,
    mux: bool,
) {
    timeout(trojan_support::DEADLINE, async {
        let upstream = spawn_observed_udp_dns_a_server(Ipv4Addr::LOCALHOST).await;
        let upstream_probe = upstream.probe();
        let (echo_address, _tcp) = trojan_support::tcp_echo().await;
        let (_, protector, _, dialer) = server.core();
        let mut json = server.profile();
        if mux { json["outbounds"][0]["mux"] = mux_settings(&server); }
        json["dns"] = serde_json::json!({
            "queryStrategy":"UseIPv4", "hosts":{"bootstrap.example":"127.0.0.1"},
            "servers":[{"address":"127.0.0.1","port":upstream.addr().port()}]
        });
        let config = parse_xray_json(&json.to_string()).unwrap().config;
        let mut core = Core::with_transport_dialer_and_tun_options(config, dialer, TunRuntimeOptions { dns_bootstrap: DnsBootstrapMode::StaticOnly, ..Default::default() }).unwrap();
        core.start().await.unwrap();
        let query = build_dns_a_query(0x7262, "wire-trojan.example");
        let anchor = Ipv4Addr::new(198,18,0,1);
        let client_ip = Ipv4Addr::new(10,10,0,2);
        core.tun().push_inbound(Bytes::from(ipv4_udp_packet(client_ip, 53044, anchor, 53, &query))).await.unwrap();
        let reply = poll_tun_outbound_until_with_timeout(core.tun(), trojan_support::DEADLINE, |packet| ipv4_udp_payload(packet).is_some_and(|p| p.get(..2) == Some(&0x7262_u16.to_be_bytes()))).await;
        let response = ipv4_udp_payload(&reply).unwrap();
        assert_eq!(dns_response_answer_ipv4(response), Some(Ipv4Addr::LOCALHOST));
        assert_ipv4_udp_packet(&reply, anchor, 53, client_ip, 53044, response);
        assert_eq!(protector.0.load(Ordering::SeqCst), 1);
        assert_eq!(upstream_probe.snapshot().len(), 1);
        core.stop().await.unwrap();

        // IPOnDemand forces a managed lookup through the selected protocol. The selected
        // Freedom TCP route then consumes the answer locally.
        json["outbounds"].as_array_mut().unwrap().push(serde_json::json!({"tag":"direct","protocol":"freedom"}));
        json["routing"] = serde_json::json!({"domainStrategy":"IPOnDemand", "rules":[{"type":"field","network":"tcp","ip":["127.0.0.1"],"outboundTag":"direct"}]});
        let (_, second_protector, _, dialer) = server.core();
        let mut managed = Core::with_transport_dialer_and_tun_options(parse_xray_json(&json.to_string()).unwrap().config, dialer, TunRuntimeOptions { dns_bootstrap: DnsBootstrapMode::StaticOnly, ..Default::default() }).unwrap();
        managed.start().await.unwrap();
        let (mut tcp, _) = trojan_support::socks(managed.inbound_addr(Some("socks-in")).unwrap(), 1, "lookup-trojan.example", echo_address.port()).await;
        trojan_support::echo(&mut tcp, b"routed managed dns").await;
        assert_eq!(second_protector.0.load(Ordering::SeqCst), 2);
        assert!(upstream_probe.snapshot().len() >= 2);
        managed.stop().await.unwrap();
        upstream.stop().await;
    }).await.unwrap();
}

#[tokio::test]
#[ignore = "requires pinned reference; use protocol interop scripts"]
async fn trojan_runtime_tun_tcp_udp_and_host_close() {
    tun_tcp_udp_and_host_close(reference("trojan", "raw").await, false).await;
}

#[tokio::test]
#[ignore = "requires pinned reference; use protocol interop scripts"]
async fn trojan_runtime_tun_dns_wire_and_managed_destination_lookup() {
    tun_dns_wire_and_managed_destination_lookup(reference("trojan", "raw").await, false).await;
}

#[tokio::test]
#[ignore = "requires pinned reference; use protocol interop scripts"]
async fn shadowsocks_runtime_tun_tcp_udp_and_host_close() {
    tun_tcp_udp_and_host_close(reference("shadowsocks", "raw").await, false).await;
}

#[tokio::test]
#[ignore = "requires pinned reference; use protocol interop scripts"]
async fn shadowsocks_runtime_tun_dns_wire_and_managed_destination_lookup() {
    tun_dns_wire_and_managed_destination_lookup(reference("shadowsocks", "raw").await, false).await;
}

#[tokio::test]
#[ignore = "requires pinned reference; use protocol interop scripts"]
async fn vmess_runtime_tun_tcp_udp_and_host_close() {
    tun_tcp_udp_and_host_close(reference("vmess", "raw").await, false).await;
}

#[tokio::test]
#[ignore = "requires pinned reference; use protocol interop scripts"]
async fn vmess_runtime_tun_dns_wire_and_managed_destination_lookup() {
    tun_dns_wire_and_managed_destination_lookup(reference("vmess", "raw").await, false).await;
}

#[tokio::test]
#[ignore = "requires pinned Xray; use check-mux-interop.sh"]
async fn mux_runtime_tun_tcp_udp_and_host_close() {
    for protocol in ["trojan", "shadowsocks", "vmess"] {
        for carrier in ["raw", "grpc", "xhttp"] {
            eprintln!("Mux TUN {protocol}/{carrier}: tcp_udp_and_host_close");
            tun_tcp_udp_and_host_close(reference(protocol, carrier).await, true).await;
        }
    }
}

#[tokio::test]
#[ignore = "requires pinned Xray; use check-mux-interop.sh"]
async fn mux_runtime_tun_dns_wire_and_managed_destination_lookup() {
    for protocol in ["trojan", "shadowsocks", "vmess"] {
        for carrier in ["raw", "grpc", "xhttp"] {
            eprintln!("Mux TUN {protocol}/{carrier}: dns_wire_and_managed_destination_lookup");
            tun_dns_wire_and_managed_destination_lookup(reference(protocol, carrier).await, true)
                .await;
        }
    }
}
