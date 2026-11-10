use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use uuid::Uuid;
use xray_config::{
    CoreConfig, DnsFakeIpConfig, InboundConfig, InboundProtocol, IpCidr, Network, OutboundConfig,
    OutboundProxySettings, OutboundSettings, RoutingBalancer, RoutingBalancerStrategy,
    RoutingConfig, StreamSecurity, StreamSettings, StreamTransport, TargetAddr,
    VlessOutboundSettings, VlessUser,
};
use xray_core_rs::{
    Core, CoreError, CoreState, OutboundNodeKind, TunMtu, TunRuntimeOptions, TunRuntimeProfile,
};
use xray_transport::{SystemDnsResolver, TransportDialer};

fn runtime_config() -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks(Default::default()),
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![OutboundConfig {
            mux: None,
            tag: Some("proxy".to_owned()),
            proxy_settings: None,
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                tcp_fragment: None,
                tcp_header_custom: None,
                udp_header_custom: None,
                tcp_sudoku: None,
                tcp_xmc: None,
                udp_xdns: None,
                udp_realm: None,
                udp_xicmp: None,
                udp_salamander: None,
                udp_sudoku: None,
                udp_noise: None,
                socket_options: None,
            },
            settings: OutboundSettings::Vless(VlessOutboundSettings {
                server: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                port: 9,
                users: vec![VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: Default::default(),
                    flow: None,
                    level: 0,
                    vision_seed: xray_proxy::vless::DEFAULT_VISION_SEED,
                    pre_connections: 0,
                }],
                reverse: None,
            }),
        }],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
        observatory: None,
        dns: Default::default(),
        policy: Default::default(),
    }
}

fn tun_runtime_config() -> CoreConfig {
    let mut config = runtime_config();
    config.inbounds = vec![InboundConfig {
        tag: Some("tun-in".to_owned()),
        protocol: InboundProtocol::Tun,
        listen: "127.0.0.1".to_owned(),
        port: 0,
        allow_unauthenticated_lan: false,
        sniffing: None,
        user_level: None,
    }];
    config
}

#[test]
fn core_owns_one_outbound_graph_and_factory_before_start() {
    let core = Core::new(runtime_config()).unwrap();

    assert_eq!(core.outbound_graph().nodes().len(), 1);
    assert_eq!(
        core.outbound_graph().nodes()[0].kind(),
        OutboundNodeKind::Vless
    );
    assert!(std::ptr::eq(
        core.outbound_graph(),
        core.outbound_factory().graph()
    ));
}

#[test]
fn core_rejects_an_invalid_outbound_proxy_graph_before_start() {
    let mut config = runtime_config();
    config.outbounds[0].proxy_settings = Some(OutboundProxySettings {
        tag: "missing".to_owned(),
        transport_layer: true,
    });

    assert!(matches!(
        Core::new(config),
        Err(CoreError::OutboundProxyGraph(_))
    ));
}

#[tokio::test]
async fn core_selector_override_is_available_before_and_during_runtime() {
    let mut config = runtime_config();
    config.outbounds[0].tag = Some("proxy-a".to_owned());
    config.outbounds.push(OutboundConfig {
        mux: None,
        tag: Some("proxy-b".to_owned()),
        proxy_settings: None,
        stream: StreamSettings {
            network: Network::Tcp,
            transport: StreamTransport::Raw,
            security: StreamSecurity::None,
            quic_params: None,
            tcp_fragment: None,
            tcp_header_custom: None,
            udp_header_custom: None,
            tcp_sudoku: None,
            tcp_xmc: None,
            udp_xdns: None,
            udp_realm: None,
            udp_xicmp: None,
            udp_salamander: None,
            udp_sudoku: None,
            udp_noise: None,
            socket_options: None,
        },
        settings: OutboundSettings::Freedom(Default::default()),
    });
    config.routing.balancers = vec![RoutingBalancer {
        tag: "automatic".to_owned(),
        selectors: vec!["proxy-".to_owned()],
        strategy: RoutingBalancerStrategy::RoundRobin,
        fallback_tag: None,
    }];
    let mut core = Core::new(config).unwrap();

    assert_eq!(
        core.outbound_selection_snapshot().groups[0].candidates,
        vec!["proxy-a", "proxy-b"]
    );
    assert_eq!(
        core.set_outbound_selector_override("automatic", "proxy-b")
            .unwrap(),
        1
    );
    core.start().await.unwrap();
    assert_eq!(
        core.outbound_selection_snapshot().groups[0]
            .override_tag
            .as_deref(),
        Some("proxy-b")
    );
    assert_eq!(
        core.clear_outbound_selector_override("automatic").unwrap(),
        2
    );
    assert_eq!(
        core.outbound_selection_snapshot().groups[0].override_tag,
        None
    );
    core.stop().await.unwrap();
}

#[tokio::test]
async fn core_starts_and_stops_from_config() {
    let mut core = Core::new(runtime_config()).unwrap();

    assert_eq!(core.state(), CoreState::Created);
    core.start().await.unwrap();
    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
    assert_eq!(core.state(), CoreState::Stopped);
}

#[test]
fn core_rejects_programmatic_fake_ip_pool_with_only_reserved_addresses() {
    let mut config = runtime_config();
    config.dns.fake_ip = Some(DnsFakeIpConfig {
        enabled: true,
        ipv4_pool: IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 30).unwrap(),
        pool_size: 1,
        ttl: 60,
    });

    assert!(matches!(
        Core::new(config),
        Err(CoreError::InvalidFakeIpConfiguration)
    ));
}

#[test]
fn core_rejects_programmatic_fake_ip_with_zero_ttl() {
    let mut config = runtime_config();
    config.dns.fake_ip = Some(DnsFakeIpConfig {
        enabled: true,
        ipv4_pool: IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 19, 0, 0)), 16).unwrap(),
        pool_size: 1024,
        ttl: 0,
    });

    assert!(matches!(
        Core::new(config),
        Err(CoreError::InvalidFakeIpConfiguration)
    ));
}

#[test]
fn tun_mtu_rejects_values_outside_its_range_instead_of_clamping() {
    assert_eq!(TunMtu::default().get(), 1500);
    assert_eq!(TunRuntimeOptions::default().mtu, TunMtu::default());
    for mtu in [TunMtu::MIN, 1500, 4000, TunMtu::MAX] {
        assert_eq!(TunMtu::new(mtu).unwrap().get(), mtu as usize);
    }
    for mtu in [0, 576, TunMtu::MIN - 1, TunMtu::MAX + 1, 65_535, u32::MAX] {
        assert!(matches!(TunMtu::new(mtu), Err(CoreError::InvalidTunMtu(m)) if m == mtu));
    }
}

#[test]
fn every_tun_profile_keeps_1500_and_takes_the_host_mtu() {
    for profile in [
        TunRuntimeProfile::Default,
        TunRuntimeProfile::Mobile,
        TunRuntimeProfile::MobilePlus,
        TunRuntimeProfile::Desktop,
        TunRuntimeProfile::LowMemory,
        TunRuntimeProfile::Throughput,
    ] {
        let options = TunRuntimeOptions::with_profile(profile);
        assert_eq!(options.tun_queue_options().mtu, 1500, "{profile:?}");
        let jumbo = TunRuntimeOptions {
            mtu: TunMtu::new(9000).unwrap(),
            ..options
        };
        assert_eq!(jumbo.tun_queue_options().mtu, 9000, "{profile:?}");
        let core = Core::with_runtime_dependencies_and_tun_options(
            tun_runtime_config(),
            Arc::new(SystemDnsResolver),
            Arc::new(TransportDialer::system().unwrap()),
            jumbo,
        )
        .unwrap();
        assert_eq!(core.tun().mtu(), 9000, "{profile:?}");
    }
}

#[tokio::test]
async fn core_applies_low_memory_tun_queue_profile() {
    let core = Core::with_runtime_dependencies_and_tun_options(
        tun_runtime_config(),
        Arc::new(SystemDnsResolver),
        Arc::new(TransportDialer::system().unwrap()),
        TunRuntimeOptions::with_profile(TunRuntimeProfile::LowMemory),
    )
    .unwrap();

    let stats = core.tun().stats().await;

    assert_eq!(stats.inbound_queue_depth, 256);
    assert_eq!(stats.outbound_queue_depth, 512);
}

#[tokio::test]
async fn core_applies_throughput_tun_queue_profile() {
    let core = Core::with_runtime_dependencies_and_tun_options(
        tun_runtime_config(),
        Arc::new(SystemDnsResolver),
        Arc::new(TransportDialer::system().unwrap()),
        TunRuntimeOptions::with_profile(TunRuntimeProfile::Throughput),
    )
    .unwrap();

    let stats = core.tun().stats().await;

    assert_eq!(stats.inbound_queue_depth, 2048);
    assert_eq!(stats.outbound_queue_depth, 8192);
}

#[tokio::test]
async fn core_applies_mobile_plus_tun_queue_profile() {
    let core = Core::with_runtime_dependencies_and_tun_options(
        tun_runtime_config(),
        Arc::new(SystemDnsResolver),
        Arc::new(TransportDialer::system().unwrap()),
        TunRuntimeOptions::with_profile(TunRuntimeProfile::MobilePlus),
    )
    .unwrap();

    let stats = core.tun().stats().await;

    assert_eq!(stats.inbound_queue_depth, 2048);
    assert_eq!(stats.outbound_queue_depth, 8192);
}

#[tokio::test]
async fn core_starts_and_stops_with_only_tun_inbound() {
    let mut core = Core::new(tun_runtime_config()).unwrap();

    core.start().await.unwrap();
    assert_eq!(core.state(), CoreState::Running);
    assert_eq!(core.inbound_addr(Some("tun-in")), None);

    core.stop().await.unwrap();
    assert_eq!(core.state(), CoreState::Stopped);
}

#[tokio::test]
async fn stopped_core_cannot_restart() {
    let mut core = Core::new(runtime_config()).unwrap();

    core.start().await.unwrap();
    core.stop().await.unwrap();

    assert!(matches!(core.start().await, Err(CoreError::AlreadyStopped)));
    assert_eq!(core.state(), CoreState::Stopped);
}

#[tokio::test]
async fn running_core_cannot_start_again() {
    let mut core = Core::new(runtime_config()).unwrap();

    core.start().await.unwrap();

    assert!(matches!(core.start().await, Err(CoreError::AlreadyRunning)));
    assert_eq!(core.state(), CoreState::Running);
}

#[tokio::test]
async fn core_start_binds_socks_listener_and_exposes_addr() {
    let mut core = Core::new(runtime_config()).unwrap();

    core.start().await.unwrap();
    let addr = core.inbound_addr(Some("socks-in")).unwrap();

    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(addr.port(), 0);

    core.stop().await.unwrap();
}

#[tokio::test]
async fn programmatic_wildcard_listener_requires_explicit_lan_opt_in() {
    let mut config = runtime_config();
    config.inbounds[0].listen = "0.0.0.0".to_owned();
    let mut core = Core::new(config).unwrap();

    assert!(matches!(
        core.start().await,
        Err(CoreError::UnauthenticatedLanExposure)
    ));
    assert_eq!(core.state(), CoreState::Created);
}

#[tokio::test]
async fn explicit_lan_opt_in_allows_programmatic_wildcard_listener() {
    let mut config = runtime_config();
    config.inbounds[0].listen = "0.0.0.0".to_owned();
    config.inbounds[0].allow_unauthenticated_lan = true;
    let mut core = Core::new(config).unwrap();

    core.start().await.unwrap();
    assert!(core
        .inbound_addr(Some("socks-in"))
        .is_some_and(|addr| addr.ip().is_unspecified()));
    core.stop().await.unwrap();
}

#[tokio::test]
async fn hostname_listener_is_checked_after_resolution() {
    let mut config = runtime_config();
    config.inbounds[0].listen = "localhost".to_owned();
    let mut core = Core::new(config).unwrap();

    core.start().await.unwrap();
    assert!(core
        .inbound_addr(Some("socks-in"))
        .is_some_and(|addr| addr.ip().is_loopback()));
    core.stop().await.unwrap();
}

#[tokio::test]
async fn core_start_fails_without_supported_socks_inbound() {
    let mut config = runtime_config();
    config.inbounds.clear();
    let mut core = Core::new(config).unwrap();

    assert!(matches!(
        core.start().await,
        Err(CoreError::NoSupportedInbound)
    ));
    assert_eq!(core.state(), CoreState::Created);
}

#[tokio::test]
async fn core_stop_closes_idle_accepted_socks_connections() {
    let mut core = Core::new(runtime_config()).unwrap();

    core.start().await.unwrap();
    let addr = core.inbound_addr(Some("socks-in")).unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();

    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);

    core.stop().await.unwrap();

    let mut one_byte = [0; 1];
    let read = timeout(Duration::from_millis(200), client.read(&mut one_byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);
}

/// Every VLESS reverse proxy configuration the parser takes builds a core,
/// except where a case records the core's refusal.
#[tokio::test]
async fn reverse_profiles_xray_accepts_build_a_core() {
    use serde_json::Value;
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/reverse/config-verdicts.json"
    ))
    .unwrap();
    let mut mismatches = Vec::new();
    let mut built = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let Ok(parsed) = xray_config::parse_xray_json(&case["config"].to_string()) else {
            continue;
        };
        let refusal = case.get("core").and_then(Value::as_str);
        match (Core::new(parsed.config), refusal) {
            (Ok(_), None) => built += 1,
            (Err(error), Some(expected)) if error.to_string().contains(expected) => {}
            (Ok(_), Some(expected)) => mismatches.push(format!(
                "{}: built, expected the core to refuse with {expected:?}",
                case["name"]
            )),
            (Err(error), _) => mismatches.push(format!("{}: {error}", case["name"])),
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    assert!(built >= 20, "only {built} cases built a core");
}

/// Every MASQUE profile the configuration takes, as `xray run -test` does,
/// also builds a core, except where a case records the core's refusal:
/// the verdicts below the configuration are Xray-core's too.
#[tokio::test]
async fn masque_profiles_xray_accepts_build_a_core() {
    use serde_json::{json, Value};
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/masque/config-verdicts.json"
    ))
    .unwrap();
    let mut mismatches = Vec::new();
    let mut built = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let mut outbounds = vec![case["outbound"].clone()];
        if let Some(extra) = case["extraOutbounds"].as_array() {
            outbounds.extend(extra.iter().cloned());
        }
        let raw = json!({"outbounds": outbounds}).to_string();
        let Ok(parsed) = xray_config::parse_xray_json(&raw) else {
            continue;
        };
        let refusal = case.get("core").and_then(Value::as_str);
        match (Core::new(parsed.config), refusal) {
            (Ok(_), None) => built += 1,
            (Err(error), Some(expected)) if error.to_string().contains(expected) => {}
            (Ok(_), Some(expected)) => mismatches.push(format!(
                "{}: built, expected the core to refuse with {expected:?}",
                case["name"]
            )),
            (Err(error), _) => mismatches.push(format!("{}: {error}", case["name"])),
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    assert!(built > 50, "only {built} cases built a core");
}

/// Every FinalMask filter case the configuration takes builds a core, on
/// every carrier that takes masks and every outbound that dials none:
/// `tests/fixtures/filter/config-verdicts.json`.
#[tokio::test]
async fn filter_cases_the_parser_takes_build_a_core() {
    use serde_json::{json, Value};
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/filter/config-verdicts.json"
    ))
    .unwrap();
    let mut mismatches = Vec::new();
    let mut built = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let raw = json!({"outbounds": [case["outbound"]]}).to_string();
        let Ok(parsed) = xray_config::parse_xray_json(&raw) else {
            continue;
        };
        let refusal = case.get("core").and_then(Value::as_str);
        match (Core::new(parsed.config), refusal) {
            (Ok(_), None) => built += 1,
            (Err(error), Some(expected)) if error.to_string().contains(expected) => {}
            (Ok(_), Some(expected)) => mismatches.push(format!(
                "{}: built, expected the core to refuse with {expected:?}",
                case["name"]
            )),
            (Err(error), _) => mismatches.push(format!("{}: {error}", case["name"])),
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    assert!(built >= 50, "only {built} cases built a core");
}

/// Every `disableChromeParrot` case Xray-core accepts builds a core here too,
/// with ChromeParrot on or off: `tests/fixtures/chrome-parrot/config-verdicts.json`.
#[tokio::test]
async fn chrome_parrot_cases_xray_accepts_build_a_core() {
    use serde_json::{json, Value};
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/chrome-parrot/config-verdicts.json"
    ))
    .unwrap();
    let mut built = 0;
    for case in corpus["cases"].as_array().unwrap() {
        if case["xray"] != "ok" {
            continue;
        }
        let raw = json!({"outbounds": [case["outbound"]]}).to_string();
        let parsed = xray_config::parse_xray_json(&raw)
            .unwrap_or_else(|error| panic!("{}: {error:?}", case["name"]));
        Core::new(parsed.config).unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
        built += 1;
    }
    assert!(built >= 20, "only {built} cases built a core");
}

/// An XDRIVE outbound never looks its server address up, as Xray-core's
/// dial never does: its sessions meet the server in the storage. A flow
/// through the SOCKS inbound announces a session and stores the VLESS
/// request in its uplink, with no server there to answer.
#[tokio::test(flavor = "multi_thread")]
async fn xdrive_flows_announce_sessions_without_resolving_the_server() {
    use serde_json::json;
    use xray_transport::{DnsResolver, TransportError};

    struct Refuses;
    #[async_trait::async_trait]
    impl DnsResolver for Refuses {
        async fn resolve(
            &self,
            domain: &str,
            _port: u16,
        ) -> Result<std::net::SocketAddr, TransportError> {
            panic!("an XDRIVE outbound looked up {domain}");
        }
    }

    let folder = std::env::temp_dir().join(format!("xray-rust-xdrive-core-{}", Uuid::new_v4()));
    let config = json!({
        "inbounds": [{"protocol": "socks", "tag": "socks-in", "listen": "127.0.0.1", "port": 0}],
        "outbounds": [{"protocol": "vless",
            "settings": {"address": "xdrive.invalid", "port": 443,
                "id": "27848739-7e62-4138-9fd3-098a63964b6b",
                "encryption": "mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I"},
            "streamSettings": {"network": "xdrive", "xdriveSettings": {"service": "local",
                "remoteFolder": folder.to_str().unwrap(), "flushIntervalMs": 5}},
            "mux": {"enabled": true}}]
    });
    let parsed = xray_config::parse_xray_json(&config.to_string()).unwrap();
    let mut core = Core::with_runtime_dependencies(
        parsed.config,
        Arc::new(Refuses),
        Arc::new(TransportDialer::system().unwrap()),
    )
    .unwrap();
    core.start().await.unwrap();
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await.unwrap();
    client
        .write_all(&[5, 1, 0, 1, 192, 0, 2, 1, 0, 80])
        .await
        .unwrap();
    let _ = client.write_all(b"GET / HTTP/1.1\r\n\r\n").await;
    let uplink_segments = || -> usize {
        let Ok(sessions) = std::fs::read_dir(folder.join("streams")) else {
            return 0;
        };
        sessions
            .filter_map(Result::ok)
            .filter_map(|session| std::fs::read_dir(session.path().join("c2s")).ok())
            .flat_map(|entries| entries.filter_map(Result::ok))
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".seg"))
            .count()
    };
    timeout(Duration::from_secs(10), async {
        while uplink_segments() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the flow stored its request");
    let announced = std::fs::read_dir(folder.join("sessions")).unwrap().count();
    assert_eq!(announced, 1);
    drop(client);
    core.stop().await.unwrap();
    let _ = std::fs::remove_dir_all(&folder);
}

/// Every XDRIVE profile Xray-core accepts builds a core, except the
/// refusals the corpus records: the services not reached yet, and what
/// Xray-core accepts only to fail every dial.
#[tokio::test(flavor = "multi_thread")]
async fn xdrive_profiles_xray_accepts_build_a_core() {
    use serde_json::{json, Value};
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/xdrive/config-verdicts.json"
    ))
    .unwrap();
    let mut mismatches = Vec::new();
    let mut built = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let mut outbounds = vec![case["outbound"].clone()];
        if let Some(extra) = case["extraOutbounds"].as_array() {
            outbounds.extend(extra.iter().cloned());
        }
        let raw = json!({"outbounds": outbounds}).to_string();
        let Ok(parsed) = xray_config::parse_xray_json(&raw) else {
            continue;
        };
        let refusal = case.get("core").and_then(Value::as_str);
        match (Core::new(parsed.config), refusal) {
            (Ok(_), None) => built += 1,
            (Err(error), Some(expected)) if error.to_string().contains(expected) => {}
            (Ok(_), Some(expected)) => mismatches.push(format!(
                "{}: built, expected the core to refuse with {expected:?}",
                case["name"]
            )),
            (Err(error), _) => mismatches.push(format!("{}: {error}", case["name"])),
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    assert!(built >= 75, "only {built} cases built a core");
}

/// Freedom and WireGuard take UDP masks, as Xray-core's `FinalMask.DialUDP`
/// wraps their sockets. WireGuard's take one peer: a second fails the start.
#[test]
fn freedom_and_one_peer_wireguard_build_a_core_under_udp_masks() {
    use serde_json::json;
    let masks = json!([
        {"type": "noise", "settings": {"noise": [{"type": "str", "packet": "synthetic"}]}},
        {"type": "salamander", "settings": {"password": "synthetic-salamander"}}
    ]);
    let peer = |public: &str, port: u16| {
        json!({"publicKey": public, "endpoint": format!("127.0.0.1:{port}"),
            "allowedIPs": ["0.0.0.0/0"]})
    };
    let wireguard = |peers: serde_json::Value| {
        json!({"outbounds": [{"protocol": "wireguard", "tag": "proxy",
            "settings": {"secretKey": "42".repeat(32), "address": ["10.44.0.2/32"],
                "mtu": 1420, "peers": peers},
            "streamSettings": {"finalmask": {"udp": masks}}}]})
    };
    let core = |config: serde_json::Value| {
        xray_core_rs::Core::new(
            xray_config::parse_xray_json(&config.to_string())
                .unwrap()
                .config,
        )
    };
    let freedom = json!({"outbounds": [{"protocol": "freedom", "tag": "direct",
        "streamSettings": {"finalmask": {"udp": masks}}}]});
    assert!(core(freedom).is_ok());
    let one = json!([peer(&"53".repeat(32), 51820)]);
    assert!(core(wireguard(one)).is_ok());
    let two = json!([peer(&"53".repeat(32), 51820), peer(&"54".repeat(32), 51821)]);
    let mut unmasked = wireguard(two.clone());
    unmasked["outbounds"][0]
        .as_object_mut()
        .unwrap()
        .remove("streamSettings");
    assert!(core(unmasked).is_ok(), "two peers build without masks");
    assert!(matches!(
        core(wireguard(two)),
        Err(xray_core_rs::CoreError::UnsupportedOutboundNetwork)
    ));
}
