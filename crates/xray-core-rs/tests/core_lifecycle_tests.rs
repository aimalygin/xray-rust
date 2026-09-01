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
    Core, CoreError, CoreState, OutboundNodeKind, TunRuntimeOptions, TunRuntimeProfile,
};
use xray_transport::{SystemDnsResolver, TransportDialer};

fn runtime_config() -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![OutboundConfig {
            tag: Some("proxy".to_owned()),
            proxy_settings: None,
            stream: StreamSettings {
                network: Network::Tcp,
                transport: StreamTransport::Raw,
                security: StreamSecurity::None,
                quic_params: None,
                socket_options: None,
            },
            settings: OutboundSettings::Vless(VlessOutboundSettings {
                server: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                port: 9,
                users: vec![VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: "none".to_owned(),
                    flow: None,
                    level: 0,
                }],
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
        tag: Some("proxy-b".to_owned()),
        proxy_settings: None,
        stream: StreamSettings {
            network: Network::Tcp,
            transport: StreamTransport::Raw,
            security: StreamSecurity::None,
            quic_params: None,
            socket_options: None,
        },
        settings: OutboundSettings::Freedom,
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
