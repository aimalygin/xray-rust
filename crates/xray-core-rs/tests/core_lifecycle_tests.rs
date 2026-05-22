use std::net::{IpAddr, Ipv4Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use uuid::Uuid;
use xray_config::{
    CoreConfig, InboundConfig, InboundProtocol, Network, OutboundConfig, OutboundSettings,
    RoutingConfig, StreamSecurity, StreamSettings, TargetAddr, VlessOutboundSettings, VlessUser,
};
use xray_core_rs::{Core, CoreError, CoreState};

fn runtime_config() -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks,
            listen: "127.0.0.1".to_owned(),
            port: 0,
        }],
        outbounds: vec![OutboundConfig {
            tag: Some("proxy".to_owned()),
            stream: StreamSettings {
                network: Network::Tcp,
                security: StreamSecurity::None,
            },
            settings: OutboundSettings::Vless(VlessOutboundSettings {
                server: TargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                port: 9,
                users: vec![VlessUser {
                    id: Uuid::parse_str("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap(),
                    encryption: "none".to_owned(),
                    flow: None,
                }],
            }),
        }],
        default_outbound_tag: None,
        routing: RoutingConfig::default(),
    }
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
