use std::net::{IpAddr, Ipv4Addr};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_config::{OutboundSettings, ProxyProtocolVersion};
use xray_transport::DnsLookup;

use super::*;

/// The final rules a freedom outbound with these settings parses to.
fn rules(final_rules: &str) -> Vec<FreedomFinalRule> {
    let raw = format!(
        r#"{{"outbounds": [{{"protocol": "freedom", "settings": {{"finalRules": {final_rules}}}}}]}}"#
    );
    let parsed = xray_config::parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics));
    let OutboundSettings::Freedom(settings) = &parsed.config.outbounds[0].settings else {
        panic!("freedom parses to freedom");
    };
    assert_eq!(settings.proxy_protocol, None::<ProxyProtocolVersion>);
    settings.final_rules.clone()
}

fn address(ip: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::from((ip, port))
}

#[test]
fn the_first_rule_that_applies_decides() {
    let rules = rules(
        r#"[
            {"action": "allow", "ip": ["192.0.2.1"]},
            {"action": "block", "ip": ["192.0.2.0/24"]},
            {"action": "block", "network": "udp", "port": "53"}
        ]"#,
    );
    // An earlier allow shields an address from a later block.
    assert!(!blocks(&rules, Network::Tcp, address([192, 0, 2, 1], 80)));
    assert!(blocks(&rules, Network::Tcp, address([192, 0, 2, 2], 80)));
    // Network and port narrow the third rule.
    assert!(blocks(&rules, Network::Udp, address([198, 51, 100, 1], 53)));
    assert!(!blocks(
        &rules,
        Network::Tcp,
        address([198, 51, 100, 1], 53)
    ));
    assert!(!blocks(
        &rules,
        Network::Udp,
        address([198, 51, 100, 1], 54)
    ));
    // An IPv4-mapped address matches as IPv4, as Go's addresses do.
    let mapped = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 2).to_ipv6_mapped()), 80);
    assert!(blocks(&rules, Network::Tcp, mapped));
}

#[test]
fn any_blocked_address_blocks_the_connection() {
    let rules = rules(r#"[{"action": "block", "ip": ["192.0.2.2"]}]"#);
    let addresses = [
        address([198, 51, 100, 1], 443),
        address([192, 0, 2, 2], 443),
    ];
    assert!(blocking_rule(&rules, Network::Tcp, addresses).is_some());
    assert!(blocking_rule(&rules, Network::Tcp, [addresses[0]]).is_none());
    assert!(blocking_rule(&rules, Network::Tcp, []).is_none());
}

#[test]
fn block_delay_draws_whole_seconds_from_the_range() {
    let rule = &rules(r#"[{"action": "block", "blockDelay": "3-5"}]"#)[0];
    for _ in 0..64 {
        let delay = block_delay(rule);
        assert!((3..=5).contains(&delay.as_secs()), "{delay:?}");
        assert_eq!(delay.subsec_nanos(), 0);
    }
    let fixed = &rules(r#"[{"action": "block", "blockDelay": 0}]"#)[0];
    assert_eq!(block_delay(fixed), Duration::ZERO);
    let default = &rules(r#"[{"action": "block"}]"#)[0];
    for _ in 0..64 {
        assert!((30..=90).contains(&block_delay(default).as_secs()));
    }
}

#[tokio::test(start_paused = true)]
async fn a_blocked_stream_discards_writes_and_fails_after_the_delay() {
    let mut stream = BlockedStream::new(Duration::from_secs(40));
    stream.write_all(b"swallowed").await.unwrap();
    let started = Instant::now();
    let mut buffer = [0; 8];
    let error = stream.read(&mut buffer).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(started.elapsed(), Duration::from_secs(40));
}

#[tokio::test(start_paused = true)]
async fn a_blocked_stream_ends_when_the_client_is_done() {
    let stream = BlockedStream::new(Duration::from_secs(40));
    let (mut reader, mut writer) = tokio::io::split(stream);
    let started = Instant::now();
    let read = tokio::spawn(async move {
        let mut buffer = [0; 8];
        reader.read(&mut buffer).await
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    writer.shutdown().await.unwrap();
    assert_eq!(read.await.unwrap().unwrap(), 0);
    assert_eq!(started.elapsed(), Duration::from_secs(1));
}

/// Resolves every name to two fixed addresses.
struct TwoAddresses;

#[async_trait]
impl DnsResolver for TwoAddresses {
    async fn resolve(&self, _domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        Ok(address([198, 51, 100, 1], port))
    }

    async fn resolve_all(&self, _domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
        Ok(DnsLookup::new(
            [
                address([198, 51, 100, 1], port),
                address([192, 0, 2, 2], port),
            ],
            None,
        ))
    }
}

#[tokio::test]
async fn udp_destinations_resolve_every_address_only_for_rules() {
    let domain = Target::new(
        TargetAddr::Domain("dual.example".to_owned()),
        53,
        xray_routing::Network::Udp,
    );
    let ip = Target::new(
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
        53,
        xray_routing::Network::Udp,
    );
    let some = rules(r#"[{"action": "block", "ip": ["192.0.2.2"]}]"#);

    let (first, all) = resolve_udp_destination(&domain, &TwoAddresses, &some)
        .await
        .unwrap();
    assert_eq!(first, address([198, 51, 100, 1], 53));
    assert_eq!(
        all,
        [address([198, 51, 100, 1], 53), address([192, 0, 2, 2], 53)]
    );
    assert!(blocking_rule(&some, Network::Udp, all).is_some());

    let (first, all) = resolve_udp_destination(&domain, &TwoAddresses, &[])
        .await
        .unwrap();
    assert_eq!(first, address([198, 51, 100, 1], 53));
    assert!(all.is_empty());

    let (first, all) = resolve_udp_destination(&ip, &TwoAddresses, &some)
        .await
        .unwrap();
    assert_eq!(first, address([192, 0, 2, 9], 53));
    assert_eq!(all, [first]);
}
