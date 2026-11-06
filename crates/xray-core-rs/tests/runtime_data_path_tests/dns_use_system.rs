//! `dns.queryStrategy: "UseSystem"` from the profile to the hijacked answer.
//!
//! A scripted route probe stands in for the system's routes, so each case
//! sets which families are routed. Xray-core's `checkSystem` narrows every
//! lookup to them; so do the destination resolver and the fake IP mapper.

use super::*;
use xray_transport::{RouteFamilies, RouteProbe};

#[derive(Debug)]
struct ScriptedRoutes(Mutex<RouteFamilies>);

impl ScriptedRoutes {
    fn new(ipv4: bool, ipv6: bool) -> Arc<Self> {
        Arc::new(Self(Mutex::new(RouteFamilies { ipv4, ipv6 })))
    }

    fn set(&self, ipv4: bool, ipv6: bool) {
        *self.0.lock().unwrap() = RouteFamilies { ipv4, ipv6 };
    }
}

impl RouteProbe for ScriptedRoutes {
    fn families(&self) -> RouteFamilies {
        *self.0.lock().unwrap()
    }
}

/// A core on the TUN profile whose dialer reports `routes`.
async fn core_with_routes(config: CoreConfig, routes: Arc<ScriptedRoutes>) -> Core {
    let dialer = TransportDialer::system().unwrap().with_route_probe(routes);
    let mut core = Core::with_transport_dialer_and_tun_options(
        config,
        Arc::new(dialer),
        TunRuntimeOptions::default(),
    )
    .unwrap();
    core.start().await.unwrap();
    core
}

/// Sends `query` through the TUN DNS anchor and returns its response.
async fn hijack(core: &Core, client_port: u16, query: &[u8]) -> Vec<u8> {
    let id = [query[0], query[1]];
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            Ipv4Addr::new(10, 10, 0, 2),
            client_port,
            Ipv4Addr::new(198, 18, 0, 1),
            53,
            query,
        )))
        .await
        .unwrap();
    let packet = poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet).is_some_and(|payload| payload.get(0..2) == Some(&id))
    })
    .await;
    ipv4_udp_payload(&packet).unwrap().to_vec()
}

/// A NOERROR response without answers.
fn is_nodata(response: &[u8]) -> bool {
    response[3] & 0x0f == 0 && response[6..8] == [0, 0]
}

#[tokio::test]
async fn use_system_asks_only_for_the_families_the_system_routes() {
    timeout(Duration::from_secs(4), async {
        let server = spawn_observed_udp_dns_a_server(Ipv4Addr::new(192, 0, 2, 31)).await;
        let probe = server.probe();
        let mut config = runtime_tun_config_with_freedom_outbound();
        config.dns.check_system_routes = true;
        config.dns.servers = vec![DnsServerConfig::Ip(server.addr())];
        let routes = ScriptedRoutes::new(false, true);
        let core = core_with_routes(config, routes.clone()).await;

        // No IPv4 route: the A query is answered empty and never asked.
        let response = hijack(&core, 53_101, &build_dns_a_query(0x3101, "routed.example")).await;
        assert!(is_nodata(&response));
        assert!(probe.snapshot().is_empty());

        // Once IPv4 is routed, the next lookup asks for it.
        routes.set(true, true);
        let response = hijack(&core, 53_102, &build_dns_a_query(0x3102, "routed.example")).await;
        assert_eq!(
            dns_response_answer_ipv4(&response),
            Some(Ipv4Addr::new(192, 0, 2, 31))
        );
        assert_eq!(
            probe
                .snapshot()
                .iter()
                .map(|query| dns_query_record_type(query))
                .collect::<Vec<_>>(),
            [Some(1)]
        );

        // Without an IPv6 route an AAAA query is answered empty, unasked.
        routes.set(true, false);
        let response = hijack(
            &core,
            53_103,
            &build_dns_query(0x3103, "routed.example", 28, 1),
        )
        .await;
        assert!(is_nodata(&response));
        assert_eq!(probe.snapshot().len(), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn use_system_gives_no_fake_ip_without_an_ipv4_route() {
    timeout(Duration::from_secs(4), async {
        let mut config = runtime_tun_config_with_freedom_outbound();
        config.dns.check_system_routes = true;
        config.dns.fake_ip = Some(xray_config::DnsFakeIpConfig {
            enabled: true,
            ipv4_pool: xray_config::IpCidr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)), 15)
                .unwrap(),
            pool_size: 1024,
            ttl: 60,
        });
        let routes = ScriptedRoutes::new(false, true);
        let core = core_with_routes(config, routes.clone()).await;

        let response = hijack(&core, 53_111, &build_dns_a_query(0x3111, "fake.example")).await;
        assert!(is_nodata(&response));

        routes.set(true, false);
        let response = hijack(&core, 53_112, &build_dns_a_query(0x3112, "fake.example")).await;
        let fake = dns_response_answer_ipv4(&response).expect("a fake IPv4 answer");
        assert_eq!(fake.octets()[..1], [198]);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_servers_use_system_passes_it_over_for_an_unrouted_family() {
    timeout(Duration::from_secs(4), async {
        let checking = spawn_observed_udp_dns_a_server(Ipv4Addr::new(192, 0, 2, 41)).await;
        let plain = spawn_observed_udp_dns_a_server(Ipv4Addr::new(192, 0, 2, 42)).await;
        let (checking_probe, plain_probe) = (checking.probe(), plain.probe());
        let mut config = runtime_tun_config_with_freedom_outbound();
        config.dns.servers = vec![
            DnsServerConfig::Policy(Box::new(DnsNameServerConfig {
                endpoint: DnsServerEndpoint::Ip(checking.addr()),
                transport: xray_config::DnsServerTransport::Classic,
                https_path: None,
                domains: Default::default(),
                expected_ips: Default::default(),
                unexpected_ips: Default::default(),
                tag: String::new(),
                timeout_ms: 0,
                skip_fallback: false,
                query_strategy: DnsQueryStrategy::UseIp,
                check_system_routes: true,
                final_query: false,
                client_ip: None,
                policy_key: xray_config::DEFAULT_DNS_POLICY_KEY.to_owned(),
            })),
            DnsServerConfig::Ip(plain.addr()),
        ];
        let routes = ScriptedRoutes::new(false, true);
        let core = core_with_routes(config, routes.clone()).await;

        // The checking server routes no IPv4, so the next one answers A.
        let response = hijack(&core, 53_121, &build_dns_a_query(0x3121, "first.example")).await;
        assert_eq!(
            dns_response_answer_ipv4(&response),
            Some(Ipv4Addr::new(192, 0, 2, 42))
        );
        assert!(checking_probe.snapshot().is_empty());

        routes.set(true, true);
        let response = hijack(&core, 53_122, &build_dns_a_query(0x3122, "second.example")).await;
        assert_eq!(
            dns_response_answer_ipv4(&response),
            Some(Ipv4Addr::new(192, 0, 2, 41))
        );
        assert_eq!(checking_probe.snapshot().len(), 1);
        assert_eq!(plain_probe.snapshot().len(), 1);
    })
    .await
    .unwrap();
}
