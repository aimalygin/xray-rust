use std::net::{IpAddr, Ipv4Addr};
use xray_routing::{Network, Session, StaticRouter, Target, TargetAddr};

#[test]
fn static_router_uses_default_outbound() {
    let router = StaticRouter::new("proxy");
    let session = Session::new(
        "socks-in",
        Target::new(
            TargetAddr::Domain("example.com".to_owned()),
            443,
            Network::Tcp,
        ),
    );

    assert_eq!(router.pick_outbound(&session).unwrap(), "proxy");
}

#[test]
fn target_preserves_ip_address() {
    let target = Target::new(
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        8080,
        Network::Tcp,
    );

    assert_eq!(target.port, 8080);
}
