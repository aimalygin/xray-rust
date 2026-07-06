use std::net::IpAddr;

use xray_config::SniffingDestination;
use xray_routing::{Network, Target, TargetAddr as RoutingTargetAddr};

use crate::{RuntimeLogger, TcpOutbound, UdpOutbound};

pub(crate) struct RouteDecisionLog<'a> {
    pub(crate) inbound_tag: Option<&'a str>,
    pub(crate) network: Network,
    pub(crate) original_target: &'a Target,
    pub(crate) sniffed_protocol: Option<SniffingDestination>,
    pub(crate) route_target: &'a Target,
    pub(crate) dial_target: &'a Target,
    pub(crate) selected_outbound: &'a str,
}

pub(crate) fn log_route_decision(logger: &RuntimeLogger, event: RouteDecisionLog<'_>) {
    logger.debug(|| route_decision_message(&event));
}

pub(crate) fn tcp_outbound_label(outbound: &TcpOutbound) -> &'static str {
    match outbound {
        TcpOutbound::Freedom => "freedom",
        TcpOutbound::Vless(_) => "vless",
    }
}

pub(crate) fn udp_outbound_label(outbound: &UdpOutbound) -> &'static str {
    match outbound {
        UdpOutbound::Freedom => "freedom",
        UdpOutbound::Vless(_) => "vless",
    }
}

pub(crate) fn log_access_accepted(
    logger: &RuntimeLogger,
    source: &str,
    target: &Target,
    outbound: &str,
) {
    logger.access(|| {
        format!(
            "from {source} accepted {} outbound={outbound}",
            target_label(target)
        )
    });
}

pub(crate) fn log_access_rejected(
    logger: &RuntimeLogger,
    source: &str,
    target: &Target,
    reason: impl std::fmt::Display,
) {
    logger.access(|| {
        format!(
            "from {source} rejected {} reason={reason}",
            target_label(target)
        )
    });
}

fn route_decision_message(event: &RouteDecisionLog<'_>) -> String {
    format!(
        "Debug routeDecision inbound={} network={} original_target={} sniffed_protocol={} sniffed_domain={} route_target={} dial_target={} selected_outbound={}",
        event.inbound_tag.unwrap_or("untagged"),
        network_label(event.network),
        target_label(event.original_target),
        sniffed_protocol_label(event.sniffed_protocol),
        sniffed_domain_label(event),
        target_label(event.route_target),
        target_label(event.dial_target),
        event.selected_outbound,
    )
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Tcp => "tcp",
        Network::Udp => "udp",
    }
}

fn sniffed_protocol_label(protocol: Option<SniffingDestination>) -> &'static str {
    match protocol {
        Some(SniffingDestination::Http) => "http",
        Some(SniffingDestination::Tls) => "tls",
        Some(SniffingDestination::Quic) => "quic",
        None => "none",
    }
}

fn sniffed_domain_label(event: &RouteDecisionLog<'_>) -> String {
    if event.sniffed_protocol.is_none() {
        return "none".to_owned();
    }
    match &event.route_target.addr {
        RoutingTargetAddr::Domain(domain) => domain.clone(),
        RoutingTargetAddr::Ip(_) => "none".to_owned(),
    }
}

pub(crate) fn target_label(target: &Target) -> String {
    match &target.addr {
        RoutingTargetAddr::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", target.port),
        RoutingTargetAddr::Ip(ip) => format!("{ip}:{}", target.port),
        RoutingTargetAddr::Domain(domain) => format!("{domain}:{}", target.port),
    }
}

#[cfg(test)]
mod tests {
    use xray_config::SniffingDestination;
    use xray_routing::{Network, Target, TargetAddr};

    use super::*;

    #[test]
    fn route_decision_message_includes_sniffed_route_and_outbound() {
        let original = Target::new(
            TargetAddr::Ip("37.203.35.22".parse().unwrap()),
            443,
            Network::Udp,
        );
        let route_target = Target::new(
            TargetAddr::Domain("www.tiktok.com".to_owned()),
            443,
            Network::Udp,
        );
        let event = RouteDecisionLog {
            inbound_tag: Some("inbound_49783"),
            network: Network::Udp,
            original_target: &original,
            sniffed_protocol: Some(SniffingDestination::Quic),
            route_target: &route_target,
            dial_target: &original,
            selected_outbound: "vless",
        };

        assert_eq!(
            route_decision_message(&event),
            "Debug routeDecision inbound=inbound_49783 network=udp original_target=37.203.35.22:443 sniffed_protocol=quic sniffed_domain=www.tiktok.com route_target=www.tiktok.com:443 dial_target=37.203.35.22:443 selected_outbound=vless"
        );
    }

    #[test]
    fn log_route_decision_writes_to_runtime_error_log() {
        let dir = unique_temp_dir("xray-route-log");
        let logger = crate::RuntimeLogger::new(crate::RuntimeLogConfig::directory(&dir))
            .expect("runtime logger should open files");
        let original = Target::new(
            TargetAddr::Ip("37.203.35.22".parse().unwrap()),
            443,
            Network::Udp,
        );
        let route_target = Target::new(
            TargetAddr::Domain("www.tiktok.com".to_owned()),
            443,
            Network::Udp,
        );
        let event = RouteDecisionLog {
            inbound_tag: Some("inbound_49783"),
            network: Network::Udp,
            original_target: &original,
            sniffed_protocol: Some(SniffingDestination::Quic),
            route_target: &route_target,
            dial_target: &original,
            selected_outbound: "vless",
        };

        log_route_decision(&logger, event);
        drop(logger);

        let error_log =
            std::fs::read_to_string(dir.join("xray-error.log")).expect("error log should exist");
        assert!(error_log.contains("Debug routeDecision"));
        assert!(error_log.contains("sniffed_domain=www.tiktok.com"));
    }

    #[test]
    fn log_access_accepted_writes_to_runtime_access_log() {
        let dir = unique_temp_dir("xray-access-log");
        let logger = crate::RuntimeLogger::new(crate::RuntimeLogConfig::directory(&dir))
            .expect("runtime logger should open files");
        let target = Target::new(
            TargetAddr::Domain("speedtest.example".to_owned()),
            443,
            Network::Tcp,
        );

        log_access_accepted(&logger, "tun", &target, "proxy");
        drop(logger);

        let access_log =
            std::fs::read_to_string(dir.join("xray-access.log")).expect("access log should exist");
        assert!(access_log.contains("from tun accepted speedtest.example:443 outbound=proxy"));
    }

    #[test]
    fn log_access_rejected_writes_to_runtime_access_log() {
        let dir = unique_temp_dir("xray-access-reject-log");
        let logger = crate::RuntimeLogger::new(crate::RuntimeLogConfig::directory(&dir))
            .expect("runtime logger should open files");
        let target = Target::new(
            TargetAddr::Domain("speedtest.example".to_owned()),
            443,
            Network::Udp,
        );

        log_access_rejected(&logger, "tun", &target, "XTLS rejected UDP/443 traffic");
        drop(logger);

        let access_log =
            std::fs::read_to_string(dir.join("xray-access.log")).expect("access log should exist");
        assert!(access_log.contains(
            "from tun rejected speedtest.example:443 reason=XTLS rejected UDP/443 traffic"
        ));
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }
}
