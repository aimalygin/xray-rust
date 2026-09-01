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
    match outbound.primary() {
        TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => "freedom",
        TcpOutbound::Vless(_) => "vless",
        TcpOutbound::Chained { .. } => unreachable!("primary outbound is never a chain wrapper"),
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
            "from {} accepted {} outbound={}",
            source_label(source),
            target_label(target),
            safe_outbound_label(outbound)
        )
    });
}

pub(crate) fn log_access_rejected(
    logger: &RuntimeLogger,
    source: &str,
    target: &Target,
    _reason: impl std::fmt::Display,
) {
    logger.access(|| {
        format!(
            "from {} rejected {} reason=<redacted>",
            source_label(source),
            target_label(target)
        )
    });
}

fn source_label(source: &str) -> &'static str {
    if source == "tun" {
        "tun"
    } else {
        "<redacted-source>"
    }
}

fn route_decision_message(event: &RouteDecisionLog<'_>) -> String {
    format!(
        "Debug routeDecision inbound={} network={} original_target={} sniffed_protocol={} sniffed_domain={} route_target={} dial_target={} selected_outbound={}",
        configured_tag_label(event.inbound_tag),
        network_label(event.network),
        target_label(event.original_target),
        sniffed_protocol_label(event.sniffed_protocol),
        sniffed_domain_label(event),
        target_label(event.route_target),
        target_label(event.dial_target),
        safe_outbound_label(event.selected_outbound),
    )
}

pub(crate) fn configured_tag_label(tag: Option<&str>) -> &'static str {
    if tag.is_some() {
        "<configured>"
    } else {
        "untagged"
    }
}

fn safe_outbound_label(label: &str) -> &str {
    match label {
        "freedom" | "vless" | "untagged" | "unselected" | "<configured>" => label,
        _ => "<configured>",
    }
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
        RoutingTargetAddr::Domain(_) => "<redacted-domain>".to_owned(),
        RoutingTargetAddr::Ip(_) => "none".to_owned(),
    }
}

pub(crate) fn target_label(target: &Target) -> String {
    match &target.addr {
        RoutingTargetAddr::Ip(_) => format!("<redacted-ip>:{}", target.port),
        RoutingTargetAddr::Domain(_) => format!("<redacted-domain>:{}", target.port),
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
            TargetAddr::Ip("192.0.2.10".parse().unwrap()),
            443,
            Network::Udp,
        );
        let route_target = Target::new(
            TargetAddr::Domain("video.example".to_owned()),
            443,
            Network::Udp,
        );
        let event = RouteDecisionLog {
            inbound_tag: Some("inbound_49783\nforged=true"),
            network: Network::Udp,
            original_target: &original,
            sniffed_protocol: Some(SniffingDestination::Quic),
            route_target: &route_target,
            dial_target: &original,
            selected_outbound: "vless",
        };

        assert_eq!(
            route_decision_message(&event),
            "Debug routeDecision inbound=<configured> network=udp original_target=<redacted-ip>:443 sniffed_protocol=quic sniffed_domain=<redacted-domain> route_target=<redacted-domain>:443 dial_target=<redacted-ip>:443 selected_outbound=vless"
        );
    }

    #[test]
    fn log_route_decision_writes_to_runtime_error_log() {
        let dir = unique_temp_dir("xray-route-log");
        let logger = crate::RuntimeLogger::new(crate::RuntimeLogConfig::directory(&dir))
            .expect("runtime logger should open files");
        let original = Target::new(
            TargetAddr::Ip("192.0.2.10".parse().unwrap()),
            443,
            Network::Udp,
        );
        let route_target = Target::new(
            TargetAddr::Domain("video.example".to_owned()),
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
        assert!(error_log.contains("sniffed_domain=<redacted-domain>"));
        assert!(!error_log.contains("video.example"));
        assert!(!error_log.contains("192.0.2.10"));
        assert!(!error_log.contains("inbound_49783"));
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
        assert!(
            access_log.contains("from tun accepted <redacted-domain>:443 outbound=<configured>")
        );
        assert!(!access_log.contains("speedtest.example"));
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

        log_access_rejected(&logger, "tun", &target, "failed for secret.example:443");
        drop(logger);

        let access_log =
            std::fs::read_to_string(dir.join("xray-access.log")).expect("access log should exist");
        assert!(access_log.contains("from tun rejected <redacted-domain>:443 reason=<redacted>"));
        assert!(!access_log.contains("speedtest.example"));
        assert!(!access_log.contains("secret.example"));
    }

    #[test]
    fn log_access_redacts_network_source_endpoint() {
        let dir = unique_temp_dir("xray-access-source-redaction");
        let logger = crate::RuntimeLogger::new(crate::RuntimeLogConfig::directory(&dir))
            .expect("runtime logger should open files");
        let target = Target::new(
            TargetAddr::Domain("private.example".to_owned()),
            443,
            Network::Tcp,
        );

        log_access_accepted(&logger, "198.51.100.42:49152", &target, "freedom");
        drop(logger);

        let access_log =
            std::fs::read_to_string(dir.join("xray-access.log")).expect("access log should exist");
        assert!(access_log.contains("from <redacted-source> accepted"));
        assert!(!access_log.contains("198.51.100.42"));
        assert!(!access_log.contains("private.example"));
    }

    #[test]
    fn configured_outbound_tag_cannot_inject_or_leak_into_log() {
        let target = Target::new(
            TargetAddr::Domain("secret.example".to_owned()),
            443,
            Network::Tcp,
        );
        let event = RouteDecisionLog {
            inbound_tag: None,
            network: Network::Tcp,
            original_target: &target,
            sniffed_protocol: None,
            route_target: &target,
            dial_target: &target,
            selected_outbound: "proxy\n123 error forged",
        };

        let message = route_decision_message(&event);

        assert!(message.contains("selected_outbound=<configured>"));
        assert!(!message.contains("proxy"));
        assert_eq!(message.lines().count(), 1);
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
