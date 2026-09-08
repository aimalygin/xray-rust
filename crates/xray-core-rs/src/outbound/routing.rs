//! Ordered routing evaluation, separate from graph selection and handler construction.

#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr};
use xray_config::{Network, RoutingConfig, RoutingDomainStrategy, RoutingRuleTarget};
use xray_routing::Target;
use xray_transport::DnsResolver;

use super::{target_domain, target_ip, target_network};
use crate::CoreError;

// Bound rule-by-address work even for an injected platform resolver. Never
// silently truncate the answer: a discarded address could change the route.
const MAX_IP_ON_DEMAND_ADDRESSES: usize = 256;

pub(super) async fn select_routed_target_with_resolver<'a>(
    routing: &'a RoutingConfig,
    inbound_tag: Option<&str>,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<Option<&'a RoutingRuleTarget>, CoreError> {
    if routing.domain_strategy == RoutingDomainStrategy::IpOnDemand {
        if let Some(domain) = target_domain(target) {
            return select_on_demand(routing, inbound_tag, domain, target, dns_resolver).await;
        }
    }

    if let Some(selected) = select_routed_target(
        routing,
        inbound_tag,
        target_domain(target),
        target_ip(target),
        Some(target_network(target)),
        Some(target.port),
    ) {
        return Ok(Some(selected));
    }

    if routing.domain_strategy == RoutingDomainStrategy::IpIfNonMatch {
        if let Some(domain) = target_domain(target) {
            if let Ok(resolved) = dns_resolver.resolve_all(domain, target.port).await {
                return Ok(select_routed_target_with_resolved_ips(
                    routing,
                    inbound_tag,
                    Some(domain),
                    resolved.socket_addrs(),
                    Some(target_network(target)),
                    Some(target.port),
                ));
            }
        }
    }
    Ok(None)
}

async fn select_on_demand<'a>(
    routing: &'a RoutingConfig,
    inbound_tag: Option<&str>,
    domain: &str,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<Option<&'a RoutingRuleTarget>, CoreError> {
    // None means not attempted; Some(None) remembers a failed lookup so later
    // IP rules cannot trigger a retry storm. The lookup stays on this future:
    // cancellation drops it and the caller retains one policy revision.
    let mut resolution = None;
    for rule in &routing.rules {
        // Xray v26.7.28 BuildCondition checks these before destination IP,
        // then domain. A domain mismatch in a combined rule must not suppress
        // its DNS lookup. An earlier matching domain-only rule still wins.
        if !rule.matches_inbound(inbound_tag)
            || !rule.matches_network(Some(target_network(target)))
            || !rule.matches_port(Some(target.port))
        {
            continue;
        }
        if !rule.ip_matchers.is_empty() {
            if resolution.is_none() {
                let resolved = dns_resolver.resolve_all(domain, target.port).await.ok();
                if resolved
                    .as_ref()
                    .is_some_and(|lookup| lookup.socket_addrs().len() > MAX_IP_ON_DEMAND_ADDRESSES)
                {
                    return Err(CoreError::RoutingDnsAddressLimitExceeded {
                        limit: MAX_IP_ON_DEMAND_ADDRESSES,
                    });
                }
                resolution = Some(resolved);
            }
            if !resolution
                .as_ref()
                .and_then(Option::as_ref)
                .is_some_and(|lookup| lookup.ips().any(|ip| rule.matches_ip(Some(&ip))))
            {
                continue;
            }
        }
        if rule.matches_domain(Some(domain)) {
            return Ok(Some(&rule.target));
        }
    }
    Ok(None)
}

pub(super) fn select_routed_target<'a>(
    routing: &'a RoutingConfig,
    inbound_tag: Option<&str>,
    target_domain: Option<&str>,
    target_ip: Option<&IpAddr>,
    target_network: Option<Network>,
    target_port: Option<u16>,
) -> Option<&'a RoutingRuleTarget> {
    routing
        .rules
        .iter()
        .find(|rule| {
            rule.matches_target(
                inbound_tag,
                target_domain,
                target_ip,
                target_network,
                target_port,
            )
        })
        .map(|rule| &rule.target)
}

pub(super) fn select_routed_target_with_resolved_ips<'a>(
    routing: &'a RoutingConfig,
    inbound_tag: Option<&str>,
    target_domain: Option<&str>,
    target_addrs: &[SocketAddr],
    target_network: Option<Network>,
    target_port: Option<u16>,
) -> Option<&'a RoutingRuleTarget> {
    routing
        .rules
        .iter()
        .find(|rule| {
            target_addrs.iter().any(|target_addr| {
                rule.matches_target(
                    inbound_tag,
                    target_domain,
                    Some(&target_addr.ip()),
                    target_network,
                    target_port,
                )
            })
        })
        .map(|rule| &rule.target)
}
