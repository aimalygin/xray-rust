//! Freedom's `sockopt.domainStrategy`, resolved as Xray-core's `LookupForIP`
//! and `DialSystem` resolve it.

use std::net::SocketAddr;

use async_trait::async_trait;
use xray_config::{AddressFamilies, DomainStrategy};
use xray_transport::{DnsLookup, DnsQueryStrategy, DnsResolver, TransportError};

/// Resolves domains under one domain strategy.
///
/// The preferred families are asked for first, and the fallback family when
/// that lookup fails or finds nothing. If both fail, a `Force` strategy fails
/// the dial. A `Use` strategy instead looks up both families as `AsIs` does,
/// since Xray-core then hands the domain to the system dialer.
///
/// Xray-core resolves through its DNS client and falls back to the system
/// resolver. Here both lookups go through the resolver the caller passes,
/// which is the configured DNS client whenever the profile has one.
pub(crate) struct DomainStrategyResolver<'a> {
    inner: &'a dyn DnsResolver,
    strategy: DomainStrategy,
}

impl<'a> DomainStrategyResolver<'a> {
    pub(crate) fn new(inner: &'a dyn DnsResolver, strategy: DomainStrategy) -> Self {
        Self { inner, strategy }
    }

    async fn lookup_for_ip(&self, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
        let preferred = self
            .inner
            .resolve_all_with_strategy(domain, port, query_strategy(self.strategy.preferred()))
            .await;
        let preferred = preferred.and_then(|lookup| non_empty(lookup, domain, port));
        match (preferred, self.strategy.fallback()) {
            (Ok(lookup), _) => Ok(lookup),
            (Err(error), None) => Err(error),
            (Err(_), Some(fallback)) => self
                .inner
                .resolve_all_with_strategy(domain, port, query_strategy(fallback))
                .await
                .and_then(|lookup| non_empty(lookup, domain, port)),
        }
    }
}

#[async_trait]
impl DnsResolver for DomainStrategyResolver<'_> {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        if !self.strategy.has_strategy() {
            return self.inner.resolve(domain, port).await;
        }
        let lookup = self.resolve_all(domain, port).await?;
        lookup
            .socket_addrs()
            .first()
            .copied()
            .ok_or_else(|| TransportError::NoResolvedAddress(domain.to_owned(), port))
    }

    async fn resolve_all(&self, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
        if !self.strategy.has_strategy() {
            return self.inner.resolve_all(domain, port).await;
        }
        match self.lookup_for_ip(domain, port).await {
            Ok(lookup) => Ok(lookup),
            Err(error) if self.strategy.force_ip() => Err(error),
            Err(_) => self.inner.resolve_all(domain, port).await,
        }
    }

    async fn resolve_all_with_strategy(
        &self,
        domain: &str,
        port: u16,
        query: DnsQueryStrategy,
    ) -> Result<DnsLookup, TransportError> {
        if !self.strategy.has_strategy() {
            return self
                .inner
                .resolve_all_with_strategy(domain, port, query)
                .await;
        }
        let lookup = self.resolve_all(domain, port).await?;
        let addresses = lookup
            .socket_addrs()
            .iter()
            .copied()
            .filter(|address| match query {
                DnsQueryStrategy::UseIp => true,
                DnsQueryStrategy::UseIpv4 => address.is_ipv4(),
                DnsQueryStrategy::UseIpv6 => address.is_ipv6(),
            });
        non_empty(DnsLookup::new(addresses, lookup.ttl()), domain, port)
    }
}

fn non_empty(lookup: DnsLookup, domain: &str, port: u16) -> Result<DnsLookup, TransportError> {
    if lookup.socket_addrs().is_empty() {
        Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
    } else {
        Ok(lookup)
    }
}

fn query_strategy(families: AddressFamilies) -> DnsQueryStrategy {
    match families {
        AddressFamilies::Both => DnsQueryStrategy::UseIp,
        AddressFamilies::Ipv4 => DnsQueryStrategy::UseIpv4,
        AddressFamilies::Ipv6 => DnsQueryStrategy::UseIpv6,
    }
}

#[cfg(test)]
mod tests;
