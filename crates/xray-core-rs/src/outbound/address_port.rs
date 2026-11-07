//! `sockopt.addressPortStrategy`: the SRV or TXT lookup Xray-core's
//! `DialSystem` makes before it dials a domain server, in
//! `checkAddressPortStrategy`.
use super::*;
use futures_util::future::Either;
use xray_config::{AddressPortRecords, AddressPortStrategy};
use xray_transport::RecordResolver;

/// The server's candidates, after `strategy`'s lookup. Without a strategy
/// this is the plain resolution, and with one a boxed lookup, so every open
/// future holds a pointer for the lookup rather than its state.
pub(super) fn resolve_server<'a>(
    server: &'a Target,
    strategy: AddressPortStrategy,
    resolver: &'a dyn DnsResolver,
    dialer: &'a TransportDialer,
) -> impl Future<Output = Result<Vec<SocketAddr>, CoreError>> + 'a {
    if strategy == AddressPortStrategy::None {
        Either::Left(resolve_server_candidates(server, resolver))
    } else {
        Either::Right(Box::pin(resolve_redirected(
            server, strategy, resolver, dialer,
        )))
    }
}

async fn resolve_redirected(
    server: &Target,
    strategy: AddressPortStrategy,
    resolver: &dyn DnsResolver,
    dialer: &TransportDialer,
) -> Result<Vec<SocketAddr>, CoreError> {
    let records = dialer.record_resolver();
    match redirect(strategy, server, records.as_ref()).await {
        Some(redirected) => resolve_server_candidates(&redirected, resolver).await,
        None => resolve_server_candidates(server, resolver).await,
    }
}

/// The server `strategy` dials in place of `server`, or `None` to dial
/// `server` itself: an IP server, a failed lookup or no usable record, as
/// Xray-core goes on with the configured server on any of them.
pub(super) async fn redirect(
    strategy: AddressPortStrategy,
    server: &Target,
    records: &dyn RecordResolver,
) -> Option<Target> {
    let kind = strategy.records()?;
    let RoutingTargetAddr::Domain(domain) = &server.addr else {
        return None;
    };
    let (address, port) = match kind {
        AddressPortRecords::Srv => {
            // Xray-core cuts the name in three at its first two dots and
            // drops the first byte of the first two parts, the underscores
            // of `_service._proto.name`.
            let mut parts = domain.splitn(3, '.');
            let (Some(service), Some(proto), Some(name)) =
                (parts.next(), parts.next(), parts.next())
            else {
                return None;
            };
            let (service, proto) = (service.get(1..)?, proto.get(1..)?);
            let record = records
                .lookup_srv(service, proto, name)
                .await
                .ok()?
                .into_iter()
                .next()?;
            (record.target, record.port)
        }
        // The first record that reads as `host:port` with a valid port.
        AddressPortRecords::Txt => records
            .lookup_txt(domain)
            .await
            .ok()?
            .into_iter()
            .find_map(|record| {
                let (host, port) = split_host_port(&record)?;
                Some((host.to_owned(), parse_port(port)?))
            })?,
    };
    let mut redirected = server.clone();
    if strategy.replaces_port() {
        redirected.port = port;
    }
    if strategy.replaces_address() {
        redirected.addr = parse_address(&address);
    }
    Some(redirected)
}

/// Go's `net.SplitHostPort`.
fn split_host_port(text: &str) -> Option<(&str, &str)> {
    let colon = text.rfind(':')?;
    let (host, after_host) = if let Some(rest) = text.strip_prefix('[') {
        let end = rest.find(']')? + 1;
        // `]` must come just before the last colon.
        if end + 1 != colon {
            return None;
        }
        (&text[1..end], end + 1)
    } else {
        let host = &text[..colon];
        if host.contains(':') {
            return None;
        }
        (host, 0)
    };
    let opening_from = usize::from(after_host != 0);
    if text[opening_from..].contains('[') || text[after_host..].contains(']') {
        return None;
    }
    Some((host, &text[colon + 1..]))
}

/// Xray-core's `PortFromString`: decimal digits, at most 65535.
fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let digits = text.trim_start_matches('0');
    if digits.len() > 5 {
        return None;
    }
    digits
        .parse::<u32>()
        .map_or(Some(0), |port| u16::try_from(port).ok())
}

/// Xray-core's `net.ParseAddress`: an IP literal, else a domain.
fn parse_address(text: &str) -> RoutingTargetAddr {
    let text = text
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(text);
    let alphanumeric = |byte: Option<&u8>| byte.is_some_and(u8::is_ascii_alphanumeric);
    let bytes = text.as_bytes();
    let text = if !bytes.is_empty() && (!alphanumeric(bytes.first()) || !alphanumeric(bytes.last()))
    {
        text.trim()
    } else {
        text
    };
    match text.parse::<IpAddr>() {
        Ok(ip) => RoutingTargetAddr::Ip(ip.to_canonical()),
        Err(_) => RoutingTargetAddr::Domain(text.to_owned()),
    }
}

#[cfg(test)]
mod tests;
