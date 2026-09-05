//! DNS selection, static hosts, fake IP and DNS outbound configuration.
use super::*;

pub(super) fn is_tun_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => matches!(ip, TUN_DNS_ANCHOR | TUN_CLIENT_IPV4),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .is_some_and(|ip| matches!(ip, TUN_DNS_ANCHOR | TUN_CLIENT_IPV4)),
    }
}

pub(super) fn dns_query_strategies_overlap(
    global: DnsQueryStrategy,
    server: DnsQueryStrategy,
) -> bool {
    global == DnsQueryStrategy::UseIp || server == DnsQueryStrategy::UseIp || global == server
}

pub(super) fn parse_dns_https_server_uri(
    address: &str,
) -> Result<Option<(DnsServerTransport, DnsServerEndpoint, String)>, String> {
    let Some((scheme, remainder)) = address.split_once(':') else {
        return Ok(None);
    };
    let transport = if scheme.eq_ignore_ascii_case("https") {
        DnsServerTransport::HttpsRouted
    } else if scheme.eq_ignore_ascii_case("https+local") {
        DnsServerTransport::HttpsLocal
    } else {
        return Ok(None);
    };
    let Some(rest) = remainder.strip_prefix("//") else {
        return Err("dns HTTPS server URL must use `https://` or `https+local://`".to_owned());
    };
    if address
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(
            "dns HTTPS server URL must not contain whitespace or control characters".to_owned(),
        );
    }
    if address.contains('#') {
        return Err("dns HTTPS server URL must not include a fragment".to_owned());
    }
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err("dns HTTPS server URL must include a host".to_owned());
    }
    if authority.contains('@') {
        return Err("dns HTTPS server URL must not include userinfo".to_owned());
    }
    let suffix = &rest[authority_end..];
    if !suffix.is_ascii() || suffix.contains('\\') {
        return Err("dns HTTPS server URL contains an invalid path or query".to_owned());
    }
    let https_path = match suffix {
        "" => "/".to_owned(),
        suffix if suffix.starts_with('/') => suffix.to_owned(),
        suffix if suffix.starts_with('?') => format!("/{suffix}"),
        _ => return Err("dns HTTPS server URL contains an invalid path or query".to_owned()),
    };

    let endpoint = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, suffix)) = bracketed.split_once(']') else {
            return Err("dns HTTPS server URL contains a malformed bracketed IPv6 host".to_owned());
        };
        if host.is_empty() || host.contains(['[', ']']) {
            return Err("dns HTTPS server URL contains a malformed bracketed IPv6 host".to_owned());
        }
        let port = match suffix {
            "" => 443,
            suffix => {
                let Some(port) = suffix.strip_prefix(':') else {
                    return Err(
                        "dns HTTPS server URL authority contains unexpected data".to_owned()
                    );
                };
                parse_dns_https_server_port(port)?
            }
        };
        let socket = format!("[{host}]:{port}")
            .parse::<SocketAddr>()
            .map_err(|_| "dns HTTPS server URL contains an invalid IPv6 host".to_owned())?;
        if !socket.is_ipv6() {
            return Err("dns HTTPS server URL brackets are only valid for IPv6 hosts".to_owned());
        }
        DnsServerEndpoint::Ip(socket)
    } else {
        if authority.contains(['[', ']']) {
            return Err("dns HTTPS server URL contains malformed host brackets".to_owned());
        }
        if authority.bytes().filter(|byte| *byte == b':').count() > 1 {
            return Err("dns HTTPS server URL requires brackets around an IPv6 host".to_owned());
        }
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, parse_dns_https_server_port(port)?),
            None => (authority, 443),
        };
        if host.is_empty() {
            return Err("dns HTTPS server URL must include a host".to_owned());
        }
        if host.contains(['\\', '%']) {
            return Err("dns HTTPS server URL contains an invalid host".to_owned());
        }
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => DnsServerEndpoint::Ip(SocketAddr::new(ip.into(), port)),
            Ok(IpAddr::V6(_)) => {
                return Err("dns HTTPS server URL requires brackets around an IPv6 host".to_owned());
            }
            Err(_) => DnsServerEndpoint::Domain {
                domain: host.to_owned(),
                port,
            },
        }
    };

    if matches!(&endpoint, DnsServerEndpoint::Ip(address) if is_tun_reserved_ip(address.ip())) {
        return Err("dns server cannot point at a tunnel-local DNS address".to_owned());
    }

    Ok(Some((transport, endpoint, https_path)))
}

pub(super) fn parse_dns_https_server_port(port: &str) -> Result<u16, String> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("dns HTTPS server URL contains an invalid port".to_owned());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "dns HTTPS server URL contains an invalid port".to_owned())?;
    if port == 0 {
        return Err("dns server port must be greater than zero".to_owned());
    }
    Ok(port)
}

pub(super) fn parse_dns_tcp_server_uri(
    address: &str,
) -> Result<Option<(DnsServerTransport, DnsServerEndpoint)>, String> {
    let Some((scheme, remainder)) = address.split_once(':') else {
        return Ok(None);
    };
    let (transport, default_port) = if scheme.eq_ignore_ascii_case("tcp") {
        (DnsServerTransport::TcpRouted, 53)
    } else if scheme.eq_ignore_ascii_case("tcp+local") {
        (DnsServerTransport::TcpLocal, 53)
    } else if scheme.eq_ignore_ascii_case("tls") {
        (DnsServerTransport::TlsRouted, 853)
    } else if scheme.eq_ignore_ascii_case("quic+local") {
        (DnsServerTransport::QuicLocal, 853)
    } else {
        return Ok(None);
    };
    let Some(authority) = remainder.strip_prefix("//") else {
        return Err(
            "dns stream server URL must use `tcp://`, `tcp+local://`, `tls://`, or `quic+local://`"
                .to_owned(),
        );
    };
    if address
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(
            "dns TCP server URL must not contain whitespace or control characters".to_owned(),
        );
    }
    if authority.is_empty() {
        return Err("dns TCP server URL must include a host".to_owned());
    }
    if authority.contains('@') {
        return Err("dns TCP server URL must not include userinfo".to_owned());
    }
    if authority.contains('/') {
        return Err("dns TCP server URL must not include a path".to_owned());
    }
    if authority.contains('?') {
        return Err("dns TCP server URL must not include a query".to_owned());
    }
    if authority.contains('#') {
        return Err("dns TCP server URL must not include a fragment".to_owned());
    }

    let endpoint = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, suffix)) = bracketed.split_once(']') else {
            return Err("dns TCP server URL contains a malformed bracketed IPv6 host".to_owned());
        };
        if host.is_empty() || host.contains(['[', ']']) {
            return Err("dns TCP server URL contains a malformed bracketed IPv6 host".to_owned());
        }
        let port = match suffix {
            "" => default_port,
            suffix => {
                let Some(port) = suffix.strip_prefix(':') else {
                    return Err(
                        "dns TCP server URL must contain only a host and optional port".to_owned(),
                    );
                };
                parse_dns_tcp_server_port(port)?
            }
        };
        let socket = format!("[{host}]:{port}")
            .parse::<SocketAddr>()
            .map_err(|_| "dns TCP server URL contains an invalid bracketed IPv6 host".to_owned())?;
        if !socket.is_ipv6() {
            return Err("dns TCP server URL brackets are only valid for IPv6 hosts".to_owned());
        }
        DnsServerEndpoint::Ip(socket)
    } else {
        if authority.contains(['[', ']']) {
            return Err("dns TCP server URL contains malformed host brackets".to_owned());
        }
        if authority.bytes().filter(|byte| *byte == b':').count() > 1 {
            return Err("dns TCP server URL requires brackets around an IPv6 host".to_owned());
        }
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, parse_dns_tcp_server_port(port)?),
            None => (authority, default_port),
        };
        if host.is_empty() {
            return Err("dns TCP server URL must include a host".to_owned());
        }
        if host.contains(['\\', '%']) {
            return Err("dns TCP server URL contains an invalid host".to_owned());
        }
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => DnsServerEndpoint::Ip(SocketAddr::new(ip.into(), port)),
            Ok(IpAddr::V6(_)) => {
                return Err("dns TCP server URL requires brackets around an IPv6 host".to_owned());
            }
            Err(_) => DnsServerEndpoint::Domain {
                domain: host.to_owned(),
                port,
            },
        }
    };

    if matches!(&endpoint, DnsServerEndpoint::Ip(address) if is_tun_reserved_ip(address.ip())) {
        return Err("dns server cannot point at a tunnel-local DNS address".to_owned());
    }

    Ok(Some((transport, endpoint)))
}

pub(super) fn parse_dns_tcp_server_port(port: &str) -> Result<u16, String> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("dns TCP server URL contains an invalid port".to_owned());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "dns TCP server URL contains an invalid port".to_owned())?;
    if port == 0 {
        return Err("dns server port must be greater than zero".to_owned());
    }
    Ok(port)
}

pub(super) fn dns_stream_server_policy(
    transport: DnsServerTransport,
    endpoint: DnsServerEndpoint,
    https_path: Option<String>,
) -> DnsServerConfig {
    DnsServerConfig::Policy(Box::new(DnsNameServerConfig {
        endpoint,
        transport,
        https_path,
        domains: DomainMatcherSet::default(),
        expected_ips: DnsIpFilter::default(),
        unexpected_ips: DnsIpFilter::default(),
        tag: String::new(),
        timeout_ms: 0,
        skip_fallback: false,
        query_strategy: DnsQueryStrategy::UseIp,
        final_query: false,
    }))
}

pub(super) fn fake_ip_usable_address_count(pool: IpCidr) -> u64 {
    let IpAddr::V4(network) = pool.network() else {
        return 0;
    };

    let address_count = 1_u64 << u32::from(32 - pool.prefix());
    let first_offset = u64::from(address_count > 2);
    let end_offset = if address_count > 2 {
        address_count - 1
    } else {
        address_count
    };
    let mut usable = end_offset - first_offset;

    let mask = if pool.prefix() == 0 {
        0
    } else {
        u32::MAX << u32::from(32 - pool.prefix())
    };
    let network_base = u32::from(network) & mask;
    for reserved in [TUN_DNS_ANCHOR, TUN_CLIENT_IPV4] {
        let reserved_offset = u32::from(reserved)
            .checked_sub(network_base)
            .map(u64::from)
            .filter(|offset| (first_offset..end_offset).contains(offset));
        if reserved_offset.is_some() {
            usable -= 1;
        }
    }

    usable
}

impl Parser<'_> {
    pub(super) fn parse_dns(&mut self) -> DnsConfig {
        let Some(dns) = self.root.get("dns") else {
            return DnsConfig::default();
        };
        let dns_path = "$.dns";
        if !dns.is_object() {
            self.error(dns_path, "dns must be an object");
            return DnsConfig::default();
        }

        self.reject_unknown_fields(dns, dns_path, &surface::DNS);
        let query_strategy = self.parse_dns_query_strategy(dns);
        let disable_cache = self
            .optional_bool_at(dns, "disableCache", "$.dns.disableCache".to_owned())
            .unwrap_or(false);
        let serve_stale = self
            .optional_bool_at(dns, "serveStale", "$.dns.serveStale".to_owned())
            .unwrap_or(false);
        let serve_expired_ttl = self
            .optional_u32_at(dns, "serveExpiredTTL", "$.dns.serveExpiredTTL".to_owned())
            .unwrap_or(0);
        if serve_stale && disable_cache {
            self.error(
                "$.dns.serveStale",
                "dns serveStale requires caching; disableCache must be false",
            );
        }
        if serve_stale && serve_expired_ttl == 0 {
            self.error(
                "$.dns.serveExpiredTTL",
                "dns serveStale requires an explicit nonzero bounded serveExpiredTTL",
            );
        }
        if serve_expired_ttl > MAX_DNS_SERVE_EXPIRED_TTL_SECONDS {
            self.error(
                "$.dns.serveExpiredTTL",
                format!(
                    "dns serveExpiredTTL must not exceed {MAX_DNS_SERVE_EXPIRED_TTL_SECONDS} seconds"
                ),
            );
        }
        DnsConfig {
            fake_ip: self.parse_dns_fake_ip(dns),
            servers: self.parse_dns_servers(dns, query_strategy),
            hosts: self.parse_dns_hosts(dns),
            tag: self
                .nullable_string_at(dns, "tag", "$.dns.tag".to_owned())
                .unwrap_or_default()
                .to_owned(),
            query_strategy,
            disable_cache,
            serve_stale,
            serve_expired_ttl,
            disable_fallback: self
                .optional_bool_at(dns, "disableFallback", "$.dns.disableFallback".to_owned())
                .unwrap_or(false),
            disable_fallback_if_match: self
                .optional_bool_at(
                    dns,
                    "disableFallbackIfMatch",
                    "$.dns.disableFallbackIfMatch".to_owned(),
                )
                .unwrap_or(false),
        }
    }

    pub(super) fn parse_dns_query_strategy(&mut self, dns: &Value) -> DnsQueryStrategy {
        self.parse_dns_query_strategy_at(dns.get("queryStrategy"), "$.dns.queryStrategy")
    }

    pub(super) fn parse_dns_query_strategy_at(
        &mut self,
        raw_strategy: Option<&Value>,
        path: &str,
    ) -> DnsQueryStrategy {
        let Some(raw_strategy) = raw_strategy else {
            return DnsQueryStrategy::default();
        };
        let Some(strategy) = raw_strategy.as_str() else {
            self.error(path, "dns queryStrategy must be a string");
            return DnsQueryStrategy::default();
        };

        match strategy.to_ascii_lowercase().as_str() {
            "useip" | "use_ip" | "use-ip" => DnsQueryStrategy::UseIp,
            "useip4" | "useipv4" | "use_ip4" | "use_ipv4" | "use_ip_v4" | "use-ip4"
            | "use-ipv4" | "use-ip-v4" => DnsQueryStrategy::UseIpv4,
            "useip6" | "useipv6" | "use_ip6" | "use_ipv6" | "use_ip_v6" | "use-ip6"
            | "use-ipv6" | "use-ip-v6" => DnsQueryStrategy::UseIpv6,
            "usesys" | "usesystem" | "use_sys" | "use_system" | "use-sys" | "use-system" => {
                self.error(
                    path,
                    "dns queryStrategy `UseSystem` requires platform route capability and is not supported",
                );
                DnsQueryStrategy::default()
            }
            _ => {
                self.error(
                    path,
                    format!(
                        "unsupported dns queryStrategy `{strategy}`; expected UseIP, UseIPv4, or UseIPv6"
                    ),
                );
                DnsQueryStrategy::default()
            }
        }
    }

    pub(super) fn parse_dns_servers(
        &mut self,
        dns: &Value,
        global_query_strategy: DnsQueryStrategy,
    ) -> Vec<DnsServerConfig> {
        let Some(raw_servers) = dns.get("servers") else {
            return Vec::new();
        };
        let Some(servers) = raw_servers.as_array() else {
            self.error("$.dns.servers", "field `servers` must be an array");
            return Vec::new();
        };
        if servers.len() > MAX_DNS_SERVERS {
            self.error(
                "$.dns.servers",
                format!(
                    "dns config contains {} servers; maximum supported per configuration is {}",
                    servers.len(),
                    MAX_DNS_SERVERS
                ),
            );
            return Vec::new();
        }

        servers
            .iter()
            .enumerate()
            .filter_map(|(index, server)| {
                let path = format!("$.dns.servers[{index}]");
                match server {
                    Value::String(server) => self.parse_dns_server(server, &path),
                    Value::Object(_) => {
                        self.parse_dns_name_server(server, &path, global_query_strategy)
                    }
                    _ => {
                        self.error(path, "dns server must be a string or an object");
                        None
                    }
                }
            })
            .collect()
    }

    pub(super) fn parse_dns_name_server(
        &mut self,
        server: &Value,
        path: &str,
        global_query_strategy: DnsQueryStrategy,
    ) -> Option<DnsServerConfig> {
        self.reject_unknown_fields(server, path, &surface::DNS_SERVER);

        let address_path = format!("{path}.address");
        let Some(address) = self.optional_string_at(server, "address", address_path.clone()) else {
            if server.get("address").is_none() {
                self.error(address_path, "missing dns server address");
            }
            return None;
        };
        let port_path = format!("{path}.port");
        let port = if server.get("port").is_some() {
            self.u16_at(server, "port", port_path.clone())?
        } else {
            53
        };
        let port = if port == 0 { 53 } else { port };
        let (transport, endpoint, https_path) = match parse_dns_https_server_uri(address) {
            Ok(Some((transport, endpoint, https_path))) => (transport, endpoint, Some(https_path)),
            Ok(None) => match parse_dns_tcp_server_uri(address) {
                Ok(Some((transport, endpoint))) => (transport, endpoint, None),
                Ok(None) => (
                    DnsServerTransport::Classic,
                    self.parse_dns_server_endpoint(address, port, &address_path)?,
                    None,
                ),
                Err(message) => {
                    self.error(&address_path, message);
                    return None;
                }
            },
            Err(message) => {
                self.error(&address_path, message);
                return None;
            }
        };
        let domains = self.parse_dns_server_domains(server, path)?;
        let (expected_ips, unexpected_ips) = self.parse_dns_server_ip_filters(server, path)?;
        let timeout_path = format!("{path}.timeoutMs");
        let timeout_ms = match server.get("timeoutMs") {
            None | Some(Value::Null) => 0,
            Some(_) => self.optional_u64_at(server, "timeoutMs", timeout_path.clone())?,
        };
        if timeout_ms > MAX_DNS_SERVER_TIMEOUT_MS {
            self.error(
                timeout_path,
                format!(
                    "dns server timeoutMs {timeout_ms} exceeds the largest timeout safe across Xray duration conversions {MAX_DNS_SERVER_TIMEOUT_MS}ms"
                ),
            );
            return None;
        }
        let query_strategy_path = format!("{path}.queryStrategy");
        let query_strategy =
            self.parse_dns_query_strategy_at(server.get("queryStrategy"), &query_strategy_path);
        if !dns_query_strategies_overlap(global_query_strategy, query_strategy) {
            self.error(
                query_strategy_path,
                "dns server queryStrategy has no address family in common with global dns.queryStrategy",
            );
            return None;
        }

        Some(DnsServerConfig::Policy(Box::new(DnsNameServerConfig {
            endpoint,
            transport,
            https_path,
            domains,
            expected_ips,
            unexpected_ips,
            tag: self
                .nullable_string_at(server, "tag", format!("{path}.tag"))
                .unwrap_or_default()
                .to_owned(),
            timeout_ms,
            skip_fallback: self
                .optional_bool_at(server, "skipFallback", format!("{path}.skipFallback"))
                .unwrap_or(false),
            query_strategy,
            final_query: self
                .optional_bool_at(server, "finalQuery", format!("{path}.finalQuery"))
                .unwrap_or(false),
        })))
    }

    pub(super) fn parse_dns_server_ip_filters(
        &mut self,
        server: &Value,
        path: &str,
    ) -> Option<(DnsIpFilter, DnsIpFilter)> {
        let expected_path = format!("{path}.expectedIPs");
        let alias_path = format!("{path}.expectIPs");
        let expected = self.parse_dns_string_list(server, "expectedIPs", &expected_path)?;
        let alias = self.parse_dns_string_list(server, "expectIPs", &alias_path)?;
        let expected_ips = if expected.is_empty() {
            self.parse_dns_ip_filter(&alias, &alias_path)?
        } else {
            self.parse_dns_ip_filter(&expected, &expected_path)?
        };

        let unexpected_path = format!("{path}.unexpectedIPs");
        let unexpected = self.parse_dns_string_list(server, "unexpectedIPs", &unexpected_path)?;
        let unexpected_ips = self.parse_dns_ip_filter(&unexpected, &unexpected_path)?;

        Some((expected_ips, unexpected_ips))
    }

    pub(super) fn parse_dns_string_list<'value>(
        &mut self,
        value: &'value Value,
        key: &str,
        path: &str,
    ) -> Option<Vec<&'value str>> {
        let Some(raw) = value.get(key) else {
            return Some(Vec::new());
        };

        match raw {
            Value::Null => Some(Vec::new()),
            Value::String(values) => Some(values.split(',').collect()),
            Value::Array(values) => {
                let mut strings = Vec::with_capacity(values.len());
                for (index, value) in values.iter().enumerate() {
                    let Some(value) = value.as_str() else {
                        self.error(
                            format!("{path}[{index}]"),
                            "dns server IP matcher must be a string",
                        );
                        return None;
                    };
                    strings.push(value);
                }
                Some(strings)
            }
            _ => {
                self.error(path, format!("field `{key}` must be a string or an array"));
                None
            }
        }
    }

    pub(super) fn parse_dns_ip_filter(
        &mut self,
        values: &[&str],
        path: &str,
    ) -> Option<DnsIpFilter> {
        let mut filter = DnsIpFilter::builder();
        for (index, value) in values.iter().copied().enumerate() {
            if value == "*" {
                filter.set_soft(true);
                continue;
            }

            let item_path = format!("{path}[{index}]");
            if self.matcher_budget.remaining_ip_matchers() == 0 {
                self.ip_matcher_budget_error(&item_path);
                return None;
            }
            let matchers = if dns_ip_rule_uses_geodata(value) {
                filter.geoip()
            } else {
                filter.custom()
            };
            let inserted = self.parse_dns_ip_matcher(value, &item_path, matchers)?;
            if !self.matcher_budget.consume_ip_matchers(inserted) {
                self.ip_matcher_budget_error(&item_path);
                return None;
            }
        }
        Some(filter.build())
    }

    pub(super) fn parse_dns_server_endpoint(
        &mut self,
        address: &str,
        port: u16,
        path: &str,
    ) -> Option<DnsServerEndpoint> {
        if address.is_empty() {
            self.error(path, "dns server address cannot be empty");
            return None;
        }
        if address.trim() != address {
            self.error(
                path,
                "dns server address must not contain surrounding whitespace",
            );
            return None;
        }
        if let Ok(ip) = address.parse::<IpAddr>() {
            if is_tun_reserved_ip(ip) {
                self.error(
                    path,
                    "dns server cannot point at a tunnel-local DNS address",
                );
                return None;
            }
            return Some(DnsServerEndpoint::Ip(SocketAddr::new(ip, port)));
        }
        if address.eq_ignore_ascii_case("localhost") || address.eq_ignore_ascii_case("fakedns") {
            self.error(
                path,
                format!("special dns server `{address}` is not supported yet"),
            );
            return None;
        }
        if address.parse::<SocketAddr>().is_ok() || address.contains(':') {
            self.error(
                path,
                "object dns server address must not include a port or unsupported URL scheme",
            );
            return None;
        }

        Some(DnsServerEndpoint::Domain {
            domain: address.to_owned(),
            port,
        })
    }

    pub(super) fn parse_dns_server_domains(
        &mut self,
        server: &Value,
        path: &str,
    ) -> Option<DomainMatcherSet> {
        let domains_path = format!("{path}.domains");
        let Some(raw_domains) = server.get("domains") else {
            return Some(DomainMatcherSet::default());
        };
        let mut matchers = DomainMatcherSet::builder();
        match raw_domains {
            Value::String(domains) => {
                for (index, domain) in domains.split(',').enumerate() {
                    let item_path = format!("{domains_path}[{index}]");
                    self.parse_dns_server_domain_matcher(domain, &item_path, &mut matchers)?;
                }
            }
            Value::Array(domains) => {
                for (index, domain) in domains.iter().enumerate() {
                    let item_path = format!("{domains_path}[{index}]");
                    let Some(domain) = domain.as_str() else {
                        self.error(item_path, "dns server domain matcher must be a string");
                        return None;
                    };
                    self.parse_dns_server_domain_matcher(domain, &item_path, &mut matchers)?;
                }
            }
            _ => {
                self.error(domains_path, "field `domains` must be a string or an array");
                return None;
            }
        }
        self.build_domain_matcher_set(matchers, &domains_path)
    }

    pub(super) fn parse_dns_server_domain_matcher(
        &mut self,
        domain: &str,
        path: &str,
        matchers: &mut DomainMatcherSetBuilder,
    ) -> Option<()> {
        if domain.is_empty() {
            self.error(path, "dns server domain matcher cannot be empty");
            return None;
        }
        let remaining = self.matcher_budget.remaining_domain_matchers();
        if remaining == 0 {
            self.domain_matcher_budget_error(path);
            return None;
        }
        let parsed_matchers = self.parse_domain_matcher(domain, path, remaining)?;
        if !self
            .matcher_budget
            .consume_domain_matchers(parsed_matchers.len())
        {
            self.domain_matcher_budget_error(path);
            return None;
        }
        insert_domain_matchers(matchers, &parsed_matchers, DomainNameMode::Dns);
        Some(())
    }

    pub(super) fn build_domain_matcher_set(
        &mut self,
        builder: DomainMatcherSetBuilder,
        path: &str,
    ) -> Option<DomainMatcherSet> {
        match build_domain_matcher_set(builder) {
            Ok(matchers) => Some(matchers),
            Err(error) => {
                self.error(path, error.to_string());
                None
            }
        }
    }

    pub(super) fn parse_dns_server(&mut self, server: &str, path: &str) -> Option<DnsServerConfig> {
        if server.is_empty() {
            self.error(path, "dns server cannot be empty");
            return None;
        }
        if server.trim() != server {
            self.error(path, "dns server must not contain surrounding whitespace");
            return None;
        }

        match parse_dns_https_server_uri(server) {
            Ok(Some((transport, endpoint, https_path))) => {
                return Some(dns_stream_server_policy(
                    transport,
                    endpoint,
                    Some(https_path),
                ));
            }
            Ok(None) => {}
            Err(message) => {
                self.error(path, message);
                return None;
            }
        }

        match parse_dns_tcp_server_uri(server) {
            Ok(Some((transport, endpoint))) => {
                return Some(dns_stream_server_policy(transport, endpoint, None));
            }
            Ok(None) => {}
            Err(message) => {
                self.error(path, message);
                return None;
            }
        }

        if let Ok(socket_addr) = server.parse::<SocketAddr>() {
            if socket_addr.port() == 0 {
                self.error(path, "dns server port must be greater than zero");
                return None;
            }
            if is_tun_reserved_ip(socket_addr.ip()) {
                self.error(
                    path,
                    "dns server cannot point at a tunnel-local DNS address",
                );
                return None;
            }
            return Some(DnsServerConfig::Ip(socket_addr));
        }
        if let Ok(ip) = server.parse::<IpAddr>() {
            if is_tun_reserved_ip(ip) {
                self.error(
                    path,
                    "dns server cannot point at a tunnel-local DNS address",
                );
                return None;
            }
            return Some(DnsServerConfig::Ip(SocketAddr::new(ip, 53)));
        }

        let (domain, port) = match server.rsplit_once(':') {
            Some((domain, port)) if !domain.contains(':') => {
                let Some(port) = port.parse::<u16>().ok() else {
                    self.error(path, format!("invalid dns server port `{port}`"));
                    return None;
                };
                if port == 0 {
                    self.error(path, "dns server port must be greater than zero");
                    return None;
                }
                (domain, port)
            }
            _ => (server, 53),
        };
        if domain.is_empty() {
            self.error(path, "dns server domain cannot be empty");
            return None;
        }

        Some(DnsServerConfig::Domain {
            domain: domain.to_owned(),
            port,
        })
    }

    pub(super) fn parse_dns_hosts(&mut self, dns: &Value) -> DomainHostIndex<DnsHostTarget> {
        let mut index = DomainHostIndex::new();
        let Some(raw_hosts) = dns.get("hosts") else {
            return index;
        };
        let Some(hosts) = raw_hosts.as_object() else {
            self.error("$.dns.hosts", "field `hosts` must be an object");
            return index;
        };

        for (host, target) in hosts {
            let path = format!("$.dns.hosts.{host}");
            let Some(target) = self.parse_dns_host_target(target, &path) else {
                continue;
            };
            let remaining = self.matcher_budget.remaining_domain_matchers();
            if remaining == 0 {
                self.domain_matcher_budget_error(&path);
                continue;
            }
            let Some(matchers) = self.parse_dns_host_matcher(host, &path, remaining) else {
                continue;
            };
            if !self.matcher_budget.consume_domain_matchers(matchers.len()) {
                self.domain_matcher_budget_error(&path);
                continue;
            }
            index.extend(
                matchers
                    .into_iter()
                    .map(|matcher| (matcher, target.clone())),
            );
        }

        index
    }

    pub(super) fn parse_dns_host_matcher(
        &mut self,
        value: &str,
        path: &str,
        max_matchers: usize,
    ) -> Option<Vec<DomainMatcher>> {
        // Xray's `dns.hosts` grammar defaults an unprefixed key to `full:`.
        // Routing rules deliberately keep their separate keyword default.
        if !value.contains(':') {
            if value.is_empty() {
                self.error(path, "DNS host domain cannot be empty");
                return None;
            }
            return Some(vec![DomainMatcher::Full(value.to_owned())]);
        }

        self.parse_domain_matcher(value, path, max_matchers)
    }

    pub(super) fn parse_dns_host_target(
        &mut self,
        target: &Value,
        path: &str,
    ) -> Option<DnsHostTarget> {
        if let Some(target) = target.as_str() {
            return Some(match target.parse::<IpAddr>() {
                Ok(ip) => DnsHostTarget::Ip(ip),
                Err(_) => DnsHostTarget::Domain(target.to_owned()),
            });
        }

        let Some(targets) = target.as_array() else {
            self.error(path, "dns host target must be a string or an array");
            return None;
        };
        if targets.is_empty() {
            self.error(path, "dns host target array must not be empty");
            return None;
        }

        let mut ips = Vec::with_capacity(targets.len());
        for (index, target) in targets.iter().enumerate() {
            let element_path = format!("{path}[{index}]");
            let Some(target) = target.as_str() else {
                self.error(element_path, "dns host target array item must be a string");
                return None;
            };
            let Ok(ip) = target.parse::<IpAddr>() else {
                self.error(
                    element_path,
                    "dns host target array item must be an IP address",
                );
                return None;
            };
            ips.push(ip);
        }

        Some(DnsHostTarget::Ips(ips))
    }

    pub(super) fn parse_dns_fake_ip(&mut self, dns: &Value) -> Option<DnsFakeIpConfig> {
        let fake_ip = dns.get("fakeIp")?;
        let fake_ip_path = "$.dns.fakeIp";
        if !fake_ip.is_object() {
            self.error(fake_ip_path, "dns fakeIp must be an object");
            return None;
        }

        self.reject_unknown_fields(fake_ip, fake_ip_path, &surface::FAKE_IP);
        let enabled = self
            .optional_bool_at(fake_ip, "enabled", format!("{fake_ip_path}.enabled"))
            .unwrap_or(false);
        let ttl = self
            .optional_u32_at(fake_ip, "ttl", format!("{fake_ip_path}.ttl"))
            .unwrap_or(60);

        if !enabled {
            return None;
        }
        if ttl == 0 {
            self.error(
                format!("{fake_ip_path}.ttl"),
                "fakeIp ttl must be greater than zero",
            );
            return None;
        }

        let ipv4_pool_path = format!("{fake_ip_path}.ipv4Pool");
        let Some(raw_pool) = self.optional_string_at(fake_ip, "ipv4Pool", ipv4_pool_path.clone())
        else {
            if fake_ip.get("ipv4Pool").is_none() {
                self.error(ipv4_pool_path, "missing fakeIp ipv4Pool");
            }
            return None;
        };
        let pool = self.parse_ip_cidr(raw_pool, &ipv4_pool_path)?;
        if !matches!(pool.network(), IpAddr::V4(_)) {
            self.error(ipv4_pool_path, "fakeIp ipv4Pool must be an IPv4 CIDR");
            return None;
        }

        let usable_address_count = fake_ip_usable_address_count(pool);
        if usable_address_count == 0 {
            self.error(ipv4_pool_path, "fakeIp ipv4Pool has no usable addresses");
            return None;
        }

        let pool_size_path = format!("{fake_ip_path}.poolSize");
        let explicit_pool_size = self.optional_u32_at(fake_ip, "poolSize", pool_size_path.clone());
        let pool_size = match explicit_pool_size {
            Some(0) => {
                self.error(pool_size_path, "fakeIp poolSize must be greater than zero");
                return None;
            }
            Some(pool_size) if u64::from(pool_size) > usable_address_count => {
                self.error(
                    pool_size_path,
                    format!(
                        "fakeIp poolSize exceeds the {usable_address_count} usable addresses in ipv4Pool"
                    ),
                );
                return None;
            }
            Some(pool_size) => pool_size,
            None => u32::try_from(usable_address_count.min(u64::from(DEFAULT_FAKE_IP_POOL_SIZE)))
                .unwrap_or(DEFAULT_FAKE_IP_POOL_SIZE),
        };

        Some(DnsFakeIpConfig {
            enabled,
            ipv4_pool: pool,
            pool_size,
            ttl,
        })
    }

    pub(super) fn parse_dns_outbound_settings(
        &mut self,
        outbound: &Value,
        index: usize,
    ) -> Option<DnsOutboundSettings> {
        let settings_path = format!("$.outbounds[{index}].settings");
        let settings = match outbound.get("settings") {
            None | Some(Value::Null) => return Some(DnsOutboundSettings::default()),
            Some(settings) if settings.is_object() => settings,
            Some(_) => {
                self.error(
                    &settings_path,
                    "dns outbound settings must be an object or null",
                );
                return None;
            }
        };

        self.reject_unknown_fields(settings, &settings_path, &surface::DNS_OUTBOUND);

        // Xray unmarshals both spellings before Build applies the legacy
        // aliases. Keep type errors from either field visible, but defer
        // semantic validation until the effective value is known.
        let canonical_network = self.dns_rewrite_text_at(
            settings,
            "rewriteNetwork",
            format!("{settings_path}.rewriteNetwork"),
        )?;
        let legacy_network =
            self.dns_rewrite_text_at(settings, "network", format!("{settings_path}.network"))?;
        let rewrite_network = match legacy_network.filter(|network| !network.is_empty()) {
            Some(network) => {
                self.parse_dns_rewrite_network(network, format!("{settings_path}.network"))
            }
            None => canonical_network.and_then(|network| {
                self.parse_dns_rewrite_network(network, format!("{settings_path}.rewriteNetwork"))
            }),
        };

        let canonical_address = self.dns_rewrite_text_at(
            settings,
            "rewriteAddress",
            format!("{settings_path}.rewriteAddress"),
        )?;
        let legacy_address =
            self.dns_rewrite_text_at(settings, "address", format!("{settings_path}.address"))?;
        let rewrite_address = match legacy_address {
            Some(address) => {
                self.parse_dns_rewrite_address(address, format!("{settings_path}.address"))
            }
            None => canonical_address.and_then(|address| {
                self.parse_dns_rewrite_address(address, format!("{settings_path}.rewriteAddress"))
            }),
        };

        let mut rewrite_port = self.nullable_u16_at(
            settings,
            "rewritePort",
            format!("{settings_path}.rewritePort"),
        )?;
        let alias_port = self.nullable_u16_at(settings, "port", format!("{settings_path}.port"))?;
        if alias_port != 0 {
            rewrite_port = alias_port;
        }

        let user_level =
            self.nullable_u32_at(settings, "userLevel", format!("{settings_path}.userLevel"))?;

        let rules_present = settings.get("rules").is_some_and(|value| !value.is_null());
        let legacy_present = ["nonIPQuery", "blockTypes"]
            .iter()
            .any(|field| settings.get(*field).is_some_and(|value| !value.is_null()));
        if rules_present && legacy_present {
            self.error(
                format!("{settings_path}.rules"),
                "legacy nonIPQuery and blockTypes cannot be mixed with rules",
            );
            return None;
        }

        let rules = if legacy_present {
            let rules = self.parse_legacy_dns_outbound_rules(settings, &settings_path)?;
            self.warning(
                &settings_path,
                "dns outbound nonIPQuery and blockTypes are deprecated; use rules",
            );
            rules
        } else {
            self.parse_dns_outbound_rules(settings.get("rules"), &settings_path)?
        };

        Some(DnsOutboundSettings {
            rewrite_network,
            rewrite_address,
            rewrite_port,
            user_level,
            rules,
        })
    }

    pub(super) fn dns_rewrite_text_at<'a>(
        &mut self,
        settings: &'a Value,
        key: &str,
        path: String,
    ) -> Option<Option<&'a str>> {
        match settings.get(key) {
            None | Some(Value::Null) => Some(None),
            Some(Value::String(value)) => Some(Some(value)),
            Some(_) => {
                self.error(path, format!("field `{key}` must be a string or null"));
                None
            }
        }
    }

    pub(super) fn parse_dns_rewrite_network(
        &mut self,
        network: &str,
        path: String,
    ) -> Option<Network> {
        if network.is_empty() {
            None
        } else if network.eq_ignore_ascii_case("tcp") {
            Some(Network::Tcp)
        } else if network.eq_ignore_ascii_case("udp") {
            Some(Network::Udp)
        } else {
            self.error(path, format!("unsupported dns rewrite network `{network}`"));
            None
        }
    }

    pub(super) fn parse_dns_rewrite_address(
        &mut self,
        address: &str,
        path: String,
    ) -> Option<TargetAddr> {
        let address = normalize_xray_address_text(address);
        if address.starts_with("env:") {
            self.error(
                path,
                "dns rewrite address environment references are not supported",
            );
            return None;
        }
        if address.is_empty() {
            self.error(path, "dns rewrite address cannot be empty");
            return None;
        }

        Some(
            address
                .parse::<IpAddr>()
                .map_or_else(|_| TargetAddr::Domain(address.to_owned()), TargetAddr::Ip),
        )
    }

    pub(super) fn parse_dns_outbound_rules(
        &mut self,
        raw_rules: Option<&Value>,
        settings_path: &str,
    ) -> Option<Vec<DnsOutboundRule>> {
        let rules_path = format!("{settings_path}.rules");
        let rules = match raw_rules {
            None | Some(Value::Null) => return Some(Vec::new()),
            Some(Value::Array(rules)) => rules,
            Some(_) => {
                self.error(&rules_path, "dns outbound rules must be an array or null");
                return None;
            }
        };
        if !self.selector_budget.consume_dns_outbound_rules(rules.len()) {
            self.error(
                &rules_path,
                format!(
                    "configuration exceeds the DNS outbound rule budget (maximum {MAX_DNS_OUTBOUND_RULES})"
                ),
            );
            return None;
        }

        let mut parsed = Vec::with_capacity(rules.len());
        for (index, rule) in rules.iter().enumerate() {
            parsed.push(self.parse_dns_outbound_rule(rule, &format!("{rules_path}[{index}]"))?);
        }
        Some(parsed)
    }

    pub(super) fn parse_dns_outbound_rule(
        &mut self,
        rule: &Value,
        rule_path: &str,
    ) -> Option<DnsOutboundRule> {
        if !rule.is_object() {
            self.error(rule_path, "dns outbound rule must be an object");
            return None;
        }
        self.reject_unknown_fields(rule, rule_path, &surface::DNS_RULE);

        let action_path = format!("{rule_path}.action");
        let (action, legacy_reject) = match rule.get("action") {
            Some(Value::String(action)) if action.eq_ignore_ascii_case("direct") => {
                (DnsOutboundRuleAction::Direct, false)
            }
            Some(Value::String(action)) if action.eq_ignore_ascii_case("drop") => {
                (DnsOutboundRuleAction::Drop, false)
            }
            Some(Value::String(action)) if action.eq_ignore_ascii_case("return") => {
                (DnsOutboundRuleAction::Return, false)
            }
            Some(Value::String(action)) if action.eq_ignore_ascii_case("reject") => {
                self.warning(
                    &action_path,
                    "dns outbound action Reject is deprecated; use Return with rCode 5",
                );
                (DnsOutboundRuleAction::Return, true)
            }
            Some(Value::String(action)) if action.eq_ignore_ascii_case("hijack") => {
                (DnsOutboundRuleAction::Hijack, false)
            }
            Some(Value::String(action)) => {
                self.error(
                    action_path,
                    format!("unknown dns outbound action `{action}`"),
                );
                return None;
            }
            Some(_) => {
                self.error(action_path, "dns outbound rule action must be a string");
                return None;
            }
            None => {
                self.error(action_path, "missing dns outbound rule action");
                return None;
            }
        };

        let canonical_qtype = rule.get("qType").filter(|value| !value.is_null());
        let legacy_qtype = rule.get("qtype").filter(|value| !value.is_null());
        if canonical_qtype.is_some() && legacy_qtype.is_some() {
            self.error(
                format!("{rule_path}.qtype"),
                "dns outbound qType cannot be combined with deprecated qtype",
            );
            return None;
        }
        let (raw_qtype, qtype_path) = if let Some(raw) = legacy_qtype {
            let path = format!("{rule_path}.qtype");
            self.warning(&path, "dns outbound qtype is deprecated; use qType");
            (Some(raw), path)
        } else {
            (canonical_qtype, format!("{rule_path}.qType"))
        };
        let qtype_ranges = self.parse_dns_qtype_ranges(raw_qtype, &qtype_path)?;
        let domain_matchers =
            self.parse_dns_outbound_domain_matchers(rule.get("domain"), rule_path)?;
        let explicit_r_code = rule.get("rCode").is_some();
        let parsed_r_code = self.nullable_u16_at(rule, "rCode", format!("{rule_path}.rCode"))?;
        let r_code = if legacy_reject && !explicit_r_code {
            5
        } else {
            parsed_r_code
        };
        Some(DnsOutboundRule {
            action,
            r_code,
            qtype_ranges,
            domain_matchers,
        })
    }

    pub(super) fn parse_dns_qtype_ranges(
        &mut self,
        raw: Option<&Value>,
        path: &str,
    ) -> Option<Vec<DnsQTypeRange>> {
        let pairs = self.parse_u16_selector_ranges(raw, path, U16SelectorKind::DnsQType)?;
        let mut ranges = Vec::with_capacity(pairs.len());
        for (start, end) in pairs {
            match DnsQTypeRange::new(start, end) {
                Ok(range) => ranges.push(range),
                Err(error) => {
                    self.error(path, error.to_string());
                    return None;
                }
            }
        }
        Some(ranges)
    }

    pub(super) fn parse_dns_outbound_domain_matchers(
        &mut self,
        raw: Option<&Value>,
        rule_path: &str,
    ) -> Option<DomainMatcherSet> {
        let path = format!("{rule_path}.domain");
        let mut matchers = DomainMatcherSet::builder();
        match raw {
            None | Some(Value::Null) => return Some(DomainMatcherSet::default()),
            Some(Value::String(domains)) => {
                for (index, domain) in domains.split(',').enumerate() {
                    self.push_dns_outbound_domain_matcher(
                        domain,
                        &format!("{path}[{index}]"),
                        &mut matchers,
                    )?;
                }
            }
            Some(Value::Array(domains)) => {
                for (index, domain) in domains.iter().enumerate() {
                    let item_path = format!("{path}[{index}]");
                    let Some(domain) = domain.as_str() else {
                        self.error(item_path, "dns outbound domain matcher must be a string");
                        return None;
                    };
                    self.push_dns_outbound_domain_matcher(domain, &item_path, &mut matchers)?;
                }
            }
            Some(_) => {
                self.error(path, "dns outbound domain must be a string, array, or null");
                return None;
            }
        }
        self.build_domain_matcher_set(matchers, &path)
    }

    pub(super) fn push_dns_outbound_domain_matcher(
        &mut self,
        domain: &str,
        path: &str,
        matchers: &mut DomainMatcherSetBuilder,
    ) -> Option<()> {
        let remaining = self.matcher_budget.remaining_domain_matchers();
        if remaining == 0 {
            self.domain_matcher_budget_error(path);
            return None;
        }
        let parsed = self.parse_domain_matcher(domain, path, remaining)?;
        if !self.matcher_budget.consume_domain_matchers(parsed.len()) {
            self.domain_matcher_budget_error(path);
            return None;
        }
        insert_domain_matchers(matchers, &parsed, DomainNameMode::Dns);
        Some(())
    }

    pub(super) fn parse_legacy_dns_outbound_rules(
        &mut self,
        settings: &Value,
        settings_path: &str,
    ) -> Option<Vec<DnsOutboundRule>> {
        let mode_path = format!("{settings_path}.nonIPQuery");
        let mode = match settings.get("nonIPQuery") {
            None | Some(Value::Null) => LegacyDnsNonIpMode::Reject,
            Some(Value::String(mode)) if mode.is_empty() => LegacyDnsNonIpMode::Reject,
            Some(Value::String(mode)) if mode == "reject" => LegacyDnsNonIpMode::Reject,
            Some(Value::String(mode)) if mode == "drop" => LegacyDnsNonIpMode::Drop,
            Some(Value::String(mode)) if mode == "skip" => LegacyDnsNonIpMode::Skip,
            Some(Value::String(mode)) => {
                self.error(
                    mode_path,
                    format!("unknown dns outbound nonIPQuery `{mode}`"),
                );
                return None;
            }
            Some(_) => {
                self.error(
                    mode_path,
                    "dns outbound nonIPQuery must be a string or null",
                );
                return None;
            }
        };

        let block_path = format!("{settings_path}.blockTypes");
        let mut blocked = Vec::new();
        match settings.get("blockTypes") {
            None | Some(Value::Null) => {}
            Some(Value::Array(values)) => {
                for (index, value) in values.iter().enumerate() {
                    let item_path = format!("{block_path}[{index}]");
                    if !self.selector_budget.consume_dns_qtype_selector() {
                        self.dns_qtype_selector_budget_error(&item_path);
                        return None;
                    }
                    let Some(value) = value.as_i64().and_then(|value| u16::try_from(value).ok())
                    else {
                        self.error(item_path, "dns outbound blockTypes value must fit in u16");
                        return None;
                    };
                    blocked.push((value, value));
                }
            }
            Some(_) => {
                self.error(
                    block_path,
                    "dns outbound blockTypes must be an array or null",
                );
                return None;
            }
        }
        let blocked = normalize_u16_ranges(blocked);
        let rule_count = usize::from(!blocked.is_empty()) + 2;
        if !self.selector_budget.consume_dns_outbound_rules(rule_count) {
            self.error(
                settings_path,
                format!(
                    "configuration exceeds the DNS outbound rule budget (maximum {MAX_DNS_OUTBOUND_RULES})"
                ),
            );
            return None;
        }

        let mut rules = Vec::with_capacity(rule_count);
        if !blocked.is_empty() {
            let mut qtype_ranges = Vec::with_capacity(blocked.len());
            for (start, end) in blocked {
                match DnsQTypeRange::new(start, end) {
                    Ok(range) => qtype_ranges.push(range),
                    Err(error) => {
                        self.error(&block_path, error.to_string());
                        return None;
                    }
                }
            }
            rules.push(DnsOutboundRule {
                action: if mode == LegacyDnsNonIpMode::Reject {
                    DnsOutboundRuleAction::Return
                } else {
                    DnsOutboundRuleAction::Drop
                },
                r_code: if mode == LegacyDnsNonIpMode::Reject {
                    5
                } else {
                    0
                },
                qtype_ranges,
                domain_matchers: DomainMatcherSet::default(),
            });
        }
        rules.push(DnsOutboundRule {
            action: DnsOutboundRuleAction::Hijack,
            r_code: 0,
            qtype_ranges: vec![DnsQTypeRange::single(1), DnsQTypeRange::single(28)],
            domain_matchers: DomainMatcherSet::default(),
        });
        rules.push(DnsOutboundRule {
            action: match mode {
                LegacyDnsNonIpMode::Reject => DnsOutboundRuleAction::Return,
                LegacyDnsNonIpMode::Drop => DnsOutboundRuleAction::Drop,
                LegacyDnsNonIpMode::Skip => DnsOutboundRuleAction::Direct,
            },
            r_code: if mode == LegacyDnsNonIpMode::Reject {
                5
            } else {
                0
            },
            qtype_ranges: Vec::new(),
            domain_matchers: DomainMatcherSet::default(),
        });
        Some(rules)
    }
}
