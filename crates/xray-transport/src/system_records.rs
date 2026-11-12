//! SRV and TXT lookups as Xray-core makes them for `addressPortStrategy`.
//!
//! Xray-core asks Go's `net.DefaultResolver`, and Go answers SRV and TXT
//! lookups with its own DNS client on every Unix, macOS, iOS and Android
//! included: it reads `/etc/resolv.conf` and asks those nameservers over UDP,
//! then over TCP when an answer is truncated. The platform's resolver is
//! never asked. Without the file, as on Android, Go asks `127.0.0.1:53` and
//! `[::1]:53`. This module follows Go 1.27's `net` package, except that on
//! Android, iOS and tvOS a missing file skips the lookup, with one warning,
//! instead of asking loopback nameservers no phone runs; the dial goes on
//! with the configured server, as Go's failed lookup leaves it.
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;

use crate::{
    dns::{exchange_direct_tcp_candidates, exchange_direct_udp, read_dns_name, read_u16},
    dns_response_matches_query, SocketProtector,
};

/// One SRV record, as Go's `net.SRV` holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    /// The target in lower case without the root's trailing dot; `.` is the
    /// root itself, which RFC 2782 uses to say there is no such service.
    pub target: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

/// The SRV and TXT lookups an outbound's `addressPortStrategy` makes.
#[async_trait]
pub trait RecordResolver: Send + Sync {
    /// Go's `LookupSRV(ctx, service, proto, name)`: the records of
    /// `_service._proto.name`, or of `name` when both are empty, sorted by
    /// priority and shuffled by weight within each priority. A record whose
    /// target is not a domain name fails the lookup, as it does in Go.
    async fn lookup_srv(
        &self,
        service: &str,
        proto: &str,
        name: &str,
    ) -> io::Result<Vec<SrvRecord>>;

    /// Go's `LookupTXT`: the TXT records of `name`, each one's strings
    /// joined.
    async fn lookup_txt(&self, name: &str) -> io::Result<Vec<String>>;
}

/// Go's resolver, reading `/etc/resolv.conf` on each lookup. Its sockets
/// take the platform's protection, so on a mobile VPN they bypass the
/// tunnel as the core's other direct DNS sockets do.
#[derive(Clone)]
pub struct SystemRecordResolver {
    config: PathBuf,
    protector: Option<Arc<dyn SocketProtector>>,
    /// Whether a missing `config` skips the lookup rather than falling back
    /// to Go's loopback nameservers.
    skips_without_config: bool,
}

impl std::fmt::Debug for SystemRecordResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemRecordResolver")
            .field("config", &self.config)
            .field("protected", &self.protector.is_some())
            .finish()
    }
}

impl SystemRecordResolver {
    pub fn new(protector: Option<Arc<dyn SocketProtector>>) -> Self {
        Self::with_config("/etc/resolv.conf", protector)
    }

    /// Reads its nameservers and options from `config` instead.
    pub fn with_config(
        config: impl Into<PathBuf>,
        protector: Option<Arc<dyn SocketProtector>>,
    ) -> Self {
        Self {
            config: config.into(),
            protector,
            skips_without_config: cfg!(any(
                target_os = "android",
                target_os = "ios",
                target_os = "tvos"
            )),
        }
    }

    /// The configuration to ask, or a failed lookup on a phone without one.
    fn read_config(&self) -> io::Result<ResolvConf> {
        if self.skips_without_config && !self.config.exists() {
            if !WARNED_WITHOUT_CONFIG.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    config = %self.config.display(),
                    "no resolver configuration: addressPortStrategy SRV and TXT lookups are skipped and servers are dialled as configured"
                );
            }
            return Err(no_such_host());
        }
        Ok(ResolvConf::read(&self.config))
    }

    /// Go's `lookup`: each name of the search list in turn, until one has
    /// records of `qtype`.
    async fn lookup(&self, conf: &ResolvConf, name: &str, qtype: u16) -> io::Result<Answers> {
        if !is_domain_name(name) {
            return Err(no_such_host());
        }
        let mut last = no_such_host();
        for fqdn in conf.name_list(name) {
            match self.try_one_name(conf, &fqdn, qtype).await {
                Ok(answers) => return Ok(answers),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Go's `tryOneName`: every server, `attempts` times, until one answers
    /// or says the name does not exist.
    async fn try_one_name(&self, conf: &ResolvConf, fqdn: &str, qtype: u16) -> io::Result<Answers> {
        let offset = if conf.rotate {
            ROTATION.fetch_add(1, Ordering::Relaxed)
        } else {
            0
        };
        let count = conf.servers.len() as u32;
        let mut last = io::Error::other("no DNS server answered");
        for _ in 0..conf.attempts {
            for index in 0..count {
                let server = conf.servers[((offset.wrapping_add(index)) % count) as usize];
                let response = match self.exchange(conf, server, fqdn, qtype).await {
                    Ok(response) => response,
                    Err(error) => {
                        last = error;
                        continue;
                    }
                };
                match check_response(&response, qtype) {
                    Checked::Answers(answers) => return Ok(answers),
                    Checked::NoSuchHost => return Err(no_such_host()),
                    Checked::NextServer(error) => last = error,
                }
            }
        }
        Err(last)
    }

    /// Go's `exchange`: UDP, then TCP when the answer is truncated, or TCP
    /// alone under `use-vc`, each within the configured timeout.
    async fn exchange(
        &self,
        conf: &ResolvConf,
        server: SocketAddr,
        fqdn: &str,
        qtype: u16,
    ) -> io::Result<Vec<u8>> {
        let query = build_query(rand::random(), fqdn, qtype, conf.trust_ad)?;
        let protector = self.protector.as_deref();
        if !conf.use_tcp {
            let udp =
                tokio::time::timeout(conf.timeout, exchange_direct_udp(server, &query, protector))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out")
                    })??;
            if !truncated(&udp) {
                return Ok(udp);
            }
        }
        let tcp = tokio::time::timeout(
            conf.timeout,
            exchange_direct_tcp_candidates(&[server], &query, protector),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))??;
        if !dns_response_matches_query(&query, &tcp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response does not match its query",
            ));
        }
        Ok(tcp)
    }
}

impl SystemRecordResolver {
    async fn srv(
        &self,
        conf: &ResolvConf,
        service: &str,
        proto: &str,
        name: &str,
    ) -> io::Result<Vec<SrvRecord>> {
        let target = if service.is_empty() && proto.is_empty() {
            name.to_owned()
        } else {
            format!("_{service}._{proto}.{name}")
        };
        let Answers::Srv(mut records) = self.lookup(conf, &target, TYPE_SRV).await? else {
            unreachable!("an SRV lookup answers SRV records")
        };
        if records
            .iter()
            .any(|record| record.target != "." && !is_domain_name(&record.target))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response contained records which contain invalid names",
            ));
        }
        sort_by_priority_weight(&mut records, random_below);
        Ok(records)
    }

    async fn txt(&self, conf: &ResolvConf, name: &str) -> io::Result<Vec<String>> {
        let Answers::Txt(records) = self.lookup(conf, name, TYPE_TXT).await? else {
            unreachable!("a TXT lookup answers TXT records")
        };
        Ok(records)
    }
}

#[async_trait]
impl RecordResolver for SystemRecordResolver {
    async fn lookup_srv(
        &self,
        service: &str,
        proto: &str,
        name: &str,
    ) -> io::Result<Vec<SrvRecord>> {
        let conf = self.read_config()?;
        self.srv(&conf, service, proto, name).await
    }

    async fn lookup_txt(&self, name: &str) -> io::Result<Vec<String>> {
        let conf = self.read_config()?;
        self.txt(&conf, name).await
    }
}

/// Whether a phone without a resolver configuration has said so once.
static WARNED_WITHOUT_CONFIG: AtomicBool = AtomicBool::new(false);

/// Go's `soffset`, the next first server under `options rotate`.
static ROTATION: AtomicU32 = AtomicU32::new(0);

const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;
/// Go's `maxDNSPacketSize`, the UDP size its EDNS(0) record offers.
const EDNS_UDP_SIZE: u16 = 1232;

/// The records of one answer, of the type asked for.
#[derive(Debug, PartialEq, Eq)]
enum Answers {
    Srv(Vec<SrvRecord>),
    Txt(Vec<String>),
}

enum Checked {
    Answers(Answers),
    /// The name does not exist, or has no record of the type: another
    /// server will not help.
    NoSuchHost,
    /// This server failed or answered nothing usable.
    NextServer(io::Error),
}

fn no_such_host() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no such host")
}

/// The nameservers, search list and options Go reads from
/// `/etc/resolv.conf`, with its defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvConf {
    servers: Vec<SocketAddr>,
    /// Rooted, with their trailing dots.
    search: Vec<String>,
    ndots: usize,
    timeout: Duration,
    attempts: u32,
    rotate: bool,
    use_tcp: bool,
    trust_ad: bool,
}

impl ResolvConf {
    /// Go's `dnsReadConfig`.
    fn read(path: &std::path::Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => Self::parse(&String::from_utf8_lossy(&bytes), default_search),
            Err(_) => Self {
                servers: default_servers(),
                search: default_search(),
                ..Self::defaults()
            },
        }
    }

    fn defaults() -> Self {
        Self {
            servers: Vec::new(),
            search: Vec::new(),
            ndots: 1,
            timeout: Duration::from_secs(5),
            attempts: 2,
            rotate: false,
            use_tcp: false,
            trust_ad: false,
        }
    }

    fn parse(text: &str, default_search: impl FnOnce() -> Vec<String>) -> Self {
        let mut conf = Self::defaults();
        // A comment, `#` or `;` first, names no keyword, so it falls through
        // as Go skips it.
        for line in text.split('\n') {
            let fields: Vec<&str> = line
                .split([' ', '\r', '\t', '\n'])
                .filter(|field| !field.is_empty())
                .collect();
            match fields.as_slice() {
                ["nameserver", server, ..] if conf.servers.len() < 3 => {
                    if let Some(server) = parse_nameserver(server) {
                        conf.servers.push(server);
                    }
                }
                ["domain", domain, ..] => conf.search = vec![ensure_rooted(domain)],
                ["search", names @ ..] => {
                    conf.search = names
                        .iter()
                        .map(|name| ensure_rooted(name))
                        .filter(|name| name != ".")
                        .collect();
                }
                ["options", options @ ..] => {
                    for option in options {
                        if let Some(value) = option.strip_prefix("ndots:") {
                            conf.ndots = dtoi(value).min(15);
                        } else if let Some(value) = option.strip_prefix("timeout:") {
                            conf.timeout = Duration::from_secs(dtoi(value).max(1) as u64);
                        } else if let Some(value) = option.strip_prefix("attempts:") {
                            conf.attempts = dtoi(value).max(1) as u32;
                        } else {
                            match *option {
                                "rotate" => conf.rotate = true,
                                "use-vc" | "usevc" | "tcp" => conf.use_tcp = true,
                                "trust-ad" => conf.trust_ad = true,
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if conf.servers.is_empty() {
            conf.servers = default_servers();
        }
        if conf.search.is_empty() {
            conf.search = default_search();
        }
        conf
    }

    /// Go's `nameList`: the names to try for `name`, in order.
    fn name_list(&self, name: &str) -> Vec<String> {
        let length = name.len();
        let rooted = name.ends_with('.');
        if length > 254 || length == 254 && !rooted {
            return Vec::new();
        }
        if rooted {
            return if avoid_dns(name) {
                Vec::new()
            } else {
                vec![name.to_owned()]
            };
        }
        let has_ndots = name.bytes().filter(|byte| *byte == b'.').count() >= self.ndots;
        let name = format!("{name}.");
        let mut names = Vec::with_capacity(1 + self.search.len());
        if has_ndots && !avoid_dns(&name) {
            names.push(name.clone());
        }
        for suffix in &self.search {
            let fqdn = format!("{name}{suffix}");
            if !avoid_dns(&fqdn) && fqdn.len() <= 254 {
                names.push(fqdn);
            }
        }
        if !has_ndots && !avoid_dns(&name) {
            names.push(name);
        }
        names
    }
}

/// Go's `defaultNS`.
fn default_servers() -> Vec<SocketAddr> {
    vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53),
    ]
}

/// Go's `dnsDefaultSearch`: the domain of the host's name, if it has one.
fn default_search() -> Vec<String> {
    let Some(hostname) = hostname() else {
        return Vec::new();
    };
    match hostname.find('.') {
        Some(dot) if dot < hostname.len() - 1 => vec![ensure_rooted(&hostname[dot + 1..])],
        _ => Vec::new(),
    }
}

#[cfg(unix)]
fn hostname() -> Option<String> {
    let mut buffer = [0_u8; 256];
    // SAFETY: the buffer is writable for its whole length.
    let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if result != 0 {
        return None;
    }
    let end = buffer.iter().position(|byte| *byte == 0)?;
    String::from_utf8(buffer[..end].to_vec()).ok()
}

#[cfg(not(unix))]
fn hostname() -> Option<String> {
    None
}

/// A `nameserver` line's address, as Go's `netip.ParseAddr` takes it: an
/// IPv4 or IPv6 literal, the latter with an optional zone.
fn parse_nameserver(text: &str) -> Option<SocketAddr> {
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    let (address, zone) = text.split_once('%')?;
    let address = address.parse::<Ipv6Addr>().ok()?;
    if zone.is_empty() {
        return None;
    }
    Some(SocketAddr::V6(SocketAddrV6::new(
        address,
        53,
        0,
        zone_index(zone),
    )))
}

/// The interface index a zone names: a number, or an interface's name.
fn zone_index(zone: &str) -> u32 {
    if let Ok(index) = zone.parse() {
        return index;
    }
    #[cfg(unix)]
    {
        let Ok(name) = std::ffi::CString::new(zone) else {
            return 0;
        };
        // SAFETY: `name` is a NUL-terminated string that outlives the call.
        unsafe { libc::if_nametoindex(name.as_ptr()) }
    }
    #[cfg(not(unix))]
    0
}

/// Go's `dtoi`: the leading decimal digits, zero when there are none, and
/// capped at its `big`.
fn dtoi(text: &str) -> usize {
    const BIG: usize = 0xFF_FFFF;
    let mut value = 0_usize;
    for byte in text.bytes() {
        if !byte.is_ascii_digit() {
            break;
        }
        value = value * 10 + usize::from(byte - b'0');
        if value >= BIG {
            return BIG;
        }
    }
    value
}

fn ensure_rooted(name: &str) -> String {
    if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    }
}

/// Go's `avoidDNS`: names Go never sends to a nameserver.
fn avoid_dns(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    name.len() >= ".onion".len()
        && name[name.len() - ".onion".len()..].eq_ignore_ascii_case(".onion")
}

/// Go's `isDomainName`.
pub fn is_domain_name(name: &str) -> bool {
    if name == "." {
        return true;
    }
    let bytes = name.as_bytes();
    let length = bytes.len();
    if length == 0 || length > 254 || length == 254 && bytes[length - 1] != b'.' {
        return false;
    }
    let mut last = b'.';
    let mut non_numeric = false;
    let mut part = 0;
    for &byte in bytes {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                part += 1;
            }
            b'0'..=b'9' => part += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                part += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' || part > 63 || part == 0 {
                    return false;
                }
                part = 0;
            }
            _ => return false,
        }
        last = byte;
    }
    last != b'-' && part <= 63 && non_numeric
}

/// The query Go's `newRequest` builds: recursion desired, the AD bit under
/// `options trust-ad`, and an EDNS(0) record offering 1232 bytes.
fn build_query(id: u16, fqdn: &str, qtype: u16, trust_ad: bool) -> io::Result<Vec<u8>> {
    let mut query = Vec::with_capacity(12 + fqdn.len() + 16);
    query.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = 0x0100 | if trust_ad { 0x0020 } else { 0 };
    query.extend_from_slice(&flags.to_be_bytes());
    query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]);
    for label in fqdn.trim_end_matches('.').split('.') {
        let length = u8::try_from(label.len())
            .ok()
            .filter(|length| (1..=63).contains(length))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS name"))?;
        query.push(length);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    // OPT: the root name, the UDP size as its class, no extended code,
    // version or flags, and no options.
    query.push(0);
    query.extend_from_slice(&41_u16.to_be_bytes());
    query.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes());
    query.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    Ok(query)
}

fn truncated(response: &[u8]) -> bool {
    response.get(2).is_some_and(|flags| flags & 0x02 != 0)
}

/// Go's `checkHeader` and `skipToAnswer`, then the records of `qtype` in
/// the answer section.
fn check_response(response: &[u8], qtype: u16) -> Checked {
    let malformed = || {
        Checked::NextServer(io::Error::new(
            io::ErrorKind::InvalidData,
            "cannot unmarshal DNS message",
        ))
    };
    let (Ok(flags), Ok(answers), Ok(authorities), Ok(additionals)) = (
        read_u16(response, 2),
        read_u16(response, 6),
        read_u16(response, 8),
        read_u16(response, 10),
    ) else {
        return malformed();
    };
    let rcode = flags & 0x000F;
    if rcode == 3 {
        return Checked::NoSuchHost;
    }
    let authoritative = flags & 0x0400 != 0;
    let recursion_available = flags & 0x0080 != 0;
    // libresolv moves on from a lame referral, and so does Go.
    if rcode == 0 && !authoritative && !recursion_available && answers == 0 && additionals == 0 {
        return Checked::NextServer(io::Error::other("lame referral"));
    }
    if rcode != 0 {
        return Checked::NextServer(io::Error::other(if rcode == 2 {
            "server misbehaving (SERVFAIL)"
        } else {
            "server misbehaving"
        }));
    }
    let _ = authorities;
    let Ok(records) = parse_answers(response, answers, qtype) else {
        return malformed();
    };
    match records {
        Answers::Srv(srv) if srv.is_empty() => Checked::NoSuchHost,
        Answers::Txt(txt) if txt.is_empty() => Checked::NoSuchHost,
        records => Checked::Answers(records),
    }
}

/// The answer section's records of `qtype`, skipping the others.
fn parse_answers(response: &[u8], answers: u16, qtype: u16) -> io::Result<Answers> {
    let mut offset = 12;
    read_dns_name(response, &mut offset)?;
    offset += 4;
    let mut srv = Vec::new();
    let mut txt = Vec::new();
    for _ in 0..answers {
        read_dns_name(response, &mut offset)?;
        let kind = read_u16(response, offset)?;
        let length = usize::from(read_u16(response, offset + 8)?);
        let start = offset + 10;
        let end = start + length;
        if end > response.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated DNS record",
            ));
        }
        if kind == qtype && qtype == TYPE_SRV {
            if length < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short SRV record",
                ));
            }
            let mut name_offset = start + 6;
            let target = read_dns_name(&response[..end], &mut name_offset)?;
            srv.push(SrvRecord {
                target: if target.is_empty() {
                    ".".to_owned()
                } else {
                    target
                },
                priority: read_u16(response, start)?,
                weight: read_u16(response, start + 2)?,
                port: read_u16(response, start + 4)?,
            });
        } else if kind == qtype && qtype == TYPE_TXT {
            let mut joined = Vec::with_capacity(length);
            let mut cursor = start;
            while cursor < end {
                let part = usize::from(response[cursor]);
                let part_end = cursor + 1 + part;
                if part_end > end {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated TXT record",
                    ));
                }
                joined.extend_from_slice(&response[cursor + 1..part_end]);
                cursor = part_end;
            }
            txt.push(String::from_utf8_lossy(&joined).into_owned());
        }
        offset = end;
    }
    Ok(if qtype == TYPE_SRV {
        Answers::Srv(srv)
    } else {
        Answers::Txt(txt)
    })
}

/// Go's `byPriorityWeight.sort`: by priority, then each priority's records
/// shuffled by weight as RFC 2782 picks them. `draw(sum)` returns a number
/// below `sum`.
fn sort_by_priority_weight(records: &mut [SrvRecord], mut draw: impl FnMut(u32) -> u32) {
    records.sort_by_key(|record| (record.priority, record.weight));
    let mut start = 0;
    while start < records.len() {
        let priority = records[start].priority;
        let end = records[start..]
            .iter()
            .position(|record| record.priority != priority)
            .map_or(records.len(), |offset| start + offset);
        shuffle_by_weight(&mut records[start..end], &mut draw);
        start = end;
    }
}

/// Go's `shuffleByWeight`.
fn shuffle_by_weight(mut records: &mut [SrvRecord], draw: &mut impl FnMut(u32) -> u32) {
    let mut sum: u32 = records.iter().map(|record| u32::from(record.weight)).sum();
    while sum > 0 && records.len() > 1 {
        let pick = draw(sum);
        let mut running = 0;
        for index in 0..records.len() {
            running += u32::from(records[index].weight);
            if running > pick {
                records.swap(0, index);
                break;
            }
        }
        sum -= u32::from(records[0].weight);
        records = &mut records[1..];
    }
}

fn random_below(bound: u32) -> u32 {
    use rand::Rng;
    rand::thread_rng().gen_range(0..bound)
}

#[cfg(test)]
mod tests;
