# Xray Core Config Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Rust library load and execute the provided Xray-core VLESS REALITY config with the same compatibility shape as Xray-core: ignored/no-op fields must not fail parsing, and behavior-changing fields must be modeled and implemented in the runtime.

**Architecture:** Split the work into a compatibility parser/model layer and runtime behavior layers. `xray-config` owns schema normalization, accept-and-ignore decisions, geodata expansion, DNS policy data, inbound sniffing settings, routing domain strategy, VLESS user level, and policy data. `xray-transport` owns resolver behavior. `xray-core-rs` owns route selection, sniffing, policy timeouts, and data-path integration. Keep Xray-core parity checks as an oracle test for the exact JSON fixture.

**Tech Stack:** Rust 2021, serde_json, Tokio, async-trait, existing `xray-config`, `xray-transport`, `xray-core-rs`, `xray-routing`, Cargo tests, local Xray-core `run -test` as an oracle.

---

## Compatibility Decisions

The user confirmed that skipped fields mean **accept-and-ignore**:

- `sniffing.excludedDomains`: parse without error, no runtime effect for now. Xray-core uses `domainsExcluded`; this spelling is ignored upstream, and it is empty in the fixture.
- `routing.rules[].ruleTag`: parse without error, no rule API/logging behavior for now.
- `routing.rules[].outboundTag: "api"` without an `api` outbound: do not reject at parse time. If a live route selects a missing tag, return the existing runtime `NoSupportedOutbound` behavior. In the fixture this rule is dead because there is no `api` inbound.
- `streamSettings.realitySettings.allowInsecure`: parse without error, no runtime effect.
- `mux.concurrency` when `mux.enabled == false`: parse without error, no runtime effect.

Not skipped and required:

- Top-level `policy`, including levels and system stats fields.
- VLESS user `level`.
- VLESS user `security` as Xray-core-compatible ignored input. Xray-core ignores this outbound user field, but our parser currently treats it as unsupported.
- `routing.domainStrategy: "IPIfNonMatch"`.
- `dns.servers` and `dns.hosts`.
- `sniffing.enabled`, `destOverride`, `metadataOnly`, and `routeOnly`.

## Fixture

Create one exact fixture for the user config:

- Create: `tests/fixtures/configs/xray_core_reality_split_routing_full.json`

Use the full JSON supplied in the thread, formatted as stable pretty JSON. Keep these important fields in the fixture:

```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "direct",
        "ruleTag": "rule_exclusions_domain",
        "domain": ["geosite:category-ru"]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ruleTag": "rule_exclusions_ip",
        "ip": ["geoip:ru"]
      },
      {
        "type": "field",
        "outboundTag": "outbound_49783",
        "ruleTag": "rule_49783",
        "inboundTag": ["inbound_49783"]
      },
      {
        "type": "field",
        "outboundTag": "api",
        "ruleTag": "rule_api",
        "inboundTag": ["api"]
      }
    ]
  },
  "inbounds": [
    {
      "settings": { "udp": true },
      "protocol": "socks",
      "tag": "inbound_49783",
      "sniffing": {
        "excludedDomains": [],
        "enabled": true,
        "routeOnly": true,
        "metadataOnly": false,
        "destOverride": ["http", "tls", "quic"]
      },
      "listen": "[::1]",
      "port": 49783
    }
  ],
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": false,
        "uplinkOnly": 1,
        "downlinkOnly": 2,
        "bufferSize": 8,
        "handshake": 10,
        "connIdle": 300,
        "statsUserDownlink": false
      }
    },
    "system": {
      "statsOutboundDownlink": false,
      "statsInboundUplink": false,
      "statsOutboundUplink": false,
      "statsInboundDownlink": false
    }
  },
  "dns": {
    "servers": ["1.1.1.1", "8.8.8.8", "8.8.4.4"],
    "hosts": {
      "domain:googleapis.cn": "googleapis.com"
    }
  }
}
```

The fixture should include the full `outbounds` object with VLESS, REALITY, Vision, disabled mux concurrency, `security: "auto"`, and `allowInsecure: false`.

## Task 1: Parser Oracle And Red Compatibility Test

**Files:**
- Create: `tests/fixtures/configs/xray_core_reality_split_routing_full.json`
- Modify: `crates/xray-config/tests/parser_tests.rs`

- [ ] **Step 1: Add a parser test for the exact fixture**

Add a test that loads the fixture through `parse_xray_json_with_geodata_dir` using the checked-in geodata directory:

```rust
#[test]
fn parses_xray_core_reality_split_routing_fixture() {
    let raw = include_str!("../../../tests/fixtures/configs/xray_core_reality_split_routing_full.json");
    let parsed = parse_xray_json_with_geodata_dir(
        raw,
        "../../../platform/apple/XrayClient/dat",
    )
    .expect("fixture accepted by xray-core should parse");

    assert_eq!(parsed.config.routing.domain_strategy, RoutingDomainStrategy::IpIfNonMatch);
    assert_eq!(parsed.config.inbounds[0].sniffing.as_ref().unwrap().route_only, true);
    assert_eq!(parsed.config.dns.servers.len(), 3);
    assert!(parsed.config.policy.levels.contains_key(&0));
}
```

- [ ] **Step 2: Run the red test**

Run:

```bash
cargo test -p xray-config --test parser_tests parses_xray_core_reality_split_routing_fixture
```

Expected: FAIL with the current unsupported-field errors.

- [ ] **Step 3: Keep an Xray-core oracle command next to the fixture**

Add a short comment near the test or a helper doc snippet with this command:

```bash
XRAY_LOCATION_ASSET=/Users/antonmalygin/xray-rust/platform/apple/XrayClient/dat \
  go run ./main run -test -format json < /Users/antonmalygin/xray-rust/tests/fixtures/configs/xray_core_reality_split_routing_full.json
```

Expected oracle output from the local Xray-core checkout:

```text
Configuration OK.
```

## Task 2: Extend Config Model

**Files:**
- Modify: `crates/xray-config/src/model.rs`
- Modify call sites that construct `CoreConfig`, `InboundConfig`, or `VlessUser`.

- [ ] **Step 1: Add routing domain strategy**

Add:

```rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RoutingDomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
}
```

Update:

```rust
pub struct RoutingConfig {
    pub rules: Vec<RoutingRule>,
    pub domain_strategy: RoutingDomainStrategy,
}
```

- [ ] **Step 2: Add DNS config model**

Extend `DnsConfig`:

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsConfig {
    pub fake_ip: Option<DnsFakeIpConfig>,
    pub servers: Vec<DnsServerConfig>,
    pub hosts: Vec<DnsHostMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsServerConfig {
    Ip(std::net::SocketAddr),
    Domain { domain: String, port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHostMapping {
    pub matcher: DomainMatcher,
    pub target: DnsHostTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsHostTarget {
    Ip(std::net::IpAddr),
    Domain(String),
}
```

Default DNS server ports to 53 for bare IP/domain server entries. Preserve existing `fake_ip` behavior.

- [ ] **Step 3: Add inbound sniffing model**

Extend `InboundConfig`:

```rust
pub struct InboundConfig {
    pub tag: Option<String>,
    pub protocol: InboundProtocol,
    pub listen: String,
    pub port: u16,
    pub sniffing: Option<InboundSniffingConfig>,
}
```

Add:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSniffingConfig {
    pub enabled: bool,
    pub dest_override: Vec<SniffingDestination>,
    pub metadata_only: bool,
    pub route_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffingDestination {
    Http,
    Tls,
    Quic,
}
```

Treat missing `sniffing` and `enabled: false` as `None`.

- [ ] **Step 4: Add policy model**

Add to `CoreConfig`:

```rust
pub policy: PolicyConfig,
```

Add:

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyConfig {
    pub levels: std::collections::BTreeMap<u32, PolicyLevelConfig>,
    pub system: PolicySystemConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyLevelConfig {
    pub handshake: Option<u64>,
    pub conn_idle: Option<u64>,
    pub uplink_only: Option<u64>,
    pub downlink_only: Option<u64>,
    pub buffer_size: Option<i32>,
    pub stats_user_uplink: bool,
    pub stats_user_downlink: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySystemConfig {
    pub stats_inbound_uplink: bool,
    pub stats_inbound_downlink: bool,
    pub stats_outbound_uplink: bool,
    pub stats_outbound_downlink: bool,
}
```

Store values as seconds for timeout fields, matching the incoming Xray JSON shape.

- [ ] **Step 5: Add VLESS user level**

Update:

```rust
pub struct VlessUser {
    pub id: Uuid,
    pub encryption: String,
    pub flow: Option<String>,
    pub level: u32,
}
```

Default to level `0`. Update all test helpers and constructors in `crates/xray-core-rs/tests` and any model tests.

## Task 3: Parser Compatibility

**Files:**
- Modify: `crates/xray-config/src/parser.rs`
- Modify: `crates/xray-config/tests/parser_tests.rs`

- [ ] **Step 1: Top-level policy**

Update the top-level allowlist:

```rust
&["log", "inbounds", "outbounds", "routing", "dns", "policy"]
```

Parse `policy` after `dns` or before `routing`; the order does not matter. Unknown fields inside `policy.levels.*` should be rejected unless Xray-core accepts them and they are known no-op compatibility fields. For this slice, accept the fields listed in the fixture and reject other behavior-changing policy fields with paths.

- [ ] **Step 2: Routing domain strategy**

Parse:

```rust
match strategy.unwrap_or("AsIs") {
    "AsIs" => RoutingDomainStrategy::AsIs,
    "IPIfNonMatch" => RoutingDomainStrategy::IpIfNonMatch,
    other => error("$.routing.domainStrategy", format!("unsupported routing domainStrategy `{other}`")),
}
```

Keep `balancers` unsupported.

- [ ] **Step 3: Routing rule compatibility**

Update routing rule allowlist to include `ruleTag`.

Remove parse-time outbound tag existence validation. Xray-core accepts missing route targets at load time and only fails if traffic selects them. Add tests with this behavior:

- `accepts_rule_tag_without_runtime_effect`: parse a rule with `ruleTag`, assert parsing succeeds, assert route matching still depends only on inbound/domain/IP/outbound tag.
- `accepts_missing_outbound_tag_until_runtime_selection`: parse a rule whose `outboundTag` is absent from `outbounds`, assert parsing succeeds, and cover the runtime error in Task 5.

Keep empty `outboundTag` as an error.

- [ ] **Step 4: DNS servers and hosts parser**

Update `parse_dns` allowlist:

```rust
&["fakeIp", "servers", "hosts"]
```

Implement:

- `servers`: accept array of strings for this slice. Parse IP strings as `DnsServerConfig::Ip(SocketAddr::new(ip, 53))`; parse `host:port` if already supported by the existing address parsing helpers or add a small helper. Reject unsupported object server syntax for now unless tests show it is required.
- `hosts`: accept object map. Parse keys through the existing domain matcher parser rules, at least `domain:`, `full:`, `regexp:`, and bare domains. Parse values as string IP or alias domain. Add array support only if a fixture or Xray-core parity test requires it.

Add tests for:

- `domain:googleapis.cn` mapping to `googleapis.com`.
- DNS server `1.1.1.1` defaulting to port 53.
- Existing `fakeIp` behavior still works.

- [ ] **Step 5: Inbound sniffing parser**

Replace `validate_inbound_sniffing` with `parse_inbound_sniffing`.

Accept allowlist:

```rust
&[
    "enabled",
    "destOverride",
    "metadataOnly",
    "routeOnly",
    "domainsExcluded",
    "excludedDomains",
]
```

Behavior:

- `enabled: false` or missing returns `None`.
- `enabled: true` returns `InboundSniffingConfig`.
- `destOverride` accepts `http`, `tls`, `quic`; reject unknown values.
- `metadataOnly` defaults false.
- `routeOnly` defaults false.
- `domainsExcluded` can be parsed into matchers if implemented immediately; otherwise accept-and-ignore only if empty. `excludedDomains` is confirmed accept-and-ignore.

Add tests for enabled sniffing and for `excludedDomains: ["example.com"]` being accepted but not represented.

- [ ] **Step 6: VLESS user compatibility**

Update VLESS user allowlist:

```rust
&["id", "encryption", "flow", "level", "email", "security"]
```

Parse `level` as `u32`, default 0. Accept `security` and do not store it. Add tests for `security: "auto"` and `level: 8`.

- [ ] **Step 7: REALITY and disabled mux compatibility**

Update REALITY settings allowlist to include `allowInsecure`. Do not copy it into `RealitySettings`.

Update mux validation:

- `enabled: true` remains unsupported.
- `enabled: false` may include `concurrency`.
- Unknown mux fields still error unless they are confirmed Xray-core no-op fields.

Add focused tests for `realitySettings.allowInsecure: false` and disabled mux concurrency.

- [ ] **Step 8: Run parser tests**

Run:

```bash
cargo test -p xray-config --test parser_tests
cargo test -p xray-config
```

Expected: PASS.

## Task 4: DNS Runtime Resolver

**Files:**
- Modify: `crates/xray-transport/src/lib.rs`
- Optionally create: `crates/xray-transport/src/dns.rs`
- Modify: `crates/xray-transport/tests/dns_tests.rs`
- Modify: `crates/xray-core-rs/src/lib.rs`

- [ ] **Step 1: Move DNS code into a module**

If `lib.rs` becomes noisy, create `crates/xray-transport/src/dns.rs` and re-export:

```rust
pub use dns::{CachingDnsResolver, ConfiguredDnsResolver, DnsResolver, SystemDnsResolver};
```

- [ ] **Step 2: Add configured resolver**

Implement:

```rust
pub struct ConfiguredDnsResolver {
    hosts: Vec<DnsHostMapping>,
    servers: Vec<DnsServerConfig>,
    fallback: Arc<dyn DnsResolver>,
}
```

Because `xray-transport` should not depend on `xray-config` if that would introduce an unwanted direction, prefer a transport-local normalized input:

```rust
pub struct StaticHostRule {
    pub matcher: TransportDomainMatcher,
    pub target: StaticHostTarget,
}

pub enum StaticHostTarget { Ip(IpAddr), Domain(String) }
pub enum NameServer { Socket(SocketAddr), Domain { domain: String, port: u16 } }
```

Then convert from `xray_config::DnsConfig` in `xray-core-rs`.

- [ ] **Step 3: Implement hosts behavior**

Resolution order:

1. If a host rule maps the requested domain to an IP, return `SocketAddr::new(ip, port)`.
2. If a host rule maps to a domain alias, resolve the alias through the configured resolver path, with a loop guard.
3. If no host rule matches, query configured DNS servers if any.
4. Fall back to the existing resolver.

Add tests:

- `configured_dns_hosts_ip_mapping_wins`: host rule `domain:example.com -> 203.0.113.7`, resolve `www.example.com:443`, assert returned socket is `203.0.113.7:443`, and assert the fallback resolver was not called.
- `configured_dns_hosts_domain_alias_uses_inner_resolution`: host rule `domain:googleapis.cn -> googleapis.com`, fake fallback resolves `googleapis.com` to `198.51.100.9`, assert `googleapis.cn` returns `198.51.100.9` with the requested port.

- [ ] **Step 4: Implement IP nameserver querying**

For `NameServer::Socket`, implement minimal UDP DNS A/AAAA lookup:

- Generate a random or monotonic query id.
- Send A query first for IPv4 preference, then AAAA if needed.
- Parse response header, question skip, and answer records.
- Follow CNAME answers only if the answer section also includes an address or by issuing one alias query with a loop guard.
- Use a per-server timeout, for example 2 seconds.
- Try servers in order.
- Fall back to `fallback` if all configured servers fail.

Keep the implementation small and covered by tests using a local UDP fake DNS server. Do not add a new DNS crate unless the worker confirms dependency policy first.

- [ ] **Step 5: Wire `Core::new` to config DNS**

Update `Core::new` and `with_tun_runtime_options` defaults to build:

```rust
let system = Arc::new(SystemDnsResolver);
let caching = Arc::new(CachingDnsResolver::new(system));
let resolver = configured_resolver_from_config(&config.dns, caching);
```

Do not wrap injected resolvers in `with_dns_resolver`; explicit injection must remain deterministic for tests.

- [ ] **Step 6: Run DNS tests**

Run:

```bash
cargo test -p xray-transport --test dns_tests
cargo test -p xray-core-rs --test runtime_data_path_tests dns
```

Expected: PASS.

## Task 5: IPIfNonMatch Routing

**Files:**
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Modify: `crates/xray-core-rs/src/socks.rs`
- Modify: `crates/xray-core-rs/src/http.rs`
- Modify: `crates/xray-core-rs/src/tun.rs`
- Modify: `crates/xray-core-rs/src/startup_probe.rs`
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Split route match from default fallback**

In `outbound.rs`, add a helper that tells whether a rule actually matched:

```rust
struct RouteMatch<'a> {
    outbound: &'a OutboundConfig,
    matched_rule: bool,
}
```

First pass:

- Evaluate rules against inbound tag, target domain, and target IP.
- If a rule matches, use its outbound tag, even if the tag is missing and later returns `NoSupportedOutbound`.
- If no rule matches, use default outbound only after `IPIfNonMatch` gets its DNS second pass.

- [ ] **Step 2: Add async selector**

Add:

```rust
pub async fn select_tcp_outbound_for_session_with_resolver(
    config: &CoreConfig,
    inbound_tag: Option<&str>,
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<TcpOutbound, CoreError>
```

Algorithm:

1. Run first pass with domain or IP from the original target.
2. If a rule matched, build that outbound immediately.
3. If no rule matched and strategy is `IpIfNonMatch` and the original target is a domain, resolve the domain through `dns_resolver`.
4. Run second pass with `target_domain = None` and `target_ip = Some(resolved.ip())`.
5. If a second-pass rule matches, build that outbound.
6. Otherwise use the default outbound.

Keep the original target for dialing and VLESS request headers. DNS here is only for routing decisions.

- [ ] **Step 3: Update all data paths**

Replace synchronous selectors in:

- SOCKS TCP connect.
- SOCKS UDP flow creation.
- HTTP CONNECT.
- TUN TCP flow.
- TUN UDP flow.

Keep direct helper APIs if external tests use them, but mark synchronous selectors as `AsIs` only or route them through a no-DNS path.

- [ ] **Step 4: Add route tests**

Add tests:

- `ip_if_non_match_uses_dns_second_pass_for_ip_rules`: configure `domainStrategy: IPIfNonMatch`, an IP rule to `direct`, default outbound `proxy`, fake DNS resolving `example.test` to the IP rule range, and assert the async selector returns `direct`.
- `ip_if_non_match_does_not_resolve_when_inbound_catch_all_matches_first`: configure the fixture-style inbound catch-all rule before IP rules, use a fake DNS resolver that panics if called, and assert the catch-all outbound is selected.
- `missing_outbound_tag_errors_only_when_selected`: parse a missing `api` tag successfully, then select a session with inbound tag `api` and assert `CoreError::NoSupportedOutbound`.

The second test protects the exact fixture behavior: the `inbound_49783 -> outbound_49783` rule matches before the DNS second pass, so exclusion IP rules only matter when no earlier rule matches.

- [ ] **Step 5: Run routing tests**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests ip_if_non_match
cargo test -p xray-core-rs
```

Expected: PASS.

## Task 6: Sniffing Runtime

**Files:**
- Create: `crates/xray-core-rs/src/sniffing.rs`
- Modify: `crates/xray-core-rs/src/lib.rs`
- Modify: `crates/xray-core-rs/src/socks.rs`
- Modify: `crates/xray-core-rs/src/http.rs` only if HTTP inbound needs sniffing after CONNECT payloads.
- Modify: `crates/xray-core-rs/src/tun.rs`
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Add sniffing data type**

Create:

```rust
pub(crate) struct SniffedTarget {
    pub(crate) domain: String,
    pub(crate) protocol: SniffedProtocol,
}

pub(crate) enum SniffedProtocol {
    Http,
    Tls,
    Quic,
}
```

Add:

```rust
pub(crate) fn sniff_tcp_initial_payload(
    config: &InboundSniffingConfig,
    bytes: &[u8],
) -> Option<SniffedTarget>

pub(crate) fn sniff_udp_datagram(
    config: &InboundSniffingConfig,
    bytes: &[u8],
) -> Option<SniffedTarget>
```

- [ ] **Step 2: Implement HTTP Host sniffing**

Parse only enough HTTP to extract `Host`:

- Methods are ASCII token followed by space.
- Headers end at `\r\n\r\n`.
- Host value trims whitespace and optional port.
- Reject invalid UTF-8 or empty host.

Use only when `destOverride` contains `http`.

- [ ] **Step 3: Implement TLS ClientHello SNI sniffing**

Parse TLS record and ClientHello:

- Content type 22.
- Handshake type 1.
- Walk extensions to `server_name` extension.
- Extract first DNS host name.
- No allocation-heavy parser; bounded reads only.

Use only when `destOverride` contains `tls`.

- [ ] **Step 4: Implement QUIC Initial SNI sniffing**

For UDP and `destOverride` containing `quic`:

- Detect QUIC long-header Initial packets.
- Parse version, DCID, SCID, token length, packet length, packet number length.
- Decrypting QUIC Initial is required to read TLS ClientHello. Implement this only if existing crypto deps are already available and the worker can keep it small; otherwise isolate this as a separate subtask with tests and do not pretend it is done.
- Add tests with a known QUIC Initial sample.

This task remains required for full fixture parity because the user config includes `quic`.

- [ ] **Step 5: Integrate SOCKS TCP sniffing**

After SOCKS CONNECT negotiation and before selecting outbound:

- If inbound sniffing is disabled or `metadataOnly == true`, do not read payload.
- If enabled, read a bounded initial buffer with a short timeout, for example up to 8 KiB or until parser has enough bytes.
- Preserve the bytes and replay them into the selected outbound stream after handshake.
- If `routeOnly == true`, use sniffed domain only for routing. Dial target remains the original SOCKS target.
- If `routeOnly == false`, replace the target domain for outbound request semantics, matching Xray behavior.

Avoid breaking clients that send no data before the SOCKS success response: because many clients wait for success before sending TLS/HTTP bytes, this may require routing after success but before outbound connect only when bytes are already available. If that conflicts with SOCKS protocol behavior, prefer Xray-like lazy sniffing design and document the exact tradeoff in code comments and tests.

- [ ] **Step 6: Integrate UDP sniffing**

In SOCKS UDP associate and TUN UDP:

- Sniff the first datagram of a flow.
- Preserve the original datagram bytes.
- Use sniffed domain for route selection.
- Keep original packet target when `routeOnly == true`.

- [ ] **Step 7: Add sniffing tests**

Add unit tests in `sniffing.rs` for parser functions:

- `sniffs_http_host_header`: feed an HTTP request with `Host: routed.example:443`, assert the sniffed domain is `routed.example` and protocol is `Http`.
- `sniffs_tls_client_hello_sni`: feed a captured TLS ClientHello fixture, assert the sniffed domain is the SNI name and protocol is `Tls`.
- `route_only_keeps_original_target_for_dialing`: build an original IP target plus sniffed domain, assert route lookup uses the sniffed domain while outbound connect/request still receives the original target.

Add runtime tests:

- SOCKS TCP with HTTP Host routes by host.
- SOCKS TCP with TLS SNI routes by SNI.
- UDP QUIC routes by SNI once QUIC Initial parsing is complete.

- [ ] **Step 8: Run sniffing tests**

Run:

```bash
cargo test -p xray-core-rs sniff
cargo test -p xray-core-rs --test runtime_data_path_tests sniff
```

Expected: PASS.

## Task 7: Policy Runtime

**Files:**
- Modify: `crates/xray-core-rs/src/lib.rs`
- Modify: `crates/xray-core-rs/src/socks.rs`
- Modify: `crates/xray-core-rs/src/http.rs`
- Modify: `crates/xray-core-rs/src/tun.rs`
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Add effective policy helper**

Create a small helper in `xray-core-rs`:

```rust
struct EffectivePolicy {
    handshake: Duration,
    conn_idle: Duration,
    uplink_only: Duration,
    downlink_only: Duration,
    buffer_size: Option<usize>,
}
```

Resolver:

- Use VLESS user `level` for outbound-level policy where applicable.
- Use inbound `settings.userLevel` only after it is parsed into `InboundConfig`; otherwise default to level 0 for inbound sessions.
- If no level is present, use Xray-compatible defaults currently implicit in runtime.

Note for the fixture: `policy.levels.0` exists, while the VLESS outbound user has `level: 8`. That means the fixture's level policy may only affect inbound/default-level behavior unless future configs define level 8. Still parse and implement level lookup correctly.

- [ ] **Step 2: Apply handshake timeout**

Wrap protocol negotiation and outbound connect phases with `tokio::time::timeout`:

- SOCKS no-auth negotiation and request read.
- HTTP CONNECT parse.
- Outbound transport connect and VLESS request header write.
- Startup probe path.

Return existing failure responses when timeout expires.

- [ ] **Step 3: Apply connIdle**

Replace direct `copy_bidirectional` with a helper that enforces idle timeout:

```rust
async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle: Duration,
) -> std::io::Result<(u64, u64)>
```

Use existing Tokio copy primitives internally when possible. Reset idle timer on either direction making progress.

- [ ] **Step 4: Parse and store inbound user level**

The current parser validates `settings.userLevel` but does not store it. Add:

```rust
pub user_level: Option<u32>,
```

to `InboundConfig` or inbound settings model. Use it for inbound policy lookup.

- [ ] **Step 5: Stats fields**

Stats fields in the fixture are all false. Parse and store them, but keep runtime stats no-op unless an existing stats subsystem is present. Add tests that false stats do not alter behavior.

- [ ] **Step 6: Run policy tests**

Run:

```bash
cargo test -p xray-config policy
cargo test -p xray-core-rs policy
```

Expected: PASS.

## Task 8: Full Fixture Runtime Smoke Test

**Files:**
- Modify: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`
- Optionally create: `crates/xray-core-rs/tests/fixtures.rs`

- [ ] **Step 1: Add load smoke test**

Use the fixture, geodata directory, and `Core::new`:

```rust
#[test]
fn full_xray_core_fixture_builds_core() {
    let raw = include_str!("../../../tests/fixtures/configs/xray_core_reality_split_routing_full.json");
    let parsed = parse_xray_json_with_geodata_dir(raw, "../../../platform/apple/XrayClient/dat")
        .expect("fixture parses");

    Core::new(parsed.config).expect("core builds");
}
```

- [ ] **Step 2: Add route selection smoke test**

Construct a target from `inbound_49783` and verify the third rule selects `outbound_49783` before DNS second pass. This catches accidental attempts to resolve every domain under `IPIfNonMatch`.

- [ ] **Step 3: Add missing API route test**

Construct a session with inbound tag `api` and verify route selection returns `NoSupportedOutbound`, matching Xray-core's load-time permissiveness and runtime failure shape.

- [ ] **Step 4: Run focused smoke tests**

Run:

```bash
cargo test -p xray-core-rs --test runtime_data_path_tests full_xray_core_fixture
```

Expected: PASS.

## Task 9: Workspace Verification

- [ ] **Step 1: Run crate-level tests**

Run:

```bash
cargo test -p xray-config
cargo test -p xray-transport
cargo test -p xray-core-rs
```

Expected: PASS.

- [ ] **Step 2: Run workspace tests**

Run:

```bash
cargo test --workspace
```

Expected: PASS. If workspace tests are too slow, record which focused tests passed and which workspace command was deferred.

- [ ] **Step 3: Re-run Xray-core oracle**

From `/Users/antonmalygin/xray-rust/Xray-core`, run:

```bash
XRAY_LOCATION_ASSET=/Users/antonmalygin/xray-rust/platform/apple/XrayClient/dat \
  go run ./main run -test -format json < /Users/antonmalygin/xray-rust/tests/fixtures/configs/xray_core_reality_split_routing_full.json
```

Expected:

```text
Configuration OK.
```

## Completion Criteria

- The exact user config fixture parses without errors.
- The skipped fields are accepted and ignored, with tests proving they do not require runtime behavior in this slice.
- DNS hosts and configured DNS servers affect runtime resolution.
- `IPIfNonMatch` performs an Xray-like second routing pass only when no rule matched the domain pass.
- Sniffing can route by HTTP Host, TLS SNI, and QUIC SNI according to `destOverride`.
- `routeOnly` keeps the original destination for dialing while using the sniffed host for routing.
- Policy levels parse and apply handshake and idle timeouts where the runtime has session boundaries.
- Missing outbound route tags are load-compatible and fail only if selected at runtime.
- `cargo test -p xray-config`, `cargo test -p xray-transport`, and `cargo test -p xray-core-rs` pass.
