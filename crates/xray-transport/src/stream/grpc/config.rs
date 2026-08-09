//! The dial-ready gRPC settings, and Xray's user-agent table.

use std::time::Duration;

use crate::stream::masquerade::{
    anchored_chrome_user_agent, anchored_edge_user_agent, anchored_firefox_user_agent,
};

/// Re-exported because [`GrpcConfig::authority`] is one and the crate that
/// builds the config (`xray-core-rs`) has no `http` dependency of its own.
/// Handing it out from here also means there is only ever one `http` in the
/// chain: a second, differently-versioned `Authority` would not be this type.
pub use http::uri::Authority;

/// Everything the gRPC dial needs, resolved from config plus the security
/// layer's server name.
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// Raw `serviceName`; the `:path` is derived per dial because `multiMode`
    /// picks a different stream name.
    pub service_name: String,
    pub multi_mode: bool,
    /// `:authority`, already resolved. The precedence chain lives in
    /// `build_transport_layer` and is tested there, not here.
    ///
    /// It reaches the wire untouched. grpc-go escapes an authority only on the
    /// `host:port` fallback it drops to when no `WithAuthority` was given, and
    /// even there `encodeAuthority` leaves `:`, `[`, `]` and `@` alone
    /// (`grpc@v1.81.0/clientconn.go:1889-1942,1977-1986`) — which is what lets
    /// a bracketed IPv6 literal survive.
    ///
    /// **Parsed here rather than at the dial**, because the value is
    /// free-form JSON that the config layer only rejects for emptiness
    /// (`crates/xray-config/src/parser.rs:2869-2872`), and it is static: it is
    /// resolved once, when the outbound is built. A `/`, `?` or `#` in it
    /// re-partitions an interpolated request URI instead of failing —
    /// `example.com/api` parses as authority `example.com` with path
    /// `/api/xray.grpc/Tun`, and `example.com#frag` leaves the path a bare `/`
    /// — which calls a gRPC method nobody configured and gets back an
    /// UNIMPLEMENTED that names nothing. An [`Authority`] cannot hold any of
    /// the three, so no assembly of one can re-partition anything, and the
    /// config that would have is refused once at startup instead of on every
    /// dial — each of which would otherwise pay a TCP connect and a TLS or
    /// REALITY handshake first, since [`super::open_grpc_h2_stream`] is handed
    /// the far side of both.
    ///
    /// That diverges from grpc-go, which validates a `WithAuthority` not at
    /// all (`grpc@v1.81.0/clientconn.go:1976-1978`) and — confirmed on the
    /// wire — sends `:authority: example.com/api` verbatim with the `:path`
    /// intact. `Authority` cannot hold a `/`, so matching that is not on the
    /// table; between refusing the config and silently calling a different
    /// method, refusing is the one that says what is wrong.
    pub authority: Authority,
    /// Already resolved through Xray's table by [`resolve_user_agent`], so
    /// `golang` has become the empty string by the time it lands here.
    pub user_agent: String,
    /// `grpcSettings.idle_timeout`. A connection property: grpc-go turns the
    /// three of these into `keepalive.ClientParameters` (`dial.go:169-175`),
    /// which [`resolve_keepalive`] resolves for the connection the pool holds.
    pub idle_timeout_secs: u32,
    /// `grpcSettings.health_check_timeout`. See [`Self::idle_timeout_secs`].
    pub health_check_timeout_secs: u32,
    /// `grpcSettings.permit_without_stream`. See [`Self::idle_timeout_secs`].
    pub permit_without_stream: bool,
    /// `grpcSettings.initial_windows_size`, which grpc-go applies as
    /// `WithInitialWindowSize` (`dial.go:177-179`) — an HTTP/2 SETTINGS value,
    /// so the connection's rather than the call's.
    pub initial_windows_size: u32,
}

/// The keepalive a connection was dialled with, once grpc-go's floors and
/// defaults have been applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcKeepalive {
    /// How long a connection may go unpinged.
    pub time: Duration,
    /// How long a ping may go unacknowledged before the connection is over.
    pub timeout: Duration,
    /// Whether a connection with no call open on it is pinged at all.
    ///
    /// The setting is read twice on its way to the wire, for two unrelated
    /// decisions, and carrying it here is what makes the second reachable. In
    /// [`resolve_keepalive`] it is one of the three that decide whether
    /// keepalive is attached to the dial at all; in the ping loop it is what
    /// grpc-go checks before going dormant on `len(t.activeStreams) < 1`
    /// (`grpc@v1.81.0/internal/transport/http2_client.go:1769-1778`). So
    /// `permitWithoutStream` alone turns keepalive on *and* keeps it awake,
    /// while `idleTimeout` alone turns it on and leaves it asleep for as long
    /// as no flow is using the connection.
    pub permit_without_stream: bool,
}

/// grpc-go's minimum ping interval, applied by `WithKeepaliveParams` itself
/// (`grpc@v1.81.0/dialoptions.go:561-569`, `internal/internal.go:40-42`).
const KEEPALIVE_MIN_PING_TIME: Duration = Duration::from_secs(10);
/// `defaultClientKeepaliveTimeout`, which the transport substitutes for a zero
/// `Timeout` (`grpc@v1.81.0/internal/transport/defaults.go:33`).
const DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// The keepalive parameters this config dials with, or `None` for no keepalive.
///
/// **The gate is a three-way OR**, not a check on the durations:
/// `idleTimeout > 0 || healthCheckTimeout > 0 || permitWithoutStream`
/// (`Xray-core/transport/internet/grpc/dial.go:169-175`). So
/// `permitWithoutStream: true` on its own attaches `WithKeepaliveParams` with
/// both durations at zero, and the two defaults below are what that turns
/// into — keepalive every ten seconds, not none.
///
/// **Zero `Time` is not "no pings".** It is `WithKeepaliveParams` that raises
/// it, before the transport is built, so the `kp.Time == 0` branch in
/// `newHTTP2Client` (`http2_client.go:265-267`, which would have made it
/// `infinity`) is unreachable from this path. Reading the transport's default
/// instead of the dial option's clamp is the easy way to conclude that a
/// keepalive Xray asked for sends nothing.
///
/// **What grpc-go does with these beyond the interval** belongs to the ping
/// loop, `super::keepalive`: the two suppressions that keep a real grpc-go
/// client silent on an idle connection and on a busy one are reproduced there,
/// and the one place the port still diverges — an unacknowledged ping being
/// forgiven by other traffic — is written down there too.
pub fn resolve_keepalive(config: &GrpcConfig) -> Option<GrpcKeepalive> {
    if config.idle_timeout_secs == 0
        && config.health_check_timeout_secs == 0
        && !config.permit_without_stream
    {
        return None;
    }

    Some(GrpcKeepalive {
        time: Duration::from_secs(u64::from(config.idle_timeout_secs)).max(KEEPALIVE_MIN_PING_TIME),
        timeout: match config.health_check_timeout_secs {
            0 => DEFAULT_KEEPALIVE_TIMEOUT,
            seconds => Duration::from_secs(u64::from(seconds)),
        },
        permit_without_stream: config.permit_without_stream,
    })
}

/// `grpcSettings.user_agent` through Xray's switch
/// (`Xray-core/transport/internet/grpc/dial.go:193-205`).
///
/// Two arms are easy to invert and both are load-bearing:
///
/// * **Unset is not the empty case.** Go reads an absent `user_agent` as `""`,
///   and `case "chrome", ""` sends it to `utils.ChromeUA`, so the default gRPC
///   dial claims to be a browser. `None` here is that same absent key — the
///   config layer collapses an explicitly empty string into it
///   (`crates/xray-config/src/parser.rs:2876-2883`) — and `Some("")` is kept
///   on the same arm anyway, so the port holds for a caller that does not.
/// * **`golang` is the one value that empties the header**, and the header is
///   still sent: grpc-go appends `user-agent` unconditionally
///   (`grpc@v1.81.0/internal/transport/http2_client.go:578`), and Xray reaches
///   in with reflection to strip the `grpc-go/version` suffix
///   `WithUserAgent` would otherwise append (`dial.go:212-218`), so what goes
///   out is this string and nothing else.
///
/// Anything else is a literal user agent and passes through verbatim —
/// `safari` and `curl` included, which are masquerade keywords the gRPC table
/// does not know.
///
/// Xray's own comment above the switch is worth repeating: setting a browser
/// UA on gRPC is **not recommended**, because browsers are fundamentally
/// incapable of initiating gRPC. We match the behaviour anyway. Parity with the
/// population a censor is looking at is the goal here, not defensible taste.
pub fn resolve_user_agent(configured: Option<&str>) -> String {
    match configured.unwrap_or_default() {
        "chrome" | "" => anchored_chrome_user_agent(),
        "firefox" => anchored_firefox_user_agent(),
        "edge" => anchored_edge_user_agent(),
        "golang" => String::new(),
        verbatim => verbatim.to_owned(),
    }
}
