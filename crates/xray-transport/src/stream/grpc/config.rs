//! The dial-ready gRPC settings, and Xray's user-agent table.

use std::time::Duration;

use http::header::InvalidHeaderValue;

use crate::stream::masquerade::{
    anchored_chrome_user_agent, anchored_edge_user_agent, anchored_firefox_user_agent,
};

/// Re-exported because [`GrpcConfig::authority`] is one and the crate that
/// builds the config (`xray-core-rs`) has no `http` dependency of its own.
/// Handing it out from here also means there is only ever one `http` in the
/// chain: a second, differently-versioned `Authority` would not be this type.
pub use http::uri::Authority;
/// Re-exported for [`GrpcConfig::user_agent`], for the reason above: it is a
/// `pub` field, and a `pub` field of a type no caller can name is one they
/// cannot construct either.
pub use http::HeaderValue;

/// Everything the gRPC dial needs, resolved from config plus the security
/// layer's server name.
///
/// **Two of these arrive resolved and the rest arrive raw, and the line is not
/// arbitrary.** [`Self::authority`] has to be resolved by the caller: its
/// precedence chain reads the security block and the destination address, which
/// this crate never sees, and the outbound is the only place that can name the
/// config key a bad value came from. [`Self::user_agent`] is resolved with it
/// because it belongs to the same moment — both are per-outbound, both are
/// settled once when the outbound is built, and both then reach the HEADERS
/// block verbatim.
///
/// The keepalive trio stays raw for the opposite reason: it is not a property
/// of the request at all but of the *connection*, so it is resolved where the
/// connection is made, by [`resolve_keepalive`] in `h2_handshake`. grpc-go
/// splits it at the same seam — `WithKeepaliveParams` is a dial option and the
/// transport applies it when it builds. Folding [`resolve_user_agent`] in here
/// too would move a per-outbound decision to per-dial and leave the struct
/// exactly as mixed as it is now, with the halves swapped.
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
    /// config that would have is refused when the outbound is built rather than
    /// once per dial. What that buys is the message, not the work: it is
    /// `xray_core_rs`'s `grpc_authority` that fails, so the error can name the
    /// config key the value came from, where a failure down here could only be
    /// one more connection error on one more flow.
    ///
    /// That diverges from grpc-go, which validates a `WithAuthority` not at
    /// all (`grpc@v1.81.0/clientconn.go:1976-1978`) and — confirmed on the
    /// wire — sends `:authority: example.com/api` verbatim with the `:path`
    /// intact. `Authority` cannot hold a `/`, so matching that is not on the
    /// table; between refusing the config and silently calling a different
    /// method, refusing is the one that says what is wrong.
    ///
    /// **The type is a ceiling as well as a policy, and the ceiling is not
    /// ours to raise.** `build_grpc_call` hands `h2` an
    /// [`http::Request`], and `h2` reads `:authority` out of its
    /// [`http::Uri`] and nowhere else
    /// (`h2-0.4.15/src/frame/headers.rs:561-604`); a `Uri`'s authority *is*
    /// this type. So an authority `Authority` rejects is not a config we
    /// refuse by choice — it is one no request can carry. Two whole classes
    /// fall in there and grpc-go sends both: every byte above `0x7f`, which
    /// makes an IDN authority like `例え.jp` unsendable, and `%` anywhere in a
    /// host (`http-1.5.0/src/uri/authority.rs:493-516,564-567`), which makes
    /// grpc-go's own `encodeAuthority` output for an IDN `host:port` fallback
    /// unsendable too even though it is pure ASCII. Both verified on the wire
    /// against grpc-go v1.81.0. `xray_core_rs`'s `grpc_authority` is where the
    /// consequence is faced, since it is what decides which key gets told.
    pub authority: Authority,
    /// Already resolved through Xray's table by [`resolve_user_agent`], so
    /// `golang` has become the empty string by the time it lands here.
    ///
    /// **A [`HeaderValue`] rather than a `String`, for the reason
    /// [`Self::authority`] is an [`Authority`]**: the value is free-form JSON
    /// that the config layer only rejects for emptiness
    /// (`crates/xray-config/src/parser.rs:2884-2891`), and it is static —
    /// settled once, when the outbound is built. Carried as a `String` it would
    /// be turned into a `HeaderValue` inside `build_grpc_call` instead, so a
    /// control character in it would fail *every flow at dial time*: on a warm
    /// pool that is indistinguishable from "this connection refused the call",
    /// which retires a healthy shared connection, and on a cold one it is a TCP
    /// connect plus a TLS or REALITY handshake paid to arrive at the same error
    /// again, once per flow, for as long as the config stands. As a type it is
    /// one error, at startup, from `xray_core_rs`'s `build_transport_layer`,
    /// which is the layer that can still name the config key it came from —
    /// `CoreError::InvalidGrpcUserAgent`.
    ///
    /// **Refusing the config costs nothing that worked upstream, and this is
    /// measured rather than argued.** grpc-go's client never validates the
    /// string `WithUserAgent` was given, so xray-core accepts the profile
    /// (`Xray-core/infra/conf/grpc.go:19-40` passes `UserAgent` through
    /// untouched), dials, caches the connection in `globalDialerMap` — and then
    /// every *stream* on it is reset by the peer with RST_STREAM
    /// PROTOCOL_ERROR before the handler is entered. Sixteen values, one real
    /// dial each, are pinned in `tests/fixtures/grpc/user_agent_validity.json`,
    /// and the boundary is exact: `http`'s rule is
    /// `b >= 32 && b != 127 || b == b'\t'`
    /// (`http-1.5.0/src/header/value.rs:563-565`) and Go's
    /// `ValidHeaderFieldValue` is `!(isCTL(b) && !isLWS(b))`
    /// (`x/net@v0.53.0/http/httpguts/httplex.go:173-183,303-311`), which is the
    /// same set once `isLWS`'s space is folded into `b >= 32`. So the values
    /// this type refuses are the values a grpc-go peer refuses. What changes is
    /// when the user is told, not which profiles run.
    ///
    /// **The `\r\n` case is not header injection**, which is worth saying
    /// because it looks like it. HPACK is length-prefixed: the field decoded
    /// off the wire is byte-identical to the configured string and no second
    /// header appears (`sent_verbatim` in the fixture, on every case). What
    /// kills the stream is field-value validation at the peer.
    ///
    /// **The one residual divergence is narrower than the predicate.** RFC 9113
    /// section 8.2.1 forbids only NUL, LF and CR in a field value; Go rejects
    /// DEL and the rest of C0 on top of that. A gRPC server that is *not*
    /// grpc-go could therefore accept a `\x7f` we refuse. An Xray gRPC inbound
    /// is `grpc.NewServer` (`Xray-core/transport/internet/grpc/hub.go:93`), so
    /// that peer is hypothetical, and it is the only one there is.
    pub user_agent: HeaderValue,
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
///   (`crates/xray-config/src/parser.rs:2884-2891`) — and `Some("")` is kept
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
///
/// **Only the verbatim arm can fail.** The other four resolve to values this
/// function chose: three from the masquerade table, which builds browser user
/// agents out of printable ASCII, and `golang`'s empty string, which has no
/// byte to be wrong. Nothing here proves that of the table, so the guarantee is
/// a test rather than an `expect`:
/// `the_user_agent_table_resolves_the_way_xrays_switch_does` puts every keyword
/// through this function and fails on an `Err`, which is what a template change
/// in the masquerade block would trip. The signature is fallible because the one
/// arm that reads a user-typed string is, and [`GrpcConfig::user_agent`] has why
/// that arm is refused here instead of at the dial.
pub fn resolve_user_agent(configured: Option<&str>) -> Result<HeaderValue, InvalidHeaderValue> {
    match configured.unwrap_or_default() {
        "chrome" | "" => HeaderValue::try_from(anchored_chrome_user_agent()),
        "firefox" => HeaderValue::try_from(anchored_firefox_user_agent()),
        "edge" => HeaderValue::try_from(anchored_edge_user_agent()),
        "golang" => Ok(HeaderValue::from_static("")),
        verbatim => HeaderValue::try_from(verbatim),
    }
}
