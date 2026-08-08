//! The dial-ready gRPC settings, and Xray's user-agent table.

use crate::stream::masquerade::{
    anchored_chrome_user_agent, anchored_edge_user_agent, anchored_firefox_user_agent,
};

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
    /// Untouched, but not unchecked: this is free-form JSON that the config
    /// layer only rejects for emptiness, so a value that is not an authority
    /// at all fails the dial rather than reshaping the request. The reasoning,
    /// and why it diverges from grpc-go, is at the URI assembly in
    /// [`super::open_grpc_h2_stream`].
    pub authority: String,
    /// Already resolved through Xray's table by [`resolve_user_agent`], so
    /// `golang` has become the empty string by the time it lands here.
    pub user_agent: String,
    /// `grpcSettings.idle_timeout`. Carried, not yet consumed: it is a
    /// connection property (grpc-go turns the three of these into
    /// `keepalive.ClientParameters`, `dial.go:169-175`), and there is no
    /// connection to hang it on until the pool exists.
    pub idle_timeout_secs: u32,
    /// `grpcSettings.health_check_timeout`. See [`Self::idle_timeout_secs`].
    pub health_check_timeout_secs: u32,
    /// `grpcSettings.permit_without_stream`. See [`Self::idle_timeout_secs`].
    pub permit_without_stream: bool,
    /// `grpcSettings.initial_windows_size`, which grpc-go applies as
    /// `WithInitialWindowSize` (`dial.go:177-179`) — an HTTP/2 SETTINGS value,
    /// so also the pool's to consume.
    pub initial_windows_size: u32,
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
