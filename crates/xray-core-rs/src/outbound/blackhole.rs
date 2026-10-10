//! Xray-compatible `blackhole` outbound.
//!
//! Like the DNS outbound this is a session handler rather than a byte-stream
//! transport: selecting it never resolves, dials or allocates a socket. A TCP
//! session receives the optional configured response and is closed. A UDP
//! flow receives the response once and then absorbs its datagrams until it is
//! idle, as Xray dispatches it once. Paths that need a dialable transport
//! (internal DNS clients, probes, TUN DNS upstreams, chains) fail closed with
//! [`CoreError::BlackholeOutbound`] instead.

use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use xray_config::{BlackholeResponse, OutboundSettings};

use super::{OutboundFactory, OutboundNodeId};
use crate::connection::wait_for_connection_close;
use crate::CoreError;

/// Xray-core v26.7.28 `proxy/blackhole/config.go` `http403response`, byte for
/// byte. It is a Go raw string, so lines end in LF and an extra LF follows the
/// blank line.
pub(crate) const XRAY_HTTP_403_RESPONSE: &[u8] = b"HTTP/1.1 403 Forbidden\nConnection: close\nCache-Control: max-age=3600, public\nContent-Length: 0\n\n\n";

/// Xray keeps a link open for one second after writing a response so that the
/// client can read it. xray-rust half-closes right after the response and
/// spends at most this long discarding late client bytes, so unread input
/// does not turn the close into a reset that could discard the response.
pub(crate) const BLACKHOLE_RESPONSE_GRACE: Duration = Duration::from_secs(1);

const DISCARD_BUFFER_SIZE: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlackholeOutbound {
    response: BlackholeResponse,
}

impl BlackholeOutbound {
    pub(crate) fn new(response: BlackholeResponse) -> Self {
        Self { response }
    }

    /// Bytes written to a blackholed TCP session before it is closed, or sent
    /// once as a datagram to a blackholed UDP flow.
    pub(crate) fn response_bytes(self) -> &'static [u8] {
        match self.response {
            BlackholeResponse::None => &[],
            BlackholeResponse::Http => XRAY_HTTP_403_RESPONSE,
        }
    }

    /// Answers a client stream whose proxy handshake already succeeded, as
    /// Xray's SOCKS and HTTP inbounds acknowledge before dispatching.
    ///
    /// Without a response this returns immediately and the caller closes the
    /// stream. With one, the response is written and the write side is shut
    /// down; late client bytes are then discarded until EOF or for at most
    /// [`BLACKHOLE_RESPONSE_GRACE`]. Callers race this against host close.
    pub(crate) async fn finish_stream<S>(self, stream: &mut S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let response = self.response_bytes();
        if response.is_empty() {
            return;
        }
        if stream.write_all(response).await.is_err() || stream.shutdown().await.is_err() {
            return;
        }
        let mut discard = [0_u8; DISCARD_BUFFER_SIZE];
        let _ = tokio::time::timeout(BLACKHOLE_RESPONSE_GRACE, async {
            while matches!(stream.read(&mut discard).await, Ok(read) if read > 0) {}
        })
        .await;
    }
}

/// Absorbs the rest of a blackholed UDP flow without reading it anywhere.
///
/// Xray dispatches a UDP flow to the blackhole once and then discards its
/// datagrams until the link has been idle for 30 to 90 seconds, so later
/// datagrams are not routed again. Inbounds pass their UDP idle timeout, which
/// falls inside that window. This returns once the flow has been idle that
/// long, its sender is gone (the inbound ended or evicted the flow), the core
/// shuts down or the host closes the connection.
pub(crate) async fn absorb_udp_datagrams(
    from_client: &mut mpsc::Receiver<Bytes>,
    shutdown: &mut watch::Receiver<bool>,
    connection_close: &mut watch::Receiver<bool>,
    idle_timeout: Duration,
) {
    if *shutdown.borrow() {
        return;
    }
    loop {
        tokio::select! {
            biased;
            () = wait_for_connection_close(connection_close) => return,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            () = tokio::time::sleep(idle_timeout) => return,
            datagram = from_client.recv() => {
                if datagram.is_none() {
                    return;
                }
            }
        }
    }
}

impl OutboundFactory {
    /// Returns the configured blackhole handler. Nothing is compiled or
    /// cached: the handler is a copy of its validated response setting.
    pub(crate) fn blackhole_outbound(
        &self,
        node: OutboundNodeId,
    ) -> Result<BlackholeOutbound, CoreError> {
        self.graph.validate_proxy_chains()?;
        match self
            .graph
            .configured_outbound(node)
            .map(|outbound| &outbound.settings)
        {
            Some(OutboundSettings::Blackhole(settings)) => {
                Ok(BlackholeOutbound::new(settings.response))
            }
            _ => Err(CoreError::NoSupportedOutbound),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_config::{parse_xray_json, BlackholeResponse};
    use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
    use xray_transport::{DnsResolver, TransportError};

    use super::*;
    use crate::outbound::{
        OutboundGraph, OutboundProxyGraphError, OutboundRouter, TcpOutbound, TcpSessionOutbound,
        UdpSessionOutbound,
    };

    /// Routing in these tests uses IP targets and `AsIs`; any lookup is a bug.
    struct NoLookupResolver;

    #[async_trait]
    impl DnsResolver for NoLookupResolver {
        async fn resolve(&self, domain: &str, _port: u16) -> Result<SocketAddr, TransportError> {
            panic!("blackhole routing must not resolve {domain}");
        }
    }

    fn router(raw: &str) -> OutboundRouter {
        let parsed = parse_xray_json(raw).expect("synthetic blackhole config parses");
        OutboundRouter::new(Arc::new(parsed.config))
    }

    fn target(octets: [u8; 4], port: u16, network: RoutingNetwork) -> Target {
        Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(octets))),
            port,
            network,
        )
    }

    const ROUTED_CONFIG: &str = r#"{
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
            {"tag": "drop", "protocol": "blackhole"}
        ],
        "routing": {"rules": [
            {"type": "field", "ip": ["192.0.2.0/24"], "outboundTag": "block"},
            {"type": "field", "network": "udp", "port": 443, "outboundTag": "drop"}
        ]}
    }"#;

    #[test]
    fn http_response_is_xray_core_403_byte_for_byte() {
        assert_eq!(
            XRAY_HTTP_403_RESPONSE,
            b"HTTP/1.1 403 Forbidden\nConnection: close\nCache-Control: max-age=3600, public\nContent-Length: 0\n\n\n"
        );
        assert_eq!(XRAY_HTTP_403_RESPONSE.len(), 97);
        assert_eq!(
            BlackholeOutbound::new(BlackholeResponse::Http).response_bytes(),
            XRAY_HTTP_403_RESPONSE
        );
        assert!(BlackholeOutbound::new(BlackholeResponse::None)
            .response_bytes()
            .is_empty());
    }

    #[tokio::test]
    async fn http_response_is_written_before_a_graceful_close() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
            .await
            .unwrap();
        let finished = tokio::spawn(async move {
            BlackholeOutbound::new(BlackholeResponse::Http)
                .finish_stream(&mut server)
                .await;
        });

        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, XRAY_HTTP_403_RESPONSE);
        drop(client);
        finished.await.unwrap();
    }

    #[tokio::test]
    async fn none_response_writes_nothing() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        BlackholeOutbound::new(BlackholeResponse::None)
            .finish_stream(&mut server)
            .await;
        drop(server);
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn response_grace_is_bounded_when_the_client_never_closes() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let started = tokio::time::Instant::now();
        BlackholeOutbound::new(BlackholeResponse::Http)
            .finish_stream(&mut server)
            .await;
        assert!(started.elapsed() >= BLACKHOLE_RESPONSE_GRACE);
        assert!(started.elapsed() < BLACKHOLE_RESPONSE_GRACE * 2);
        let mut response = vec![0; XRAY_HTTP_403_RESPONSE.len()];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, XRAY_HTTP_403_RESPONSE);
    }

    const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

    #[tokio::test(start_paused = true)]
    async fn udp_flow_is_absorbed_until_it_has_been_idle() {
        let (sender, mut receiver) = mpsc::channel(4);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let (_close_tx, mut close) = watch::channel(false);
        let started = tokio::time::Instant::now();
        let (_, sender) = tokio::join!(
            absorb_udp_datagrams(&mut receiver, &mut shutdown, &mut close, UDP_IDLE_TIMEOUT),
            async move {
                for _ in 0..2 {
                    tokio::time::sleep(Duration::from_secs(40)).await;
                    sender.send(Bytes::from_static(b"quic")).await.unwrap();
                }
                sender
            },
        );
        // Each datagram restarts the idle window: 40 s + 40 s + 60 s.
        assert_eq!(started.elapsed(), Duration::from_secs(140));
        drop(sender);
    }

    #[tokio::test(start_paused = true)]
    async fn udp_absorption_ends_with_the_flow_the_core_or_a_host_close() {
        // The inbound ended or evicted the flow.
        let (sender, mut receiver) = mpsc::channel::<Bytes>(1);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let (_close_tx, mut close) = watch::channel(false);
        drop(sender);
        let started = tokio::time::Instant::now();
        absorb_udp_datagrams(&mut receiver, &mut shutdown, &mut close, UDP_IDLE_TIMEOUT).await;
        assert_eq!(started.elapsed(), Duration::ZERO);

        let (_sender, mut receiver) = mpsc::channel::<Bytes>(1);
        let (shutdown_tx, mut shutdown) = watch::channel(false);
        let (_close_tx, mut close) = watch::channel(false);
        let started = tokio::time::Instant::now();
        tokio::join!(
            absorb_udp_datagrams(&mut receiver, &mut shutdown, &mut close, UDP_IDLE_TIMEOUT),
            async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                shutdown_tx.send_replace(true);
            },
        );
        assert_eq!(started.elapsed(), Duration::from_secs(5));

        let (_sender, mut receiver) = mpsc::channel::<Bytes>(1);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let (close_tx, mut close) = watch::channel(false);
        let started = tokio::time::Instant::now();
        tokio::join!(
            absorb_udp_datagrams(&mut receiver, &mut shutdown, &mut close, UDP_IDLE_TIMEOUT),
            async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                close_tx.send_replace(true);
            },
        );
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn routing_rules_select_the_blackhole_session_handler() {
        let router = router(ROUTED_CONFIG);
        let resolver = NoLookupResolver;

        let selected = router
            .select_tcp_session_outbound_with_tag_and_resolver(
                None,
                &target([192, 0, 2, 10], 80, RoutingNetwork::Tcp),
                true,
                &resolver,
            )
            .await
            .unwrap();
        assert_eq!(selected.tag.as_deref(), Some("block"));
        let TcpSessionOutbound::Blackhole(blackhole) = selected.outbound else {
            panic!("expected blackhole, got {:?}", selected.outbound);
        };
        assert_eq!(blackhole.response_bytes(), XRAY_HTTP_403_RESPONSE);

        let selected = router
            .select_udp_session_outbound_with_tag_and_resolver(
                None,
                &target([198, 51, 100, 7], 443, RoutingNetwork::Udp),
                true,
                &resolver,
            )
            .await
            .unwrap();
        assert_eq!(selected.tag.as_deref(), Some("drop"));
        assert!(matches!(
            selected.outbound,
            UdpSessionOutbound::Blackhole(blackhole) if blackhole.response_bytes().is_empty()
        ));

        let selected = router
            .select_tcp_session_outbound_with_tag_and_resolver(
                None,
                &target([198, 51, 100, 7], 443, RoutingNetwork::Tcp),
                true,
                &resolver,
            )
            .await
            .unwrap();
        assert_eq!(selected.tag.as_deref(), Some("direct"));
        assert!(matches!(
            selected.outbound,
            TcpSessionOutbound::Transport(TcpOutbound::Freedom)
        ));
    }

    #[test]
    fn transport_only_selection_fails_closed_without_compiling_a_dialer() {
        let router = router(ROUTED_CONFIG);
        let blocked = target([192, 0, 2, 10], 53, RoutingNetwork::Tcp);
        assert!(matches!(
            router.select_tcp_outbound_for_session_with_tag(None, &blocked, true),
            Err(CoreError::BlackholeOutbound)
        ));
        assert!(matches!(
            router.select_udp_outbound_for_session(
                None,
                &target([192, 0, 2, 10], 53, RoutingNetwork::Udp)
            ),
            Err(CoreError::BlackholeOutbound)
        ));
        assert!(matches!(
            router.select_dns_outbound_for_session(None, &blocked),
            Ok(None)
        ));
        assert!(matches!(
            router.select_tcp_outbound_direct(Some("drop")),
            Err(CoreError::BlackholeOutbound)
        ));
    }

    #[tokio::test]
    async fn balancer_fallback_tag_can_select_the_blackhole() {
        let router = router(
            r#"{
                "outbounds": [
                    {"tag": "direct", "protocol": "freedom"},
                    {"tag": "block", "protocol": "blackhole"}
                ],
                "routing": {
                    "balancers": [{"tag": "proxies", "selector": ["proxy-"], "fallbackTag": "block"}],
                    "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "proxies"}]
                }
            }"#,
        );
        let resolver = NoLookupResolver;
        let selected = router
            .select_tcp_session_outbound_with_tag_and_resolver(
                None,
                &target([203, 0, 113, 5], 443, RoutingNetwork::Tcp),
                true,
                &resolver,
            )
            .await
            .unwrap();
        assert_eq!(selected.tag.as_deref(), Some("block"));
        assert!(matches!(
            selected.outbound,
            TcpSessionOutbound::Blackhole(blackhole)
                if blackhole.response_bytes().is_empty()
        ));
        let selected = router
            .select_udp_session_outbound_with_tag_and_resolver(
                None,
                &target([203, 0, 113, 5], 443, RoutingNetwork::Udp),
                true,
                &resolver,
            )
            .await
            .unwrap();
        assert!(matches!(
            selected.outbound,
            UdpSessionOutbound::Blackhole(_)
        ));
    }

    #[test]
    fn blackhole_cannot_join_a_transport_chain() {
        for raw in [
            r#"{"outbounds": [
                {"tag": "direct", "protocol": "freedom", "proxySettings": {"tag": "block", "transportLayer": true}},
                {"tag": "block", "protocol": "blackhole"}
            ]}"#,
            r#"{"outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole", "proxySettings": {"tag": "direct", "transportLayer": true}}
            ]}"#,
        ] {
            let parsed = parse_xray_json(raw).expect("chain shape parses");
            let graph = OutboundGraph::new(Arc::new(parsed.config));
            assert!(matches!(
                graph.validate_proxy_chains(),
                Err(OutboundProxyGraphError::UnsupportedNode { outbound, reason })
                    if outbound == "block" && reason.contains("blackhole")
            ));
        }
    }
}
