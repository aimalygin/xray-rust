//! SOCKS5 client lifecycle over the shared protected stream carrier.
//!
//! TCP uses CONNECT. UDP uses UDP ASSOCIATE: the control connection goes
//! through the carrier, so every transport and its TLS or REALITY apply to
//! it, while datagrams use a plain, protected UDP socket connected to the
//! relay, as in Xray-core. There is no Mux path.
use super::*;
use std::sync::atomic::AtomicBool;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::Mutex as AsyncMutex;
use xray_proxy::inbound::SocksAccount;
use xray_proxy::outbound::{
    decode_socks5_udp_reply, encode_socks5_udp_request, socks5_connect, socks5_udp_associate,
    validate_connect_target,
};

/// Large enough for any UDP datagram, so a relay reply is never truncated.
const UDP_RECEIVE_BUFFER_LENGTH: usize = 65_536;

#[derive(Debug, Clone)]
pub struct SocksOutbound(Arc<Payload>);

#[derive(Debug)]
struct Payload {
    carrier: StreamCarrier,
    account: Option<SocksAccount>,
    level: u32,
}

impl SocksOutbound {
    pub(super) fn new(config: &OutboundConfig) -> Result<Self, CoreError> {
        let OutboundSettings::Socks(settings) = &config.settings else {
            return Err(CoreError::NoSupportedOutbound);
        };
        if settings.port == 0
            || matches!(&settings.server, TargetAddr::Domain(d) if d.is_empty() || d.len() > 255 || d.chars().any(|c| c.is_whitespace() || c.is_control()))
        {
            return Err(CoreError::UnsupportedOutboundServerAddress);
        }
        if settings.level > 255 {
            return Err(CoreError::NoSupportedOutbound);
        }
        // The parser refuses `allowInsecure`; keep that for programmatically
        // built configs.
        if matches!(&config.stream.security, StreamSecurity::Tls(tls) if tls.allow_insecure) {
            return Err(CoreError::UnsupportedOutboundSecurity);
        }
        Ok(Self(Arc::new(Payload {
            // A plaintext public server is accepted for SOCKS, so an XHTTP
            // download leg to one is too.
            carrier: StreamCarrier::new(
                &config.stream,
                &settings.server,
                settings.port,
                false,
                carrier::TROJAN_PATHS,
            )?,
            account: settings.account.clone(),
            level: settings.level,
        })))
    }

    pub fn server(&self) -> &Target {
        &self.0.carrier.server
    }
    pub fn level(&self) -> u32 {
        self.0.level
    }

    pub(super) async fn open(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        // Validate before DNS or dialing, including programmatically built targets.
        validate_connect_target(target)?;
        let candidates = resolve_server_candidates(self.server(), resolver).await?;
        let download = self.0.carrier.resolve_download(resolver).await?;
        self.open_resolved(target, &candidates, &download, dialer)
            .await
    }

    pub(super) async fn open_resolved(
        &self,
        target: &Target,
        candidates: &[SocketAddr],
        download: &[SocketAddr],
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        validate_connect_target(target)?;
        let mut stream = self.0.carrier.open(candidates, download, dialer).await?;
        stream.release_record_alignment();
        socks5_connect(&mut stream, self.0.account.as_ref(), target).await?;
        Ok(stream)
    }

    /// Opens one UDP association for `target`.
    ///
    /// The relay socket is bound before the request so that its real port is
    /// declared, which servers that pin the association to the declared
    /// endpoint require. Its IP stays unspecified, so such servers pair the
    /// port with the control connection's source IP, as Xray-core's own server
    /// does; the control connection and the socket therefore use the same
    /// address family, trying the server's families in resolver order. A
    /// relay of the other family moves on to the next one: a transport that
    /// shares one connection between flows may carry the control connection
    /// over the other family whatever the candidates say.
    pub(super) async fn open_udp(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<UdpSession, CoreError> {
        if target.network != RoutingNetwork::Udp {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        // Validate before DNS or dialing, including programmatically built targets.
        encode_socks5_udp_request(target, &[])?;
        // The datagrams leave on a socket of their own, so a chained control
        // connection would not carry them. Routing refuses chained UDP; this
        // keeps that before any I/O.
        if dialer.carries_tcp_through_outbound() {
            return Err(TransportError::UnsupportedChainedTransport("UDP association").into());
        }
        // DNS lookups already canonicalize mapped IPv6, but literal endpoints
        // bypass DNS. Use the same normalization before selecting a UDP family.
        let candidates = xray_transport::DnsLookup::new(
            resolve_server_candidates(self.server(), resolver).await?,
            None,
        );
        let download = self.0.carrier.resolve_download(resolver).await?;
        let mut families = Vec::with_capacity(2);
        for candidate in candidates.socket_addrs() {
            if !families.contains(&candidate.is_ipv4()) {
                families.push(candidate.is_ipv4());
            }
        }

        let mut last_error = None;
        for ipv4 in families {
            let family: Vec<SocketAddr> = candidates
                .socket_addrs()
                .iter()
                .copied()
                .filter(|candidate| candidate.is_ipv4() == ipv4)
                .collect();
            // A host without this family (e.g. no IPv6) falls through to the next one.
            let socket = match bind_relay_socket(ipv4, dialer) {
                Ok(socket) => socket,
                Err(error) => {
                    last_error = Some(error.into());
                    continue;
                }
            };
            let (mut control, server) = match self.open_control(&family, &download, dialer).await {
                Ok(connected) => connected,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            control.release_record_alignment();
            let relay = socks5_udp_associate(
                &mut control,
                self.0.account.as_ref(),
                socket.local_addr()?,
                server,
            )
            .await?;
            if relay.is_ipv4() != ipv4 {
                last_error = Some(
                    io::Error::other(
                        "SOCKS UDP relay address family differs from the control connection",
                    )
                    .into(),
                );
                continue;
            }
            socket.connect(relay).await?;
            return Ok(UdpSession {
                socket,
                relay,
                closed: AtomicBool::new(false),
                reader: AsyncMutex::new(Reader {
                    control,
                    buffer: vec![0; UDP_RECEIVE_BUFFER_LENGTH],
                }),
            });
        }
        Err(last_error.unwrap_or_else(|| io::Error::other("no SOCKS server address").into()))
    }

    /// Opens the control connection over `family`, the candidates of one
    /// address family, and returns it with the server address that a relay
    /// address of `0.0.0.0` or `::` names.
    ///
    /// A direct raw carrier knows which candidate answered, so that one is
    /// the server. Other transports may share one connection between flows,
    /// and REALITY dials its own socket, so the family's first candidate
    /// stands in for it, as Xray-core names the configured server address.
    async fn open_control(
        &self,
        family: &[SocketAddr],
        download: &[SocketAddr],
        dialer: &TransportDialer,
    ) -> Result<(BoxedTransportStream, IpAddr), CoreError> {
        let carrier = &self.0.carrier;
        if matches!(carrier.transport_layer, TransportLayer::Raw)
            && !matches!(carrier.transport, ConnectorConfig::Reality(_))
        {
            let fragmented_dialer = carrier
                .fragment
                .as_ref()
                .map(|fragment| dialer.clone().with_tcp_fragment(fragment.clone()));
            let dialer = fragmented_dialer.as_ref().unwrap_or(dialer);
            let (control, peer) = dialer
                .connect_raw_stream_with_peer(
                    &carrier.transport,
                    self.server(),
                    family,
                    carrier.happy_eyeballs.as_ref(),
                )
                .await?;
            return Ok((control, peer.ip()));
        }
        let server = family
            .first()
            .ok_or_else(|| io::Error::other("no SOCKS server address"))?
            .ip();
        Ok((carrier.open(family, download, dialer).await?, server))
    }
}

/// Binds and protects the relay socket before any network I/O, like the
/// other native UDP outbounds.
fn bind_relay_socket(ipv4: bool, dialer: &TransportDialer) -> io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(if ipv4 { "0.0.0.0:0" } else { "[::]:0" })?;
    xray_transport::protect_std_udp_socket(&socket, dialer.socket_protector())
        .map_err(io::Error::other)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

/// One UDP association. It ends when the server closes the control
/// connection or the flow drops the session, which closes both sockets; no
/// detached task watches the control connection.
pub(crate) struct UdpSession {
    socket: UdpSocket,
    relay: SocketAddr,
    closed: AtomicBool,
    reader: AsyncMutex<Reader>,
}

struct Reader {
    control: BoxedTransportStream,
    buffer: Vec<u8>,
}

fn control_closed() -> CoreError {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "SOCKS UDP control connection closed",
    )
    .into()
}

impl UdpSession {
    pub(super) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(control_closed());
        }
        let datagram = encode_socks5_udp_request(target, payload)?;
        let sent = self.socket.send(&datagram).await?;
        if sent != datagram.len() {
            return Err(
                io::Error::new(io::ErrorKind::WriteZero, "partial SOCKS UDP datagram").into(),
            );
        }
        Ok(())
    }

    /// Returns the next well-formed datagram from the relay. Malformed,
    /// fragmented and foreign datagrams are dropped without ending the
    /// association; end of file or an error on the control connection ends it.
    pub(super) async fn recv(&self) -> Result<datagram::Datagram, CoreError> {
        let mut reader = self.reader.lock().await;
        let Reader { control, buffer } = &mut *reader;
        loop {
            if self.closed.load(Ordering::Acquire) {
                return Err(control_closed());
            }
            // Both reads are cancellation-safe, so the relay loop may drop
            // this future between datagrams without losing one.
            let mut discard = [0; 64];
            tokio::select! {
                biased;
                read = control.read(&mut discard) => {
                    // The server sends nothing after the reply; stray bytes are ignored.
                    if !matches!(read, Ok(read) if read > 0) {
                        self.closed.store(true, Ordering::Release);
                    }
                }
                received = self.socket.recv_from(buffer) => {
                    let (len, source) = received?;
                    if let Ok(datagram) = decode_socks5_udp_reply(self.relay, source, &buffer[..len]) {
                        return Ok(datagram::Datagram {
                            source: datagram.target,
                            payload: datagram.payload.into(),
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use xray_transport::{HappyEyeballsConfig, ResolvedTcpConnector};

    fn outbound(stream: Value) -> OutboundConfig {
        let raw = json!({"outbounds":[{"protocol":"socks",
            "settings":{"address":"socks.example","port":1080},"streamSettings":stream}]});
        xray_config::parse_xray_json(&raw.to_string())
            .unwrap_or_else(|error| panic!("{raw}: {:?}", error.diagnostics))
            .config
            .outbounds
            .remove(0)
    }

    #[test]
    fn every_transport_and_security_builds() {
        let tls = json!({"serverName":"socks.example"});
        let reality = json!({"serverName":"socks.example","fingerprint":"chrome",
            "publicKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","shortId":"02030405"});
        for stream in [
            json!({}),
            json!({"security":"tls","tlsSettings":tls}),
            json!({"security":"reality","realitySettings":reality}),
            json!({"network":"ws","security":"tls","tlsSettings":tls}),
            json!({"network":"httpupgrade"}),
            json!({"network":"grpc","security":"reality","realitySettings":reality}),
            json!({"network":"xhttp","security":"reality","realitySettings":reality}),
            json!({"network":"xhttp","xhttpSettings":{"downloadSettings":{
                "address":"198.51.100.20","port":443,"network":"xhttp"}}}),
        ] {
            let config = outbound(stream.clone());
            SocksOutbound::new(&config).unwrap_or_else(|error| panic!("{stream}: {error:?}"));
        }
    }

    struct NoTcp;
    #[async_trait]
    impl ResolvedTcpConnector for NoTcp {
        async fn connect_resolved(
            &self,
            _: &Target,
            _: &[SocketAddr],
            _: Option<&HappyEyeballsConfig>,
        ) -> Result<BoxedTransportStream, TransportError> {
            unreachable!("a chained association opens no control connection")
        }
    }

    struct NoDns;
    #[async_trait]
    impl DnsResolver for NoDns {
        async fn resolve(&self, domain: &str, _: u16) -> Result<SocketAddr, TransportError> {
            unreachable!("a chained association resolves nothing, asked for {domain}")
        }
    }

    /// REALITY dials its own socket, so its control connection goes through
    /// the carrier rather than the direct raw dial that reads the peer.
    #[tokio::test]
    async fn reality_opens_its_control_connection_through_the_carrier() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let raw = json!({"outbounds":[{"protocol":"socks",
            "settings":{"address":"127.0.0.1","port":port},
            "streamSettings":{"security":"reality","realitySettings":{
                "serverName":"socks.example","fingerprint":"chrome",
                "publicKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","shortId":"02030405"}}}]});
        let config = xray_config::parse_xray_json(&raw.to_string())
            .unwrap()
            .config
            .outbounds
            .remove(0);
        let socks = SocksOutbound::new(&config).unwrap();
        let target = Target::new(
            RoutingTargetAddr::Ip(Ipv4Addr::LOCALHOST.into()),
            53,
            RoutingNetwork::Udp,
        );
        let association = tokio::spawn(async move {
            let dialer = TransportDialer::system().unwrap();
            socks.open_udp(&target, &NoDns, &dialer).await.err()
        });
        let accepted =
            tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await;
        let Ok(Ok((mut control, _))) = accepted else {
            panic!("no control connection: {:?}", association.await);
        };
        let mut record = [0; 1];
        control.read_exact(&mut record).await.unwrap();
        assert_eq!(record, [0x16], "a TLS handshake record opens it");
        drop(control);
        assert!(association.await.unwrap().is_some());
    }

    /// The datagrams would leave beside the chain, so no transport opens one.
    #[tokio::test]
    async fn a_chained_dialer_opens_no_association() {
        let target = Target::new(
            RoutingTargetAddr::Ip(Ipv4Addr::LOCALHOST.into()),
            53,
            RoutingNetwork::Udp,
        );
        let dialer = TransportDialer::system()
            .unwrap()
            .with_resolved_tcp_connector(Arc::new(NoTcp));
        for stream in [json!({}), json!({"network":"ws"})] {
            let socks = SocksOutbound::new(&outbound(stream.clone())).unwrap();
            let Err(error) = socks.open_udp(&target, &NoDns, &dialer).await else {
                panic!("{stream}: a chained association opened");
            };
            assert!(
                matches!(
                    error,
                    CoreError::Transport(TransportError::UnsupportedChainedTransport(
                        "UDP association"
                    ))
                ),
                "{stream}: {error:?}"
            );
        }
    }
}
