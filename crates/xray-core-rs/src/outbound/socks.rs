//! SOCKS5 client lifecycle over the shared protected stream carrier.
//!
//! TCP uses CONNECT. UDP uses UDP ASSOCIATE: the control connection goes
//! through the carrier (so TLS applies to it), while datagrams use a plain,
//! protected UDP socket connected to the relay. There is no Mux path.
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
        // The parser enforces raw/tcp with none or TLS; keep that invariant for
        // programmatically built configs instead of dialing another carrier.
        if config.stream.transport != StreamTransport::Raw {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        if matches!(&config.stream.security, StreamSecurity::Reality(_))
            || matches!(&config.stream.security, StreamSecurity::Tls(tls) if tls.allow_insecure)
        {
            return Err(CoreError::UnsupportedOutboundSecurity);
        }
        Ok(Self(Arc::new(Payload {
            carrier: StreamCarrier::new(
                &config.stream,
                &settings.server,
                settings.port,
                true,
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
    /// port with the control connection's source IP; the control connection
    /// and the socket therefore always use the same address family, trying
    /// the server's families in resolver order.
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
        // DNS lookups already canonicalize mapped IPv6, but literal endpoints
        // bypass DNS. Use the same normalization before selecting a UDP family.
        let candidates = xray_transport::DnsLookup::new(
            resolve_server_candidates(self.server(), resolver).await?,
            None,
        );
        let fragmented_dialer = self
            .0
            .carrier
            .fragment
            .as_ref()
            .map(|fragment| dialer.clone().with_tcp_fragment(fragment.clone()));
        let dialer = fragmented_dialer.as_ref().unwrap_or(dialer);
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
            let (mut control, peer) = match dialer
                .connect_raw_stream_with_peer(
                    &self.0.carrier.transport,
                    self.server(),
                    &family,
                    self.0.carrier.happy_eyeballs.as_ref(),
                )
                .await
            {
                Ok(connected) => connected,
                Err(error) => {
                    last_error = Some(error.into());
                    continue;
                }
            };
            control.release_record_alignment();
            let relay = socks5_udp_associate(
                &mut control,
                self.0.account.as_ref(),
                socket.local_addr()?,
                peer.ip(),
            )
            .await?;
            if relay.is_ipv4() != ipv4 {
                return Err(io::Error::other(
                    "SOCKS UDP relay address family differs from the control connection",
                )
                .into());
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
