//! Trojan client lifecycle over the shared protected stream carrier.
use super::*;
use tokio::io::{AsyncReadExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex as AsyncMutex;
use xray_proxy::trojan::{self as wire, TrojanAuth, UdpPacket, WireError};

#[derive(Debug, Clone)]
pub struct TrojanOutbound(Arc<Payload>);

#[derive(Debug)]
struct Payload {
    carrier: StreamCarrier,
    mux: Option<super::mux::Runtime>,
    auth: TrojanAuth,
    level: u32,
}

impl TrojanOutbound {
    pub(super) fn new(config: &OutboundConfig) -> Result<Self, CoreError> {
        let OutboundSettings::Trojan(settings) = &config.settings else {
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
        if (config.stream.security == StreamSecurity::None
            && !settings.server.is_xray_plaintext_server_exempt())
            || matches!(&config.stream.security, StreamSecurity::Tls(tls) if tls.allow_insecure)
        {
            return Err(CoreError::UnsupportedOutboundSecurity);
        }
        let auth = TrojanAuth::new(&settings.password)?;
        Ok(Self(Arc::new(Payload {
            carrier: StreamCarrier::new(
                &config.stream,
                &settings.server,
                settings.port,
                true,
                carrier::TROJAN_PATHS,
            )?,
            auth,
            level: settings.level,
            mux: super::mux::Runtime::new(&config.mux, &config.stream.transport)?,
        })))
    }

    pub(super) fn close(&self) {
        if let Some(m) = &self.0.mux {
            m.close();
        }
    }
    pub(super) async fn join(&self) {
        if let Some(m) = &self.0.mux {
            m.join().await;
        }
    }
    fn mux_pool(&self, target: &Target) -> Result<Option<&super::mux::Pool>, CoreError> {
        self.0.mux.as_ref().map_or(Ok(None), |m| m.pool(target))
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
        wire::encode_request_header(&self.0.auth, target)?;
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
        if target.network == RoutingNetwork::Tcp {
            if let Some(pool) = self.mux_pool(target)? {
                return Ok(Box::new(
                    pool.open(target, self.open_parent(candidates, download, dialer))
                        .await?,
                ));
            }
        }
        self.open_direct(target, candidates, download, dialer).await
    }
    async fn open_parent(
        &self,
        candidates: &[SocketAddr],
        download: &[SocketAddr],
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        self.open_direct(&super::mux::target(), candidates, download, dialer)
            .await
    }
    async fn open_direct(
        &self,
        target: &Target,
        candidates: &[SocketAddr],
        download: &[SocketAddr],
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        let header = wire::encode_request_header(&self.0.auth, target)?;
        let mut stream = self.0.carrier.open(candidates, download, dialer).await?;
        stream.release_record_alignment();
        stream.write_all(header.as_bytes()).await?;
        stream.flush().await?;
        Ok(stream)
    }

    pub(super) async fn open_udp(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
        flow_id: [u8; 8],
    ) -> Result<UdpSession, CoreError> {
        if target.network != RoutingNetwork::Udp {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        if let Some(pool) = self.mux_pool(target)? {
            let candidates = resolve_server_candidates(self.server(), resolver).await?;
            let download = self.0.carrier.resolve_download(resolver).await?;
            let child = pool
                .open_datagram(
                    target,
                    flow_id,
                    self.open_parent(&candidates, &download, dialer),
                )
                .await?;
            return Ok(UdpSession::Mux(super::mux::UdpSession::new(
                child,
                target.clone(),
            )));
        }

        let stream = self.open(target, resolver, dialer).await?;
        Ok(UdpSession::Native(NativeUdpSession::new(stream)))
    }
}

/// No detached tasks. Dropping the session drops both halves and its bounded buffer.
pub(crate) struct NativeUdpSession {
    writer: AsyncMutex<Option<WriteHalf<BoxedTransportStream>>>,
    reader: AsyncMutex<Reader>,
}
struct Reader {
    stream: ReadHalf<BoxedTransportStream>,
    pending: Vec<u8>,
    closed: bool,
}
impl NativeUdpSession {
    fn new(stream: BoxedTransportStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            writer: AsyncMutex::new(Some(writer)),
            reader: AsyncMutex::new(Reader {
                stream: reader,
                pending: Vec::with_capacity(wire::MAX_UDP_FRAME_LENGTH),
                closed: false,
            }),
        }
    }
    pub(super) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        let frame = wire::encode_udp_packet(&UdpPacket {
            target: target.clone(),
            payload,
        })?;
        let mut owner = self.writer.lock().await;
        // Cancellation after any partial write permanently closes this writer.
        let mut writer = owner
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Trojan UDP writer closed"))?;
        writer.write_all(&frame).await?;
        writer.flush().await?;
        *owner = Some(writer);
        Ok(())
    }
    pub(super) async fn recv(&self) -> Result<datagram::Datagram, CoreError> {
        let mut reader = self.reader.lock().await;
        if reader.closed {
            return Err(
                io::Error::new(io::ErrorKind::BrokenPipe, "Trojan UDP reader closed").into(),
            );
        }
        loop {
            match wire::decode_udp_packet(&reader.pending) {
                Ok((packet, consumed)) => {
                    let packet = datagram::Datagram {
                        source: packet.target,
                        payload: packet.payload.to_vec(),
                    };
                    reader.pending.drain(..consumed);
                    return Ok(packet);
                }
                Err(WireError::Incomplete) => {}
                Err(error) => {
                    reader.closed = true;
                    return Err(error.into());
                }
            }
            let remaining = wire::MAX_UDP_FRAME_LENGTH - reader.pending.len();
            if remaining == 0 {
                reader.closed = true;
                return Err(WireError::PayloadLength.into());
            }
            let mut scratch = [0u8; 1024];
            let limit = remaining.min(scratch.len());
            // read is cancellation-safe; committed bytes move into persistent state
            // without another await, so select cancellation cannot lose a prefix.
            let read = match reader.stream.read(&mut scratch[..limit]).await {
                Ok(n) if n > 0 => n,
                Ok(_) => {
                    reader.closed = true;
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Trojan UDP stream closed",
                    )
                    .into());
                }
                Err(error) => {
                    reader.closed = true;
                    return Err(error.into());
                }
            };
            reader.pending.extend_from_slice(&scratch[..read]);
        }
    }
}

pub(crate) enum UdpSession {
    Native(NativeUdpSession),
    Mux(super::mux::UdpSession),
}
impl UdpSession {
    pub(super) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        match self {
            Self::Native(s) => s.send(target, payload).await,
            Self::Mux(s) => s.send(target, payload).await,
        }
    }
    pub(super) async fn recv(&self) -> Result<datagram::Datagram, CoreError> {
        match self {
            Self::Native(s) => s.recv().await,
            Self::Mux(s) => s.recv().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (NativeUdpSession, tokio::io::DuplexStream) {
        let (client, peer) = tokio::io::duplex(64);
        (NativeUdpSession::new(Box::new(client)), peer)
    }
    fn target() -> Target {
        Target::new(
            RoutingTargetAddr::Domain("example.test".into()),
            53,
            RoutingNetwork::Udp,
        )
    }

    #[tokio::test]
    async fn canceled_receive_keeps_partial_frame_and_following_packets() {
        let (session, mut peer) = pair();
        let target = target();
        let frame = wire::encode_udp_packet(&UdpPacket {
            target: target.clone(),
            payload: b"reply",
        })
        .unwrap();
        peer.write_all(&frame[..5]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), session.recv())
                .await
                .is_err()
        );
        peer.write_all(&frame[5..]).await.unwrap();
        let packet = session.recv().await.unwrap();
        assert_eq!(packet.source, target);
        assert_eq!(packet.payload, b"reply");
        peer.write_all(&frame).await.unwrap();
        peer.write_all(&frame).await.unwrap();
        assert_eq!(session.recv().await.unwrap().payload, b"reply");
        assert_eq!(session.recv().await.unwrap().payload, b"reply");
    }

    #[tokio::test]
    async fn canceled_partial_write_cannot_be_reused_as_another_datagram() {
        let (session, _peer) = pair();
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            session.send(&target(), &[7; 8192])
        )
        .await
        .is_err());
        assert!(session.send(&target(), b"second").await.is_err());
    }

    #[tokio::test]
    async fn malformed_or_oversized_frame_poison_the_reader_without_waiting_for_body() {
        for frame in [vec![255], vec![1, 127, 0, 0, 1, 0, 53, 0x20, 1]] {
            let (session, mut peer) = pair();
            peer.write_all(&frame).await.unwrap();
            assert!(tokio::time::timeout(Duration::from_secs(1), session.recv())
                .await
                .unwrap()
                .is_err());
            assert!(session.recv().await.is_err());
            assert!(session.reader.lock().await.pending.capacity() <= wire::MAX_UDP_FRAME_LENGTH);
        }
    }
}
