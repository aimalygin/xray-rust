use super::*;
use tokio::io::{AsyncReadExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex as AsyncMutex;
use xray_proxy::vmess::{Account, Cipher, ClientStream};
#[derive(Debug, Clone)]
pub struct VmessOutbound(Arc<Payload>);
#[derive(Debug)]
struct Payload {
    carrier: StreamCarrier,
    mux: Option<super::mux::Runtime>,
    account: Account,
    parallel_duplex: bool,
    flow_ids: xray_proxy::mux::FlowIds,
    level: u32,
}
impl VmessOutbound {
    pub(super) fn new(config: &OutboundConfig) -> Result<Self, CoreError> {
        let OutboundSettings::Vmess(settings) = &config.settings else {
            return Err(CoreError::NoSupportedOutbound);
        };
        if matches!(&config.stream.security, StreamSecurity::Tls(tls) if tls.allow_insecure) {
            return Err(CoreError::UnsupportedOutboundSecurity);
        }
        let carrier = StreamCarrier::new(
            &config.stream,
            &settings.server,
            settings.port,
            false,
            carrier::VLESS_PATHS,
        )?;
        Account::validate_target(&carrier.server)
            .map_err(|_| CoreError::UnsupportedOutboundServerAddress)?;
        let cipher = Cipher::parse(&settings.security)
            .map_err(|_| CoreError::UnsupportedOutboundSecurity)?;
        let account = Account::new(&settings.user_id, cipher, settings.options);
        Ok(Self(Arc::new(Payload {
            carrier,
            account,
            parallel_duplex: cipher == Cipher::ChaCha20Poly1305,
            flow_ids: xray_proxy::mux::FlowIds::default(),
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
        Account::validate_target(target)?;
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
        let mut inner = self.0.carrier.open(candidates, download, dialer).await?;
        inner.release_record_alignment();
        let mut stream = ClientStream::new_mux(inner, &self.0.account)?;
        stream.flush().await?;
        Ok(Box::new(protocol_stream::ProtocolStream(stream)))
    }
    async fn open_direct(
        &self,
        target: &Target,
        candidates: &[SocketAddr],
        download: &[SocketAddr],
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        Account::validate_target(target)?;
        let mut inner = self.0.carrier.open(candidates, download, dialer).await?;
        inner.release_record_alignment();
        let mut stream = ClientStream::new(inner, &self.0.account, target)?;
        stream.flush().await?;
        // Independent tasks reduce measured ChaCha CPU cost. Keep AES on the
        // combined relay: its parallel variant used more CPU for the same load.
        if self.0.parallel_duplex
            && target.network == RoutingNetwork::Tcp
            && matches!(self.0.carrier.transport_layer, TransportLayer::Raw)
            && matches!(self.0.carrier.transport, ConnectorConfig::Tcp)
        {
            return Ok(Box::new(ParallelStream(Some(stream))));
        }
        Ok(Box::new(protocol_stream::ProtocolStream(stream)))
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

        // Match the pinned VMess cone-mode path; DNS and QUIC retain native
        // command 2. Association IDs are scoped to this owned UDP flow.
        if !matches!(target.port, 53 | 443) {
            let candidates = resolve_server_candidates(self.server(), resolver).await?;
            let download = self.0.carrier.resolve_download(resolver).await?;
            let mut inner = self.0.carrier.open(&candidates, &download, dialer).await?;
            inner.release_record_alignment();
            let mut stream = ClientStream::new_mux(inner, &self.0.account)?;
            stream.flush().await?;
            return Ok(UdpSession::Xudp(super::xudp::Session::new(
                Box::new(protocol_stream::ProtocolStream(stream)),
                target.clone(),
                self.0.flow_ids.derive(flow_id),
            )));
        }
        let stream = self.open(target, resolver, dialer).await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(UdpSession::Native(NativeUdpSession {
            target: target.clone(),
            reader: AsyncMutex::new(reader),
            writer: AsyncMutex::new(Some(writer)),
        }))
    }
}
pub(crate) enum UdpSession {
    Native(NativeUdpSession),
    Mux(super::mux::UdpSession),
    Xudp(super::xudp::Session),
}
impl UdpSession {
    pub(super) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        match self {
            Self::Native(s) => s.send(target, payload).await,
            Self::Mux(s) => s.send(target, payload).await,
            Self::Xudp(s) => s.send(target, payload).await,
        }
    }
    pub(super) async fn recv(&self) -> Result<datagram::Datagram, CoreError> {
        match self {
            Self::Native(s) => s.recv().await,
            Self::Mux(s) => s.recv().await,
            Self::Xudp(s) => s.recv().await,
        }
    }
}
pub(crate) struct NativeUdpSession {
    target: Target,
    reader: AsyncMutex<ReadHalf<BoxedTransportStream>>,
    writer: AsyncMutex<Option<WriteHalf<BoxedTransportStream>>>,
}
impl NativeUdpSession {
    pub(super) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        if target != &self.target || payload.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid VMess datagram target or empty payload",
            )
            .into());
        }
        let mut owner = self.writer.lock().await;
        let mut writer = owner.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "VMess datagram writer closed")
        })?;
        writer.write_all(payload).await?;
        writer.flush().await?;
        *owner = Some(writer);
        Ok(())
    }
    pub(super) async fn recv(&self) -> Result<datagram::Datagram, CoreError> {
        let mut reader = self.reader.lock().await;
        let mut payload = vec![0; 65535];
        let n = reader.read(&mut payload).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "VMess datagram stream closed",
            )
            .into());
        }
        payload.truncate(n);
        Ok(datagram::Datagram {
            source: self.target.clone(),
            payload,
        })
    }
}

struct ParallelStream(Option<ClientStream<BoxedTransportStream>>);
impl AsyncRead for ParallelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut().0.as_mut() {
            Some(s) => Pin::new(s).poll_read(cx, out),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
}
impl AsyncWrite for ParallelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut().0.as_mut() {
            Some(s) => Pin::new(s).poll_write(cx, input),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().0.as_mut() {
            Some(s) => Pin::new(s).poll_flush(cx),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().0.as_mut() {
            Some(s) => Pin::new(s).poll_shutdown(cx),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
}
impl TransportStream for ParallelStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read(cx, out)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write(cx, input)
    }
    fn take_parallel_halves(
        &mut self,
    ) -> Option<(xray_transport::ParallelRead, xray_transport::ParallelWrite)> {
        let (read, write) = self
            .0
            .take()?
            .into_split_with(|inner| inner.into_io_halves());
        Some((Box::new(read), Box::new(write)))
    }
}
