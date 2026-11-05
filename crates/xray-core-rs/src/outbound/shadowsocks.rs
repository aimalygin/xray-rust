use super::*;
use tokio::net::UdpSocket;
use tokio::sync::Mutex as AsyncMutex;
use xray_proxy::shadowsocks::{self as wire, Method};

#[derive(Debug, Clone)]
pub struct Shadowsocks2022Outbound(Arc<Payload>);
#[derive(Debug)]
struct Payload {
    carrier: StreamCarrier,
    mux: Option<super::mux::Runtime>,
    method: Method,
    level: u32,
}
impl Shadowsocks2022Outbound {
    pub(super) fn new(config: &OutboundConfig) -> Result<Self, CoreError> {
        let OutboundSettings::Shadowsocks2022(settings) = &config.settings else {
            return Err(CoreError::NoSupportedOutbound);
        };
        let carrier = StreamCarrier::new(
            &config.stream,
            &settings.server,
            settings.port,
            false,
            carrier::TROJAN_PATHS,
        )?;
        Method::validate_target(&carrier.server)
            .map_err(|_| CoreError::UnsupportedOutboundServerAddress)?;
        if settings.level > 255
            || matches!(&config.stream.security, StreamSecurity::Tls(tls) if tls.allow_insecure)
        {
            return Err(CoreError::NoSupportedOutbound);
        }
        let method = Method::new(&settings.method, &settings.password)
            .map_err(|_| CoreError::UnsupportedOutboundSecurity)?;
        Ok(Self(Arc::new(Payload {
            carrier,
            method,
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
    /// Debug-log protocol label for the configured method family.
    pub(crate) fn label(&self) -> &'static str {
        if self.0.method.is_2022() {
            "shadowsocks-2022"
        } else {
            "shadowsocks"
        }
    }
    pub(super) async fn open(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        Method::validate_target(target)?;
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
        Method::validate_target(target)?;
        let mut inner = self.0.carrier.open(candidates, download, dialer).await?;
        inner.release_record_alignment();
        let mut stream = wire::ClientStream::new(inner, &self.0.method, target)?;
        stream.flush().await?;
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
            return Ok(UdpSession::Mux(Box::new(super::mux::UdpSession::new(
                child,
                target.clone(),
            ))));
        }

        Method::validate_target(target)?;
        let candidates = resolve_server_candidates(self.server(), resolver).await?;
        let mut last = None;
        for address in candidates {
            let result = (|| -> io::Result<UdpSocket> {
                let socket = std::net::UdpSocket::bind(if address.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                })?;
                xray_transport::protect_std_udp_socket(&socket, dialer.socket_protector())
                    .map_err(io::Error::other)?;
                socket.set_nonblocking(true)?;
                socket.connect(address)?;
                UdpSocket::from_std(socket)
            })();
            match result {
                Ok(socket) => {
                    return Ok(UdpSession::Native(Box::new(NativeUdpSession {
                        socket,
                        codec: Mutex::new(wire::UdpSession::new(&self.0.method)?),
                        reader: AsyncMutex::new(vec![0; wire::MAX_UDP_WIRE_LENGTH + 1]),
                    })))
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last
            .unwrap_or_else(|| io::Error::other("no Shadowsocks server address"))
            .into())
    }
}
/// Xray receives native UDP in an 8192-byte buffer, including the
/// Shadowsocks framing of either family. Oversized ciphertext would be
/// silently truncated (and Xray's own AEAD-2017 encoder cannot build it).
const PEER_UDP_BUFFER: usize = 8192;
pub(crate) struct NativeUdpSession {
    socket: UdpSocket,
    codec: Mutex<wire::UdpSession>,
    reader: AsyncMutex<Vec<u8>>,
}
impl NativeUdpSession {
    /// The largest payload whose datagram to `target` fits the peer's
    /// buffer under this method's salt or headers and tag.
    fn max_payload(&self, target: &Target) -> usize {
        self.codec
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .overhead(target)
            .map_or(usize::MAX, |overhead| {
                PEER_UDP_BUFFER.saturating_sub(overhead)
            })
    }
    pub(super) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        let bytes = self
            .codec
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .encode(target, payload)?;
        if bytes.len() > PEER_UDP_BUFFER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks packet exceeds pinned peer UDP limit",
            )
            .into());
        }
        let sent = self.socket.send(&bytes).await?;
        if sent != bytes.len() {
            return Err(
                io::Error::new(io::ErrorKind::WriteZero, "partial Shadowsocks datagram").into(),
            );
        }
        Ok(())
    }
    pub(super) async fn recv(&self) -> Result<datagram::Datagram, CoreError> {
        let mut buffer = self.reader.lock().await;
        loop {
            let len = self.socket.recv(&mut buffer).await?;
            let result = self
                .codec
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .decode(&buffer[..len]);
            if let Ok((source, payload)) = result {
                return Ok(datagram::Datagram { source, payload });
            }
            // Forged/replayed packets cannot tear down an authenticated association.
            tokio::task::yield_now().await;
        }
    }
}

pub(crate) enum UdpSession {
    Native(Box<NativeUdpSession>),
    Mux(Box<super::mux::UdpSession>),
}
impl UdpSession {
    pub(super) fn max_payload(&self, target: &Target) -> usize {
        match self {
            Self::Native(s) => s.max_payload(target),
            Self::Mux(_) => xray_proxy::mux::MAX_PAYLOAD,
        }
    }
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
    use bytes::Bytes;

    #[tokio::test]
    async fn oversize_native_datagram_is_dropped_and_the_flow_keeps_relaying() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let method = Method::new("aes-128-gcm", "synthetic").unwrap();
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(server.local_addr().unwrap()).await.unwrap();
            let session = datagram::Session::Shadowsocks2022(Box::new(UdpSession::Native(
                Box::new(NativeUdpSession {
                    socket,
                    codec: Mutex::new(wire::UdpSession::new(&method).unwrap()),
                    reader: AsyncMutex::new(vec![0; wire::MAX_UDP_WIRE_LENGTH + 1]),
                }),
            )));
            let target = Target::new(
                RoutingTargetAddr::Domain("example.test".into()),
                443,
                RoutingNetwork::Udp,
            );
            let mut peer = wire::UdpSession::new(&method).unwrap();
            let max = PEER_UDP_BUFFER - peer.overhead(&target).unwrap();
            assert_eq!(session.max_payload(&target), max);

            let (input, ingress) = tokio::sync::mpsc::channel(4);
            input.send(Bytes::from(vec![1; max])).await.unwrap();
            input.send(Bytes::from_static(b"after")).await.unwrap();
            drop(input);
            let mut rejected = Vec::new();
            datagram::relay_udp(
                session,
                &target,
                ingress.into(),
                Bytes::from(vec![0; max + 1]),
                &crate::connection::ConnectionTraffic::default(),
                std::time::Duration::from_secs(1),
                None,
                |payload: Bytes, max_payload| {
                    rejected.push((payload.len(), max_payload));
                    async {}
                },
                |_, _| async { Ok(()) },
            )
            .await
            .unwrap();
            assert_eq!(rejected, [(max + 1, max)]);

            let mut buffer = vec![0; wire::MAX_UDP_WIRE_LENGTH + 1];
            let len = server.recv(&mut buffer).await.unwrap();
            assert_eq!(
                len, PEER_UDP_BUFFER,
                "the largest payload fills Xray's buffer"
            );
            assert_eq!(
                peer.decode(&buffer[..len]).unwrap(),
                (target.clone(), vec![1; max])
            );
            let len = server.recv(&mut buffer).await.unwrap();
            assert_eq!(
                peer.decode(&buffer[..len]).unwrap(),
                (target.clone(), b"after".to_vec())
            );
            assert!(server.try_recv(&mut buffer).is_err());
        })
        .await
        .unwrap();
    }
}
