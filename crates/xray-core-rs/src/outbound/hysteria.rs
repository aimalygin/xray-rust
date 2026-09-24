//! Runtime ownership of one authenticated connection per configured Hysteria outbound.
use super::*;
use std::sync::atomic::AtomicBool;
use tokio::sync::Mutex as AsyncMutex;
use xray_transport::hysteria::{HysteriaClient, HysteriaConfig, HysteriaError, HysteriaUdpSession};

#[derive(Clone, Debug)]
pub struct HysteriaOutbound {
    inner: Arc<SessionOwner>,
}

#[derive(Debug)]
struct SessionOwner {
    server: Target,
    tls: TlsClientConfig,
    auth: xray_config::HysteriaSettings,
    // Synchronous ownership permits deterministic close even while a dial is pending.
    session: Mutex<Option<CachedSession>>,
    connecting: AsyncMutex<()>,
    closed: AtomicBool,
    network_generation: std::sync::atomic::AtomicU64,
    shutdown: tokio::sync::watch::Sender<bool>,
}

#[derive(Debug)]
struct CachedSession {
    client: HysteriaClient,
    connector: xray_transport::TlsConnector,
}

impl Drop for CachedSession {
    fn drop(&mut self) {
        self.client.close();
    }
}

impl HysteriaOutbound {
    pub(crate) fn new(config: &OutboundConfig) -> Result<Self, CoreError> {
        let (
            OutboundSettings::Hysteria(server),
            StreamTransport::Hysteria(auth),
            StreamSecurity::Tls(tls),
        ) = (
            &config.settings,
            &config.stream.transport,
            &config.stream.security,
        )
        else {
            return Err(CoreError::UnsupportedOutboundSecurity);
        };
        if config.stream.network != Network::Udp
            || config.proxy_settings.is_some()
            || config.stream.quic_params.is_some()
            || config.stream.socket_options.is_some()
            || tls.allow_insecure
            || tls.fingerprint.is_some()
            || (!tls.alpn.is_empty() && tls.alpn != ["h3"])
            || server.port == 0
            || auth.auth.is_empty()
            || auth.auth.len() > 4096
            || auth.auth.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        let server_name = tls
            .server_name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| match &server.server {
                TargetAddr::Domain(domain) => domain.clone(),
                TargetAddr::Ip(ip) => ip.to_string(),
            });
        xray_transport::validate_tls_server_name(&server_name)
            .map_err(|_| CoreError::UnsupportedOutboundSecurity)?;
        Ok(Self {
            inner: Arc::new(SessionOwner {
                server: Target::new(
                    match &server.server {
                        TargetAddr::Domain(domain) => RoutingTargetAddr::Domain(domain.clone()),
                        TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
                    },
                    server.port,
                    RoutingNetwork::Udp,
                ),
                tls: TlsClientConfig {
                    server_name,
                    allow_insecure: false,
                    pinned_peer_cert_sha256: tls.pinned_peer_cert_sha256.clone(),
                    verify_peer_cert_by_name: tls.verify_peer_cert_by_name.clone(),
                    alpn: vec!["h3".into()],
                    fingerprint: None,
                },
                auth: auth.clone(),
                session: Mutex::new(None),
                connecting: AsyncMutex::new(()),
                closed: AtomicBool::new(false),
                network_generation: std::sync::atomic::AtomicU64::new(0),
                shutdown: tokio::sync::watch::channel(false).0,
            }),
        })
    }

    pub(super) fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.shutdown.send_replace(true);
        if let Some(client) = self
            .inner
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            client.client.close();
        }
    }

    pub(super) fn rebind(&self) -> bool {
        let cached = self.inner.session.lock().unwrap_or_else(|e| e.into_inner());
        self.inner.network_generation.fetch_add(1, Ordering::AcqRel);
        cached
            .as_ref()
            .is_some_and(|session| session.client.rebind())
    }

    async fn client(
        &self,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<HysteriaClient, CoreError> {
        let mut shutdown = self.inner.shutdown.subscribe();
        if *shutdown.borrow() {
            return Err(HysteriaError::Closed.into());
        }
        // One total deadline includes contention, endpoint DNS and candidate attempts.
        tokio::select! {
            biased;
            _ = shutdown.changed() => Err(HysteriaError::Closed.into()),
            result = tokio::time::timeout(Duration::from_secs(10), self.client_inner(resolver, dialer)) => result.map_err(|_| HysteriaError::Timeout)?,
        }
    }

    async fn client_inner(
        &self,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<HysteriaClient, CoreError> {
        let _admission = self.inner.connecting.lock().await;
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(HysteriaError::Closed.into());
        }
        {
            let mut cached = self.inner.session.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(session) = cached.as_ref().filter(|s| s.client.is_live()) {
                if !session
                    .connector
                    .shares_session_context(dialer.tls_connector())
                {
                    return Err(HysteriaError::Configuration.into());
                }
                return Ok(session.client.clone());
            }
            if let Some(stale) = cached.take() {
                drop(stale);
            }
        }
        let candidates = resolve_server_candidates(&self.inner.server, resolver).await?;
        let mut last = HysteriaError::Connect;
        for candidate in candidates.into_iter().take(8) {
            let mut config = HysteriaConfig::new(candidate, self.inner.tls.clone(), String::new());
            config.auth = self.inner.auth.auth.clone();
            // Give later DNS candidates a chance within the total operation deadline.
            let generation = self.inner.network_generation.load(Ordering::Acquire);
            let attempt = tokio::time::timeout(
                Duration::from_secs(3),
                HysteriaClient::connect(config, dialer.tls_connector()),
            )
            .await;
            match attempt.unwrap_or(Err(HysteriaError::Timeout)) {
                Ok(client) => {
                    let mut cached = self.inner.session.lock().unwrap_or_else(|e| e.into_inner());
                    if self.inner.closed.load(Ordering::Acquire) {
                        client.close();
                        return Err(HysteriaError::Closed.into());
                    }
                    // A usable-path update during auth/socket creation must
                    // also reach a client that was not cached at that instant.
                    if self.inner.network_generation.load(Ordering::Acquire) != generation {
                        client.rebind();
                    }
                    *cached = Some(CachedSession {
                        client: client.clone(),
                        connector: dialer.tls_connector().clone(),
                    });
                    return Ok(client);
                }
                Err(
                    error @ (HysteriaError::SocketProtection
                    | HysteriaError::Authentication
                    | HysteriaError::AuthenticationHeaders
                    | HysteriaError::Configuration
                    | HysteriaError::TlsConfiguration),
                ) => return Err(error.into()),
                Err(error) => last = error,
            }
        }
        Err(last.into())
    }

    pub(crate) async fn open_tcp(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        Ok(Box::new(
            self.client(resolver, dialer)
                .await?
                .open_tcp(target)
                .await?,
        ))
    }

    pub(crate) async fn open_udp(
        &self,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<HysteriaUdpSession, CoreError> {
        Ok(self.client(resolver, dialer).await?.open_udp()?)
    }
}

#[cfg(test)]
mod tests;
