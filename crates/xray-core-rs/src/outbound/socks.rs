//! SOCKS5 client lifecycle over the shared protected stream carrier.
//!
//! TCP CONNECT only: the outbound has no UDP or Mux path, so UDP routed to it
//! is refused when the outbound is selected.
use super::*;
use xray_proxy::inbound::SocksAccount;
use xray_proxy::outbound::{socks5_connect, validate_connect_target};

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
}
