//! HTTP CONNECT client lifecycle over the shared protected stream carrier.
//!
//! TCP only: there is no UDP or Mux path. The CONNECT request carries Xray's
//! browser masquerade block for navigations, as Xray's HTTP/1.1 client does,
//! and TLS offers only `http/1.1` because HTTP/2 CONNECT is not implemented.
use super::*;
use xray_proxy::outbound::{encode_connect_request, http_connect, HttpAccount};
use xray_transport::stream::{apply_masquerade, HeaderMap, PrefixedStream};
use zeroize::Zeroizing;

const ALPN_HTTP11: &str = "http/1.1";

#[derive(Debug, Clone)]
pub struct HttpOutbound(Arc<Payload>);

#[derive(Debug)]
struct Payload {
    carrier: StreamCarrier,
    account: Option<HttpAccount>,
    headers: Vec<(String, String)>,
    level: u32,
}

impl HttpOutbound {
    pub(super) fn new(config: &OutboundConfig) -> Result<Self, CoreError> {
        let OutboundSettings::Http(settings) = &config.settings else {
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
        // The parser enforces raw/tcp with none or TLS offering at most
        // `http/1.1`; keep that invariant for programmatically built configs.
        if config.stream.transport != StreamTransport::Raw {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        let mut stream = config.stream.clone();
        match &mut stream.security {
            StreamSecurity::None => {}
            StreamSecurity::Tls(tls)
                if !tls.allow_insecure
                    && tls.alpn.len() <= 1
                    && tls.alpn.iter().all(|protocol| protocol == ALPN_HTTP11) =>
            {
                // Always offer it, so a shaped ClientHello cannot negotiate h2.
                tls.alpn = vec![ALPN_HTTP11.to_owned()];
            }
            StreamSecurity::Tls(_) | StreamSecurity::Reality(_) => {
                return Err(CoreError::UnsupportedOutboundSecurity);
            }
        }
        let mut masquerade = HeaderMap::new();
        apply_masquerade(&mut masquerade, "nav");
        Ok(Self(Arc::new(Payload {
            carrier: StreamCarrier::new(
                &stream,
                &settings.server,
                settings.port,
                true,
                carrier::TROJAN_PATHS,
            )?,
            account: settings.account.clone(),
            headers: masquerade
                .iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
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
        let request = self.request(target)?;
        let candidates = resolve_server_candidates(self.server(), resolver).await?;
        let download = self.0.carrier.resolve_download(resolver).await?;
        self.connect(&request, &candidates, &download, dialer).await
    }

    pub(super) async fn open_resolved(
        &self,
        target: &Target,
        candidates: &[SocketAddr],
        download: &[SocketAddr],
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        let request = self.request(target)?;
        self.connect(&request, candidates, download, dialer).await
    }

    fn request(&self, target: &Target) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let headers: Vec<(&str, &str)> = self
            .0
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        Ok(encode_connect_request(
            target,
            self.0.account.as_ref(),
            &headers,
        )?)
    }

    /// Bytes that arrived with the 200 response are replayed before the
    /// stream is read again.
    async fn connect(
        &self,
        request: &[u8],
        candidates: &[SocketAddr],
        download: &[SocketAddr],
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        let mut stream = self.0.carrier.open(candidates, download, dialer).await?;
        stream.release_record_alignment();
        let early = http_connect(&mut stream, request).await?;
        Ok(if early.is_empty() {
            stream
        } else {
            Box::new(PrefixedStream::new(stream, early))
        })
    }
}
