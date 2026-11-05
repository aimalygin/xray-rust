//! HTTP CONNECT client lifecycle over the shared protected stream carrier.
//!
//! TCP only: there is no UDP or Mux path. The CONNECT request carries the
//! configured custom headers and then Xray's browser masquerade block for
//! navigations, as Xray's HTTP/1.1 client sets them, and TLS offers only
//! `http/1.1` because HTTP/2 CONNECT is not implemented.
use super::*;
use xray_proxy::outbound::{encode_connect_request, http_connect, HttpAccount, HttpHeaderTemplate};
use xray_transport::stream::{apply_masquerade, HeaderMap, PrefixedStream};
use zeroize::Zeroizing;

const ALPN_HTTP11: &str = "http/1.1";

#[derive(Debug, Clone)]
pub struct HttpOutbound(Arc<Payload>);

#[derive(Debug)]
struct Payload {
    carrier: StreamCarrier,
    account: Option<HttpAccount>,
    /// The configured custom headers, filled in for each connection.
    custom: Vec<(String, HttpHeaderTemplate)>,
    /// The masquerade block alone, for profiles without custom headers.
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
            custom: settings.headers.clone(),
            headers: masquerade
                .iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            level: settings.level,
        })))
    }

    /// Whether a custom header names the connection's source, which then has
    /// to reach [`Self::open`].
    pub(crate) fn names_the_client(&self) -> bool {
        self.0
            .custom
            .iter()
            .any(|(_, template)| template.uses_source())
    }

    pub fn server(&self) -> &Target {
        &self.0.carrier.server
    }
    pub fn level(&self) -> u32 {
        self.0.level
    }

    /// Opens a tunnel to `target`; `source` is the client its custom headers
    /// may name.
    pub(super) async fn open(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
        source: Option<SocketAddr>,
    ) -> Result<BoxedTransportStream, CoreError> {
        // Validate before DNS or dialing, including programmatically built targets.
        let request = self.request(target, source)?;
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
        source: Option<SocketAddr>,
    ) -> Result<BoxedTransportStream, CoreError> {
        let request = self.request(target, source)?;
        self.connect(&request, candidates, download, dialer).await
    }

    /// The `CONNECT` request, with the headers Xray-core sets in this order:
    /// the custom ones, filled in for `source` and `target`, then the
    /// masquerade block, which a custom `User-Agent` other than a browser's
    /// name leaves out.
    fn request(
        &self,
        target: &Target,
        source: Option<SocketAddr>,
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let filled;
        let headers: Vec<(&str, &str)> = if self.0.custom.is_empty() {
            self.0
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect()
        } else {
            let mut headers = HeaderMap::new();
            for (name, template) in &self.0.custom {
                headers.set(name, &template.render(source, target));
            }
            apply_masquerade(&mut headers, "nav");
            filled = headers;
            filled.iter().collect()
        };
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
