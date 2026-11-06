//! HTTP CONNECT client lifecycle over the shared protected stream carrier.
//!
//! TCP only: there is no UDP or Mux path. The CONNECT request carries the
//! configured custom headers and then Xray's browser masquerade block for
//! navigations, as Xray's client sets them. Every transport carries it. TLS
//! offers the application protocols Xray-core offers, `h2` included, and on
//! the raw transport, when the proxy picks `h2`, the tunnel is an HTTP/2
//! stream, and later tunnels share that connection while it takes them, as
//! Xray-core keeps one per proxy.
use super::*;
use std::sync::PoisonError;
use xray_proxy::outbound::{
    encode_connect_request, encode_http2_connect_request, http_connect, Http2ConnectRequest,
    HttpAccount, HttpClientError, HttpHeaderTemplate,
};
use xray_transport::stream::{
    apply_masquerade, HeaderMap, Http2ConnectClient, Http2ConnectError, PrefixedStream,
};
use zeroize::Zeroizing;

const ALPN_HTTP11: &[u8] = b"http/1.1";
const ALPN_H2: &[u8] = b"h2";

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
    /// The HTTP/2 connection to the proxy that new tunnels share while it
    /// takes them.
    http2: std::sync::Mutex<SharedHttp2>,
}

#[derive(Debug, Default)]
struct SharedHttp2 {
    client: Option<Http2ConnectClient>,
    /// Set when the core stops: no connection is kept from then on.
    closed: bool,
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
        // The parser refuses `allowInsecure`; keep that for programmatically
        // built configs.
        if matches!(&config.stream.security, StreamSecurity::Tls(tls) if tls.allow_insecure) {
            return Err(CoreError::UnsupportedOutboundSecurity);
        }
        let mut masquerade = HeaderMap::new();
        apply_masquerade(&mut masquerade, "nav");
        Ok(Self(Arc::new(Payload {
            // A plaintext public server is accepted for HTTP, so an XHTTP
            // download leg to one is too.
            carrier: StreamCarrier::new(
                &config.stream,
                &settings.server,
                settings.port,
                false,
                carrier::TROJAN_PATHS,
            )?,
            account: settings.account.clone(),
            custom: settings.headers.clone(),
            headers: masquerade
                .iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            level: settings.level,
            http2: std::sync::Mutex::default(),
        })))
    }

    /// Lets the shared HTTP/2 connection close once its tunnels end, and
    /// keeps none from then on, as the core closes every outbound's sessions
    /// when it stops.
    pub(crate) fn close(&self) {
        let mut shared = self.0.http2.lock().unwrap_or_else(PoisonError::into_inner);
        shared.closed = true;
        shared.client = None;
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
        if let Some(stream) = self.reuse_http2(target, source).await? {
            return Ok(stream);
        }
        let candidates = resolve_server_candidates(self.server(), resolver).await?;
        let download = self.0.carrier.resolve_download(resolver).await?;
        self.connect(&request, target, source, &candidates, &download, dialer)
            .await
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
        if let Some(stream) = self.reuse_http2(target, source).await? {
            return Ok(stream);
        }
        self.connect(&request, target, source, candidates, download, dialer)
            .await
    }

    /// The request's fields before encoding, in the order Xray-core sets
    /// them: the custom ones, filled in for `source` and `target`, then the
    /// masquerade block, which a custom `User-Agent` other than a browser's
    /// name leaves out. `render` gives each custom value in the form it is
    /// sent: Go's HTTP/1.1 form, or as it is for HTTP/2.
    fn fields(&self, render: impl Fn(&HttpHeaderTemplate) -> String) -> Vec<(String, String)> {
        if self.0.custom.is_empty() {
            return self.0.headers.clone();
        }
        let mut headers = HeaderMap::new();
        for (name, template) in &self.0.custom {
            headers.set(name, &render(template));
        }
        apply_masquerade(&mut headers, "nav");
        headers
            .iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect()
    }

    /// The HTTP/1.1 `CONNECT` request.
    fn request(
        &self,
        target: &Target,
        source: Option<SocketAddr>,
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let fields = self.fields(|template| template.render(source, target));
        let headers: Vec<(&str, &str)> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        Ok(encode_connect_request(
            target,
            self.0.account.as_ref(),
            &headers,
        )?)
    }

    /// The HTTP/2 `CONNECT` request, with the values as Go's HTTP/2 client
    /// sends them.
    fn http2_request(
        &self,
        target: &Target,
        source: Option<SocketAddr>,
    ) -> Result<Http2ConnectRequest, CoreError> {
        let fields = self.fields(|template| template.render_raw(source, target));
        let headers: Vec<(&str, &str)> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        Ok(encode_http2_connect_request(
            target,
            self.0.account.as_ref(),
            &headers,
        )?)
    }

    /// Opens the tunnel on the shared HTTP/2 connection while it takes new
    /// ones, before any lookup or dial, as Xray-core tries its cached
    /// connection first. `None` asks for a new connection: there is no shared
    /// one, it takes no more tunnels, or it failed before the proxy processed
    /// this one. The new connection then replaces it.
    async fn reuse_http2(
        &self,
        target: &Target,
        source: Option<SocketAddr>,
    ) -> Result<Option<BoxedTransportStream>, CoreError> {
        let shared = self
            .0
            .http2
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .client
            .as_ref()
            .filter(|client| client.can_take_new_tunnel())
            .cloned();
        let Some(client) = shared else {
            return Ok(None);
        };
        let request = self.http2_request(target, source)?;
        match client.open(request.authority(), &request.fields()).await {
            Ok(stream) => Ok(Some(stream)),
            Err(error) if error.connection_unusable() => Ok(None),
            Err(error) => Err(http2_error(error)),
        }
    }

    /// Dials the proxy and opens the tunnel in the protocol its TLS
    /// negotiated, as [`Self::negotiated_http2`] reads it. Bytes that arrived
    /// with an HTTP/1.1 200 response are replayed before the stream is read
    /// again.
    async fn connect(
        &self,
        request: &[u8],
        target: &Target,
        source: Option<SocketAddr>,
        candidates: &[SocketAddr],
        download: &[SocketAddr],
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        let mut stream = self.0.carrier.open(candidates, download, dialer).await?;
        if self.negotiated_http2(stream.negotiated_alpn())? {
            return self.connect_http2(stream, target, source).await;
        }
        stream.release_record_alignment();
        let early = http_connect(&mut stream, request).await?;
        Ok(if early.is_empty() {
            stream
        } else {
            Box::new(PrefixedStream::new(stream, early))
        })
    }

    /// Whether a new connection's tunnel is HTTP/2: the proxy's TLS picked
    /// `h2`, which Xray-core reads only from the raw transport's TLS.
    ///
    /// Every other transport, and REALITY, carries HTTP/1.1 whatever was
    /// negotiated, as there. Xray-core's own REALITY server negotiates no
    /// protocol, but another may, and the proxy behind it reads the request
    /// Xray-core's client sends.
    fn negotiated_http2(&self, alpn: Option<&[u8]>) -> Result<bool, HttpClientError> {
        let carrier = &self.0.carrier;
        if !matches!(carrier.transport_layer, TransportLayer::Raw)
            || !matches!(carrier.transport, ConnectorConfig::Tls(_))
        {
            return Ok(false);
        }
        match alpn {
            None | Some(ALPN_HTTP11) => Ok(false),
            Some(ALPN_H2) => Ok(true),
            Some(_) => Err(HttpClientError::UnsupportedApplicationProtocol),
        }
    }

    /// Opens HTTP/2 on a new connection and the tunnel on it, then keeps the
    /// connection for the tunnels that follow, as Xray-core caches it once its
    /// first tunnel opened.
    async fn connect_http2(
        &self,
        stream: BoxedTransportStream,
        target: &Target,
        source: Option<SocketAddr>,
    ) -> Result<BoxedTransportStream, CoreError> {
        let request = self.http2_request(target, source)?;
        let client = Http2ConnectClient::handshake(stream)
            .await
            .map_err(http2_error)?;
        let tunnel = client
            .open(request.authority(), &request.fields())
            .await
            .map_err(http2_error)?;
        let mut shared = self.0.http2.lock().unwrap_or_else(PoisonError::into_inner);
        if !shared.closed {
            shared.client = Some(client);
        }
        Ok(tunnel)
    }
}

/// A refusal reads as the HTTP/1.1 client reports it.
fn http2_error(error: Http2ConnectError) -> CoreError {
    match error {
        Http2ConnectError::Rejected(407) => HttpClientError::ProxyAuthenticationRequired.into(),
        Http2ConnectError::Rejected(status) => HttpClientError::Rejected(status).into(),
        Http2ConnectError::InvalidField => HttpClientError::InvalidHeader.into(),
        error => TransportError::from(error).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http2_refusals_read_as_http1_ones() {
        assert!(matches!(
            http2_error(Http2ConnectError::Rejected(407)),
            CoreError::Http(HttpClientError::ProxyAuthenticationRequired)
        ));
        assert!(matches!(
            http2_error(Http2ConnectError::Rejected(403)),
            CoreError::Http(HttpClientError::Rejected(403))
        ));
        assert!(matches!(
            http2_error(Http2ConnectError::InvalidField),
            CoreError::Http(HttpClientError::InvalidHeader)
        ));
        assert!(matches!(
            http2_error(Http2ConnectError::Protocol("reset".to_owned())),
            CoreError::Transport(TransportError::Http2Connect(_))
        ));
    }

    fn outbound(stream: serde_json::Value) -> HttpOutbound {
        let raw = serde_json::json!({"outbounds":[{"protocol":"http",
            "settings":{"address":"proxy.example","port":443},"streamSettings":stream}]});
        let config = xray_config::parse_xray_json(&raw.to_string())
            .unwrap_or_else(|error| panic!("{raw}: {:?}", error.diagnostics))
            .config;
        HttpOutbound::new(&config.outbounds[0]).unwrap_or_else(|error| panic!("{raw}: {error:?}"))
    }

    fn reality() -> serde_json::Value {
        serde_json::json!({"serverName":"proxy.example","fingerprint":"chrome",
            "publicKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","shortId":"02030405"})
    }

    #[test]
    fn every_transport_and_security_builds() {
        let tls = serde_json::json!({"serverName":"proxy.example"});
        for stream in [
            serde_json::json!({}),
            serde_json::json!({"security":"tls","tlsSettings":tls}),
            serde_json::json!({"security":"reality","realitySettings":reality()}),
            serde_json::json!({"network":"ws","security":"tls","tlsSettings":tls}),
            serde_json::json!({"network":"httpupgrade"}),
            serde_json::json!({"network":"grpc","security":"reality","realitySettings":reality()}),
            serde_json::json!({"network":"xhttp","security":"reality","realitySettings":reality()}),
            serde_json::json!({"network":"xhttp","xhttpSettings":{"downloadSettings":{
                "address":"198.51.100.20","port":443,"network":"xhttp"}}}),
        ] {
            outbound(stream);
        }
    }

    /// Only the raw transport's TLS decides the tunnel's protocol, as in
    /// Xray-core; everything else, REALITY included, carries HTTP/1.1.
    #[test]
    fn only_raw_tls_negotiates_the_tunnel_protocol() {
        let tls = serde_json::json!({"serverName":"proxy.example"});
        let raw_tls = outbound(serde_json::json!({"security":"tls","tlsSettings":tls}));
        assert!(raw_tls.negotiated_http2(Some(ALPN_H2)).unwrap());
        assert!(!raw_tls.negotiated_http2(Some(ALPN_HTTP11)).unwrap());
        assert!(!raw_tls.negotiated_http2(None).unwrap());
        assert!(matches!(
            raw_tls.negotiated_http2(Some(b"spdy/3")),
            Err(HttpClientError::UnsupportedApplicationProtocol)
        ));
        for stream in [
            serde_json::json!({"security":"reality","realitySettings":reality()}),
            serde_json::json!({"network":"ws","security":"tls","tlsSettings":tls}),
            serde_json::json!({"network":"grpc","security":"tls","tlsSettings":tls}),
            serde_json::json!({"network":"xhttp","security":"tls","tlsSettings":tls}),
        ] {
            let carried = outbound(stream.clone());
            for alpn in [Some(ALPN_H2), Some(&b"spdy/3"[..]), None] {
                assert!(
                    !carried.negotiated_http2(alpn).unwrap(),
                    "{stream} {alpn:?}"
                );
            }
        }
    }
}

#[cfg(test)]
mod close_tests {
    use super::*;

    fn outbound() -> HttpOutbound {
        let config = xray_config::parse_xray_json(
            r#"{"outbounds":[{"protocol":"http","settings":{"address":"192.0.2.1","port":443}}]}"#,
        )
        .unwrap()
        .config;
        HttpOutbound::new(&config.outbounds[0]).unwrap()
    }

    /// An HTTP/2 connection to a proxy that answers every CONNECT with 200.
    fn accepting_proxy() -> BoxedTransportStream {
        let (client, server) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let mut answered = Vec::new();
            while let Some(Ok((_request, mut respond))) = connection.accept().await {
                answered.push(respond.send_response(::http::Response::new(()), false));
            }
        });
        Box::new(client)
    }

    #[tokio::test]
    async fn a_stopped_outbound_keeps_no_new_connection() {
        let target = Target::new(
            RoutingTargetAddr::Domain("example.com".to_owned()),
            443,
            RoutingNetwork::Tcp,
        );
        let open = outbound();
        let _kept = open
            .connect_http2(accepting_proxy(), &target, None)
            .await
            .unwrap();
        assert!(open.0.http2.lock().unwrap().client.is_some());

        // A tunnel whose handshake finishes after the core began to stop.
        let closed = outbound();
        closed.close();
        let _tunnel = closed
            .connect_http2(accepting_proxy(), &target, None)
            .await
            .unwrap();
        assert!(closed.0.http2.lock().unwrap().client.is_none());
    }
}
