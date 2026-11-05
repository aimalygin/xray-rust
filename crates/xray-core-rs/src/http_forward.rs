//! Plain HTTP forwarding on the HTTP inbound, as Xray-core's
//! `handlePlainHTTP` does it: each request is routed on its own, sent on
//! with `Connection: close`, and its response written back, keeping the
//! client connection when the response's length is known and the client
//! asked to.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;
use xray_config::{ContentAttributes, CoreConfig, RouteContext};
use xray_proxy::inbound::{
    copy_body_chunked, copy_body_length, read_http_response, HttpBody, InboundUser,
    PlainHttpRequest,
};
use xray_transport::TransportDialer;

use crate::connection::{wait_for_connection_close, ConnectionTraffic};
use crate::dns::RuntimeDnsResolvers;
use crate::outbound::{
    open_tcp_stream_with_resolvers_and_dialer, InboundSource, TcpSessionOutbound,
};
use crate::policy::EffectivePolicy;
use crate::{ConnectionRegistry, OutboundRouter, RuntimeLogger};

/// Xray's answer when a forwarded request gets no response, byte for byte.
pub(crate) const HTTP_SERVICE_UNAVAILABLE: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nProxy-Connection: close\r\nContent-Length: 0\r\n\r\n";

/// The shared state of one inbound connection.
pub(crate) struct ForwardContext<'a> {
    pub inbound_tag: Option<&'a str>,
    pub config: &'a Arc<CoreConfig>,
    pub router: &'a Arc<OutboundRouter>,
    pub dns: &'a RuntimeDnsResolvers,
    pub dialer: &'a Arc<TransportDialer>,
    pub policy: EffectivePolicy,
    pub logger: &'a RuntimeLogger,
    pub registry: &'a Arc<ConnectionRegistry>,
}

/// Forwards one plain request and reports whether the client connection can
/// take another: when the response's length was known and every byte went
/// through.
pub(crate) async fn forward_plain_request(
    inbound: &mut TcpStream,
    request: &PlainHttpRequest,
    user: Option<&InboundUser>,
    context: &ForwardContext<'_>,
) -> bool {
    let forwarded = request.forwarded_head();
    let restored = context
        .dns
        .outbound
        .restore_client_target(&request.destination);
    // Xray-core's HTTP inbound gives each forwarded request a content of
    // its own, without the inbound's sniffing settings, so nothing sniffs
    // it, and routing sees the protocol as `http/1.1`.
    let route_target = restored.target;
    let dial_target = route_target.clone();
    let protocol = "http/1.1";

    let mut attributes = ContentAttributes::default();
    for (name, value) in request.attributes() {
        attributes.set(name, String::from_utf8_lossy(&value).into_owned());
    }
    let route = RouteContext {
        inbound_tag: context.inbound_tag,
        source: inbound.peer_addr().ok(),
        local: inbound.local_addr().ok(),
        user: user.map(InboundUser::as_str),
        protocol: Some(protocol),
        attributes: Some(&attributes),
    };
    let selected = context
        .router
        .select_tcp_session_outbound_with_tag_and_resolver(
            &route,
            &route_target,
            &dial_target,
            true,
            context.dns.destination.as_ref(),
        )
        .await;
    let source = context.logger.is_enabled().then(|| {
        inbound
            .peer_addr()
            .map_or_else(|_| "unknown".to_owned(), |addr| addr.to_string())
    });
    let selected = match selected {
        Ok(selected) => selected,
        Err(error) => {
            if let Some(source) = source.as_deref() {
                crate::debug_log::log_access_rejected(context.logger, source, &route_target, error);
            }
            let _ = inbound.write_all(HTTP_SERVICE_UNAVAILABLE).await;
            return false;
        }
    };
    let connection = context.registry.register(
        context.inbound_tag.map(ToOwned::to_owned),
        selected.tag.clone(),
        dial_target.clone(),
    );
    let mut connection_close = connection.close_receiver();
    let traffic = connection.traffic();

    let outcome = match selected.outbound {
        TcpSessionOutbound::Transport(outbound) => {
            // A request and its response share the connIdle bound, with no
            // half-close phase between them.
            let (open_timeout, timeouts, _) =
                crate::socks::tcp_relay_policy(context.config, &context.policy, &outbound);
            let idle = timeouts.conn_idle;
            let client = outbound
                .names_the_client()
                .then(|| inbound.peer_addr().ok().map(InboundSource::tcp))
                .flatten();
            let opened = tokio::select! {
                result = tokio::time::timeout(
                    open_timeout,
                    open_tcp_stream_with_resolvers_and_dialer(
                        &outbound,
                        &dial_target,
                        context.dns.destination.as_ref(),
                        context.dns.bootstrap.as_ref(),
                        context.dialer.as_ref(),
                        client.as_ref(),
                    ),
                ) => result.ok().and_then(Result::ok),
                () = wait_for_connection_close(&mut connection_close) => None,
            };
            match opened {
                Some(upstream) => {
                    if let Some(source) = source.as_deref() {
                        crate::debug_log::log_access_accepted(
                            context.logger,
                            source,
                            &dial_target,
                            crate::debug_log::tcp_outbound_label(&outbound),
                        );
                    }
                    connection.mark_active();
                    tokio::select! {
                        result = exchange(inbound, upstream, request, &forwarded, idle, &traffic) => result,
                        () = wait_for_connection_close(&mut connection_close) => false,
                    }
                }
                None => {
                    if let Some(source) = source.as_deref() {
                        crate::debug_log::log_access_rejected(
                            context.logger,
                            source,
                            &dial_target,
                            "outbound tcp open failed",
                        );
                    }
                    let _ = inbound.write_all(HTTP_SERVICE_UNAVAILABLE).await;
                    false
                }
            }
        }
        // A blackhole's reply, if any, is the response; a DNS outbound reads
        // no request from HTTP, so neither gives one.
        TcpSessionOutbound::Blackhole(blackhole) => {
            if let Some(source) = source.as_deref() {
                crate::debug_log::log_access_accepted(
                    context.logger,
                    source,
                    &dial_target,
                    "blackhole",
                );
            }
            connection.mark_active();
            let reply = std::io::Cursor::new(blackhole.response_bytes().to_vec());
            exchange(
                inbound,
                Discarding(reply),
                request,
                &forwarded,
                context.policy.conn_idle,
                &traffic,
            )
            .await
        }
        TcpSessionOutbound::Dns(_) => {
            let _ = inbound.write_all(HTTP_SERVICE_UNAVAILABLE).await;
            false
        }
    };
    connection.finish();
    outcome
}

/// Sends the request on and its response back, both at once, as Xray-core's
/// two tasks do, so that a server can answer `100 Continue` before the body.
async fn exchange<S>(
    inbound: &mut TcpStream,
    upstream: S,
    request: &PlainHttpRequest,
    forwarded: &[u8],
    idle: Duration,
    traffic: &ConnectionTraffic,
) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Arc::new(AtomicBool::new(false));
    let (client_read, client_write) = inbound.split();
    let mut client_read = Tracked::new(client_read, &activity, None);
    let mut client_write = Tracked::new(client_write, &activity, Some(&traffic.downlink_bytes));
    let (upstream_read, upstream_write) = tokio::io::split(Tracked::new(
        upstream,
        &activity,
        Some(&traffic.uplink_bytes),
    ));
    let mut upstream_read = BufReader::new(upstream_read);
    let mut upstream_write = upstream_write;

    let upload = async {
        upstream_write.write_all(forwarded).await?;
        match request.body {
            HttpBody::Length(length) => {
                copy_body_length(&mut client_read, &mut upstream_write, length).await?;
            }
            HttpBody::Chunked => {
                copy_body_chunked(&mut client_read, &mut upstream_write).await?;
            }
            HttpBody::None | HttpBody::UntilClose => {}
        }
        upstream_write.flush().await
    };
    let download = async {
        let Ok(response) = read_http_response(&mut upstream_read, &request.method).await else {
            let _ = client_write.write_all(HTTP_SERVICE_UNAVAILABLE).await;
            return Err(std::io::ErrorKind::InvalidData.into());
        };
        if let Some(informational) = &response.informational {
            client_write.write_all(informational).await?;
        }
        let head = response.head;
        client_write
            .write_all(&head.client_head(&request.method))
            .await?;
        match head.body {
            HttpBody::Length(length) => {
                copy_body_length(&mut upstream_read, &mut client_write, length).await?;
            }
            HttpBody::Chunked => {
                copy_body_chunked(&mut upstream_read, &mut client_write).await?;
            }
            HttpBody::UntilClose => {
                tokio::io::copy(&mut upstream_read, &mut client_write).await?;
            }
            HttpBody::None => {}
        }
        client_write.flush().await?;
        std::io::Result::Ok(head.keeps_alive())
    };
    let exchanged = async { tokio::join!(upload, download) };
    tokio::select! {
        (uploaded, downloaded) = exchanged => uploaded.is_ok() && downloaded.unwrap_or(false),
        () = idle_timeout(&activity, idle) => false,
    }
}

/// Resolves once a whole `idle` period passes without any byte moving.
async fn idle_timeout(activity: &AtomicBool, idle: Duration) {
    loop {
        tokio::time::sleep(idle).await;
        if !activity.swap(false, Ordering::Relaxed) {
            return;
        }
    }
}

/// A stream that marks activity whenever bytes move, and counts the bytes
/// written through it.
struct Tracked<'a, S> {
    inner: S,
    activity: &'a AtomicBool,
    written: Option<&'a AtomicU64>,
}

impl<'a, S> Tracked<'a, S> {
    fn new(inner: S, activity: &'a Arc<AtomicBool>, written: Option<&'a AtomicU64>) -> Self {
        Self {
            inner,
            activity: activity.as_ref(),
            written,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.activity.store(true, Ordering::Relaxed);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = polled {
            self.activity.store(true, Ordering::Relaxed);
            if let Some(counter) = self.written {
                counter.fetch_add(written as u64, Ordering::Relaxed);
            }
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A blackhole's reply as a stream that swallows whatever is sent to it.
struct Discarding(std::io::Cursor<Vec<u8>>);

impl AsyncRead for Discarding {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Discarding {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
