use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use xray_config::{CoreConfig, InboundSniffingConfig};
use xray_proxy::inbound::{
    read_http_request_head, HttpInboundAccounts, PlainHttpError, PlainHttpRequest,
};
use xray_transport::TransportDialer;

use crate::dns::RuntimeDnsResolvers;
use crate::http_forward::{forward_plain_request, ForwardContext};
use crate::policy::{accept_error_wants_backoff, AcceptBackoff, EffectivePolicy};
use crate::{ConnectionRegistry, OutboundRouter, RuntimeLogger};

/// Xray's answer to `CONNECT`, byte for byte, sent before routing.
pub(crate) const HTTP_CONNECT_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
/// Xray's answer to a request it does not tunnel, byte for byte.
pub(crate) const HTTP_BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nProxy-Connection: close\r\nContent-Length: 0\r\n\r\n";
/// Xray's reply to missing or wrong `Proxy-Authorization`, byte for byte.
pub(crate) const HTTP_PROXY_AUTH_REQUIRED: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n";

#[expect(
    clippy::too_many_arguments,
    reason = "listener tasks receive shared runtime dependencies explicitly"
)]
pub async fn serve_http_listener(
    listener: TcpListener,
    accounts: Arc<HttpInboundAccounts>,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    outbound_router: Arc<OutboundRouter>,
    dns_resolvers: RuntimeDnsResolvers,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    policy: EffectivePolicy,
    runtime_logger: RuntimeLogger,
    connection_registry: Arc<ConnectionRegistry>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    let mut accept_backoff = AcceptBackoff::new();

    loop {
        if *shutdown.borrow() {
            break;
        }

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        if !accept_error_wants_backoff(error.kind()) {
                            continue;
                        }
                        if !accept_backoff.is_backing_off() {
                            // accept() errors carry only OS errno text (no peer
                            // data), and the errno is the operator's signal to
                            // raise `ulimit -n` — so this log skips <redacted>.
                            runtime_logger.error(|| {
                                format!("Debug httpAccept failed, backing off error={error}")
                            });
                        }
                        let delay = accept_backoff.next_delay();
                        tokio::select! {
                            changed = shutdown.changed() => {
                                if changed.is_err() || *shutdown.borrow() {
                                    break;
                                }
                            }
                            _ = tokio::time::sleep(delay) => {}
                        }
                        continue;
                    }
                };
                accept_backoff.reset();
                let accounts = Arc::clone(&accounts);
                let inbound_tag = inbound_tag.clone();
                let config = Arc::clone(&config);
                let outbound_router = Arc::clone(&outbound_router);
                let dns_resolvers = dns_resolvers.clone();
                let transport_dialer = Arc::clone(&transport_dialer);
                let sniffing = sniffing.clone();
                let runtime_logger = runtime_logger.clone();
                let connection_registry = Arc::clone(&connection_registry);
                connections.spawn(async move {
                    serve_http_proxy_connection(
                        stream,
                        tokio::time::Instant::now() + policy.handshake,
                        &accounts,
                        inbound_tag,
                        config,
                        outbound_router,
                        dns_resolvers,
                        transport_dialer,
                        sniffing,
                        policy,
                        runtime_logger,
                        connection_registry,
                    ).await;
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                let _ = joined;
            }
        }
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

/// Serves requests on an HTTP inbound, or on a SOCKS port, as Xray-core's
/// HTTP server does. A request that does not parse is closed without a
/// reply, and one without the accounts' credentials gets the 407. `CONNECT`
/// is answered before routing, so a tunnel that cannot open only closes;
/// then it routes and sniffs as a SOCKS `CONNECT` does. Other requests with
/// an absolute target are forwarded, each routed on its own, and the
/// connection takes another request after a response of known length when
/// the client sent `Proxy-Connection: keep-alive`. A request without a host
/// gets a 400. The first request head must arrive by `deadline`, each later
/// one within the handshake timeout of the response before it.
#[expect(
    clippy::too_many_arguments,
    reason = "connection tasks receive shared runtime dependencies explicitly"
)]
pub(crate) async fn serve_http_proxy_connection(
    mut inbound: TcpStream,
    mut deadline: tokio::time::Instant,
    accounts: &HttpInboundAccounts,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    outbound_router: Arc<OutboundRouter>,
    dns_resolvers: RuntimeDnsResolvers,
    transport_dialer: Arc<TransportDialer>,
    sniffing: Option<InboundSniffingConfig>,
    policy: EffectivePolicy,
    runtime_logger: RuntimeLogger,
    connection_registry: Arc<ConnectionRegistry>,
) {
    loop {
        let Ok(Ok(head)) =
            tokio::time::timeout_at(deadline, read_http_request_head(&mut inbound)).await
        else {
            drain_arrived(&inbound);
            return;
        };
        let Some(user) =
            accounts.basic_user(head.proxy_authorization.as_deref().map(Vec::as_slice))
        else {
            let _ = inbound.write_all(HTTP_PROXY_AUTH_REQUIRED).await;
            return;
        };
        if let Some(target) = head.connect_target() {
            let Ok(target) = target else {
                drain_arrived(&inbound);
                return;
            };
            if inbound.write_all(HTTP_CONNECT_ESTABLISHED).await.is_err() {
                return;
            }
            crate::socks::handle_socks_connect::<false>(
                inbound,
                target,
                user,
                inbound_tag,
                config,
                outbound_router,
                dns_resolvers,
                transport_dialer,
                sniffing,
                policy,
                runtime_logger,
                connection_registry,
            )
            .await;
            return;
        }
        let request = match PlainHttpRequest::new(&head) {
            Ok(request) => request,
            Err(PlainHttpError::NoHost) => {
                let _ = inbound.write_all(HTTP_BAD_REQUEST).await;
                return;
            }
            Err(PlainHttpError::Malformed) => {
                drain_arrived(&inbound);
                return;
            }
        };
        let context = ForwardContext {
            inbound_tag: inbound_tag.as_deref(),
            config: &config,
            router: &outbound_router,
            dns: &dns_resolvers,
            dialer: &transport_dialer,
            policy,
            logger: &runtime_logger,
            registry: &connection_registry,
        };
        let reusable = forward_plain_request(&mut inbound, &request, user.as_ref(), &context).await;
        if !(reusable && request.keep_alive) {
            return;
        }
        deadline = tokio::time::Instant::now() + policy.handshake;
    }
}

/// Reads what has already arrived, as Xray-core's buffered reader has by the
/// time it gives up on a request, so closing ends the connection instead of
/// resetting it over unread bytes.
pub(crate) fn drain_arrived(stream: &TcpStream) {
    let mut buffer = [0; 4096];
    for _ in 0..16 {
        match stream.try_read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}
