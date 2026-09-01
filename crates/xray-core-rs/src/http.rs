use std::sync::Arc;

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use xray_config::CoreConfig;
use xray_proxy::inbound::parse_http_connect;
use xray_transport::TransportDialer;

use crate::connection::wait_for_connection_close;
use crate::dns::RuntimeDnsResolvers;
use crate::outbound::{open_tcp_stream_with_resolvers_and_dialer, TcpSessionOutbound};
use crate::policy::{
    accept_error_wants_backoff, copy_bidirectional_with_idle_timeout_and_traffic,
    effective_policy_for_level, AcceptBackoff, EffectivePolicy,
};
use crate::{ConnectionRegistry, OutboundRouter, RuntimeLogger, TcpOutbound};

const HTTP_CONNECT_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const HTTP_BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
const HTTP_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

#[expect(
    clippy::too_many_arguments,
    reason = "listener tasks receive shared runtime dependencies explicitly"
)]
pub async fn serve_http_listener(
    listener: TcpListener,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    outbound_router: Arc<OutboundRouter>,
    dns_resolvers: RuntimeDnsResolvers,
    transport_dialer: Arc<TransportDialer>,
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
                let inbound_tag = inbound_tag.clone();
                let config = Arc::clone(&config);
                let outbound_router = Arc::clone(&outbound_router);
                let dns_resolvers = dns_resolvers.clone();
                let transport_dialer = Arc::clone(&transport_dialer);
                let runtime_logger = runtime_logger.clone();
                let connection_registry = Arc::clone(&connection_registry);
                connections.spawn(async move {
                    handle_http_connection(
                        stream,
                        inbound_tag,
                        config,
                        outbound_router,
                        dns_resolvers,
                        transport_dialer,
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

#[expect(
    clippy::too_many_arguments,
    reason = "connection tasks receive shared runtime dependencies explicitly"
)]
async fn handle_http_connection(
    mut inbound: TcpStream,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    outbound_router: Arc<OutboundRouter>,
    dns_resolvers: RuntimeDnsResolvers,
    transport_dialer: Arc<TransportDialer>,
    policy: EffectivePolicy,
    runtime_logger: RuntimeLogger,
    connection_registry: Arc<ConnectionRegistry>,
) {
    let source = runtime_logger.is_enabled().then(|| {
        inbound
            .peer_addr()
            .map_or_else(|_| "unknown".to_owned(), |addr| addr.to_string())
    });
    let raw_target =
        match tokio::time::timeout(policy.handshake, parse_http_connect(&mut inbound)).await {
            Ok(Ok(target)) => target,
            _ => {
                let _ = inbound.write_all(HTTP_BAD_REQUEST).await;
                return;
            }
        };
    let target = dns_resolvers
        .outbound
        .restore_client_target(&raw_target)
        .target;

    let selected = match outbound_router
        .select_tcp_session_outbound_with_tag_and_resolver(
            inbound_tag.as_deref(),
            &target,
            true,
            dns_resolvers.destination.as_ref(),
        )
        .await
    {
        Ok(outbound) => outbound,
        Err(error) => {
            if let Some(source) = source.as_deref() {
                crate::debug_log::log_access_rejected(&runtime_logger, source, &target, error);
            }
            let _ = inbound.write_all(HTTP_BAD_GATEWAY).await;
            return;
        }
    };
    let connection =
        connection_registry.register(inbound_tag.clone(), selected.tag.clone(), target.clone());
    let mut connection_close = connection.close_receiver();
    let connection_traffic = connection.traffic();

    if runtime_logger.is_enabled() {
        let selected_outbound = match &selected.outbound {
            TcpSessionOutbound::Transport(outbound) => {
                crate::debug_log::tcp_outbound_label(outbound)
            }
            TcpSessionOutbound::Dns(_) => "dns",
        };
        crate::debug_log::log_route_decision(
            &runtime_logger,
            crate::debug_log::RouteDecisionLog {
                inbound_tag: inbound_tag.as_deref(),
                network: target.network,
                original_target: &raw_target,
                sniffed_protocol: None,
                route_target: &target,
                dial_target: &target,
                selected_outbound,
            },
        );
    }

    let outbound = match selected.outbound {
        TcpSessionOutbound::Transport(outbound) => outbound,
        TcpSessionOutbound::Dns(outbound) => {
            if let Some(source) = source.as_deref() {
                crate::debug_log::log_access_accepted(&runtime_logger, source, &target, "dns");
            }
            if inbound.write_all(HTTP_CONNECT_ESTABLISHED).await.is_err() {
                return;
            }
            connection.mark_active();
            let served = tokio::select! {
                result = dns_resolvers.outbound.serve_tcp_stream(
                    &mut inbound,
                    Bytes::new(),
                    &outbound,
                    &target,
                    policy.conn_idle,
                ) => Some(result),
                () = wait_for_connection_close(&mut connection_close) => None,
            };
            let _ = served;
            connection.finish();
            return;
        }
    };

    let (open_timeout, tunnel_idle, relay_buffer_size) = match outbound.primary() {
        TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => (
            policy.handshake,
            policy.conn_idle,
            policy.relay_buffer_size(),
        ),
        TcpOutbound::Vless(outbound) => {
            let outbound_policy = effective_policy_for_level(&config, Some(outbound.user().level));
            (
                outbound_policy.handshake,
                policy.conn_idle.min(outbound_policy.conn_idle),
                outbound_policy.relay_buffer_size(),
            )
        }
        TcpOutbound::Chained { .. } => unreachable!("primary outbound is never a chain wrapper"),
    };
    let outbound_label = crate::debug_log::tcp_outbound_label(&outbound);
    let opened = tokio::select! {
        result = tokio::time::timeout(
            open_timeout,
            open_tcp_stream_with_resolvers_and_dialer(
                &outbound,
                &target,
                dns_resolvers.destination.as_ref(),
                dns_resolvers.bootstrap.as_ref(),
                transport_dialer.as_ref(),
            ),
        ) => Some(result),
        () = wait_for_connection_close(&mut connection_close) => None,
    };
    let mut outbound_stream = match opened {
        None => return,
        Some(result) => match result {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                if let Some(source) = source.as_deref() {
                    crate::debug_log::log_access_rejected(&runtime_logger, source, &target, error);
                }
                let _ = inbound.write_all(HTTP_BAD_GATEWAY).await;
                return;
            }
            Err(_) => {
                if let Some(source) = source.as_deref() {
                    crate::debug_log::log_access_rejected(
                        &runtime_logger,
                        source,
                        &target,
                        "outbound open timed out",
                    );
                }
                let _ = inbound.write_all(HTTP_BAD_GATEWAY).await;
                return;
            }
        },
    };
    if let Some(source) = source.as_deref() {
        crate::debug_log::log_access_accepted(&runtime_logger, source, &target, outbound_label);
    }

    if inbound.write_all(HTTP_CONNECT_ESTABLISHED).await.is_err() {
        return;
    }
    connection.mark_active();

    let copied = tokio::select! {
        result = copy_bidirectional_with_idle_timeout_and_traffic(
            &mut inbound,
            &mut outbound_stream,
            tunnel_idle,
            relay_buffer_size,
            connection_traffic.as_ref(),
        ) => Some(result),
        () = wait_for_connection_close(&mut connection_close) => None,
    };
    let _ = copied;
    connection.finish();
}
