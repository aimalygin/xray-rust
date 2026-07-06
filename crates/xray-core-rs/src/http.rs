use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use xray_config::CoreConfig;
use xray_proxy::inbound::parse_http_connect;
use xray_transport::{DnsResolver, TransportDialer};

use crate::policy::{
    copy_bidirectional_with_idle_timeout, effective_policy_for_level, EffectivePolicy,
};
use crate::{
    open_tcp_stream_with_resolver_and_dialer, select_tcp_outbound_for_session_with_resolver,
    RuntimeLogger, TcpOutbound,
};

const HTTP_CONNECT_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const HTTP_BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
const HTTP_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

pub async fn serve_http_listener(
    listener: TcpListener,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    policy: EffectivePolicy,
    runtime_logger: RuntimeLogger,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();

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
                    Err(_) => continue,
                };
                let inbound_tag = inbound_tag.clone();
                let config = Arc::clone(&config);
                let dns_resolver = Arc::clone(&dns_resolver);
                let transport_dialer = Arc::clone(&transport_dialer);
                let runtime_logger = runtime_logger.clone();
                connections.spawn(async move {
                    handle_http_connection(
                        stream,
                        inbound_tag,
                        config,
                        dns_resolver,
                        transport_dialer,
                        policy,
                        runtime_logger,
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

async fn handle_http_connection(
    mut inbound: TcpStream,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    policy: EffectivePolicy,
    runtime_logger: RuntimeLogger,
) {
    let source = runtime_logger.is_enabled().then(|| {
        inbound
            .peer_addr()
            .map_or_else(|_| "unknown".to_owned(), |addr| addr.to_string())
    });
    let target =
        match tokio::time::timeout(policy.handshake, parse_http_connect(&mut inbound)).await {
            Ok(Ok(target)) => target,
            _ => {
                let _ = inbound.write_all(HTTP_BAD_REQUEST).await;
                return;
            }
        };

    let outbound = match select_tcp_outbound_for_session_with_resolver(
        &config,
        inbound_tag.as_deref(),
        &target,
        dns_resolver.as_ref(),
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

    if runtime_logger.is_enabled() {
        crate::debug_log::log_route_decision(
            &runtime_logger,
            crate::debug_log::RouteDecisionLog {
                inbound_tag: inbound_tag.as_deref(),
                network: target.network,
                original_target: &target,
                sniffed_protocol: None,
                route_target: &target,
                dial_target: &target,
                selected_outbound: crate::debug_log::tcp_outbound_label(&outbound),
            },
        );
    }

    let (open_timeout, tunnel_idle) = match &outbound {
        TcpOutbound::Freedom => (policy.handshake, policy.conn_idle),
        TcpOutbound::Vless(outbound) => {
            let outbound_policy = effective_policy_for_level(&config, Some(outbound.user().level));
            (
                outbound_policy.handshake,
                policy.conn_idle.min(outbound_policy.conn_idle),
            )
        }
    };
    let outbound_label = crate::debug_log::tcp_outbound_label(&outbound);
    let mut outbound_stream = match tokio::time::timeout(
        open_timeout,
        open_tcp_stream_with_resolver_and_dialer(
            &outbound,
            &target,
            dns_resolver.as_ref(),
            transport_dialer.as_ref(),
        ),
    )
    .await
    {
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
    };
    if let Some(source) = source.as_deref() {
        crate::debug_log::log_access_accepted(&runtime_logger, source, &target, outbound_label);
    }

    if inbound.write_all(HTTP_CONNECT_ESTABLISHED).await.is_err() {
        return;
    }

    let _ =
        copy_bidirectional_with_idle_timeout(&mut inbound, &mut outbound_stream, tunnel_idle).await;
}
