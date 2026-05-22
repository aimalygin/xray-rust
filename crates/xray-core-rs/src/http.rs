use std::sync::Arc;

use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use xray_config::CoreConfig;
use xray_proxy::inbound::parse_http_connect;
use xray_transport::{DnsResolver, TransportDialer};

use crate::{open_vless_tcp_stream_with_resolver_and_dialer, select_vless_tcp_outbound};

const HTTP_CONNECT_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const HTTP_BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
const HTTP_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

pub async fn serve_http_listener(
    listener: TcpListener,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
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
                let config = Arc::clone(&config);
                let dns_resolver = Arc::clone(&dns_resolver);
                let transport_dialer = Arc::clone(&transport_dialer);
                connections.spawn(async move {
                    handle_http_connection(stream, config, dns_resolver, transport_dialer).await;
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
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
) {
    let target = match parse_http_connect(&mut inbound).await {
        Ok(target) => target,
        Err(_) => {
            let _ = inbound.write_all(HTTP_BAD_REQUEST).await;
            return;
        }
    };

    let outbound = match select_vless_tcp_outbound(&config) {
        Ok(outbound) => outbound,
        Err(_) => {
            let _ = inbound.write_all(HTTP_BAD_GATEWAY).await;
            return;
        }
    };

    let mut outbound_stream = match open_vless_tcp_stream_with_resolver_and_dialer(
        &outbound,
        &target,
        dns_resolver.as_ref(),
        transport_dialer.as_ref(),
    )
    .await
    {
        Ok(stream) => stream,
        Err(_) => {
            let _ = inbound.write_all(HTTP_BAD_GATEWAY).await;
            return;
        }
    };

    if inbound.write_all(HTTP_CONNECT_ESTABLISHED).await.is_err() {
        return;
    }

    let _ = copy_bidirectional(&mut inbound, &mut outbound_stream).await;
}
