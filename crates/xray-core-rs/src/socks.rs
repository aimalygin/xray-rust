use std::sync::Arc;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use xray_config::CoreConfig;
use xray_proxy::inbound::{
    negotiate_socks5_no_auth, parse_socks5_request, write_socks5_failure, write_socks5_success,
};
use xray_transport::{DnsResolver, TransportDialer};

use crate::{open_vless_tcp_stream_with_resolver_and_dialer, select_vless_tcp_outbound};

pub async fn serve_socks_listener(
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
                    handle_socks_connection(stream, config, dns_resolver, transport_dialer).await;
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

async fn handle_socks_connection(
    mut inbound: TcpStream,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
) {
    if negotiate_socks5_no_auth(&mut inbound).await.is_err() {
        return;
    }

    let target = match parse_socks5_request(&mut inbound).await {
        Ok(target) => target,
        Err(_) => {
            let _ = write_socks5_failure(&mut inbound).await;
            return;
        }
    };

    let outbound = match select_vless_tcp_outbound(&config) {
        Ok(outbound) => outbound,
        Err(_) => {
            let _ = write_socks5_failure(&mut inbound).await;
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
            let _ = write_socks5_failure(&mut inbound).await;
            return;
        }
    };

    if write_socks5_success(&mut inbound).await.is_err() {
        return;
    }

    let _ = copy_bidirectional(&mut inbound, &mut outbound_stream).await;
}
