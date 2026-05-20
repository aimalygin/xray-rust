use std::sync::Arc;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use xray_config::CoreConfig;
use xray_proxy::inbound::{
    negotiate_socks5_no_auth, parse_socks5_request, write_socks5_failure, write_socks5_success,
};

use crate::{open_vless_tcp_stream, select_vless_tcp_outbound};

pub async fn serve_socks_listener(
    listener: TcpListener,
    config: Arc<CoreConfig>,
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
                connections.spawn(async move {
                    handle_socks_connection(stream, config).await;
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

async fn handle_socks_connection(mut inbound: TcpStream, config: Arc<CoreConfig>) {
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

    let mut outbound_stream = match open_vless_tcp_stream(&outbound, &target).await {
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
