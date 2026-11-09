//! Hysteria through the `xicmp` mask against Xray-core's server, which
//! reads echo requests on raw ICMP sockets and so needs root or
//! `CAP_NET_RAW`: `scripts/check-xicmp-interop.sh` runs this on Linux, as
//! root, with `XRAY_XICMP_LIVE=1`. Without it the test skips, so the
//! binary's other `--ignored` runs, unprivileged, pass it by.
//! Every QUIC packet goes out in an echo request and comes back in a reply.
use super::support::{ReferenceServer, Task, DEADLINE, SALAMANDER_PASSWORD};
use serde_json::json;
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{hysteria::HysteriaClient, xicmp::XicmpConfig};

async fn scenario(salamander: bool) {
    let server_xicmp = json!({"type":"xicmp","settings":{}});
    let obfuscation = json!({"type":"salamander","settings":{"password":SALAMANDER_PASSWORD}});
    let masks = if salamander {
        json!([obfuscation, server_xicmp])
    } else {
        json!([server_xicmp])
    };
    let Some(server) = ReferenceServer::start_with_udp_masks(masks.clone()).await else {
        eprintln!("native Hysteria has no finalmask; skipped");
        return;
    };
    eprintln!("Hysteria xicmp {masks}");
    let mut config = server.config();
    if salamander {
        config.carrier.salamander_password = Some(Arc::new(zeroize::Zeroizing::new(
            SALAMANDER_PASSWORD.into(),
        )));
    }
    config.carrier.xicmp = Some(Arc::new(XicmpConfig {
        dgram: true,
        ips: vec![],
    }));
    let client = HysteriaClient::connect(config, &server.connector)
        .await
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let _echo = Task(tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    }));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let udp_address = socket.local_addr().unwrap();
    let _udp_echo = Task(tokio::spawn(async move {
        let mut bytes = [0; 8192];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            socket.send_to(&bytes[..n], peer).await.unwrap();
        }
    }));
    let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
    let udp_target = Target::new(
        TargetAddr::Ip(udp_address.ip()),
        udp_address.port(),
        Network::Udp,
    );
    let udp = client.open_udp().unwrap();
    // A rebind keeps the xicmp client, whose id the server knows.
    for phase in 0..2u8 {
        if phase == 1 {
            assert!(client.rebind());
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let mut tcp = client.open_tcp(&target).await.unwrap();
        let payload = vec![0x41 + phase; 64 * 1024];
        let mut reply = vec![0; payload.len()];
        timeout(DEADLINE, async {
            let (mut r, mut w) = tokio::io::split(&mut tcp);
            let (write, read) = tokio::join!(w.write_all(&payload), r.read_exact(&mut reply));
            write.unwrap();
            read.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(reply, payload);
        let packet = vec![phase; 1000];
        timeout(DEADLINE, async {
            loop {
                udp.send(&udp_target, &packet).await.unwrap();
                if let Ok(reply) = timeout(Duration::from_millis(500), udp.recv()).await {
                    assert_eq!(reply.unwrap().payload, packet);
                    break;
                }
            }
        })
        .await
        .unwrap();
    }
    client.close();
}

/// Whether this run may start Xray-core's xicmp server: only
/// `check-xicmp-interop.sh` says so.
fn live() -> bool {
    let live = std::env::var_os("XRAY_XICMP_LIVE").is_some_and(|value| value == "1");
    if !live {
        eprintln!(
            "xicmp: needs root and XRAY_XICMP_LIVE=1, as check-xicmp-interop.sh runs it; skipped"
        );
    }
    live
}

/// Alone, and with Salamander inside it.
#[tokio::test]
#[ignore = "requires pinned Xray Hysteria with raw ICMP sockets; use check-xicmp-interop.sh"]
async fn xicmp_alone_and_around_salamander() {
    if !live() {
        return;
    }
    for salamander in [false, true] {
        timeout(Duration::from_secs(90), scenario(salamander))
            .await
            .unwrap();
    }
}
