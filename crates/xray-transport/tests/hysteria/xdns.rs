//! Hysteria through the `xdns` mask against Xray-core's server, which
//! answers as the domain's DNS server: every QUIC packet goes out in the
//! names of several queries and comes back in TXT, A, AAAA or CNAME
//! answers.
use super::support::{ReferenceServer, Task, DEADLINE, SALAMANDER_PASSWORD};
use serde_json::json;
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    hysteria::HysteriaClient,
    xdns::{XdnsConfig, XdnsDomain, XdnsResolver},
};

fn xdns(name: &str, resolver: std::net::SocketAddr) -> Arc<XdnsConfig> {
    Arc::new(XdnsConfig {
        domains: vec![XdnsDomain {
            name: name.into(),
            len_limit: 255,
            label_limit: 63,
            types: vec![1, 5, 16, 28],
            edns0: 4096,
        }],
        resolvers: vec![XdnsResolver::Udp(vec![resolver])],
        extra_poll: 1,
    })
}

async fn scenario(salamander: bool) {
    let server_xdns =
        json!({"type":"xdns","settings":{"domains":[{"names":["t.example.com"],"edns0":4096}]}});
    let obfuscation = json!({"type":"salamander","settings":{"password":SALAMANDER_PASSWORD}});
    let masks = if salamander {
        json!([obfuscation, server_xdns])
    } else {
        json!([server_xdns])
    };
    let Some(server) = ReferenceServer::start_with_udp_masks(masks.clone()).await else {
        eprintln!("native Hysteria has no finalmask; skipped");
        return;
    };
    eprintln!("Hysteria xdns {masks}");
    let config = |name: &str| {
        let mut config = server.config();
        if salamander {
            config.carrier.salamander_password = Some(Arc::new(zeroize::Zeroizing::new(
                SALAMANDER_PASSWORD.into(),
            )));
        }
        config.carrier.xdns = Some(xdns(name, config.remote_addr));
        config
    };
    // The server answers for its domain only.
    let refused = timeout(
        Duration::from_secs(3),
        HysteriaClient::connect(config("u.example.com"), &server.connector),
    )
    .await;
    assert!(!matches!(refused, Ok(Ok(_))), "another domain connected");
    let client = HysteriaClient::connect(config("t.example.com"), &server.connector)
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
    // A rebind keeps the xdns client, whose id the server knows.
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

/// Alone, and with Salamander inside it.
#[tokio::test]
#[ignore = "requires pinned Xray Hysteria; use check-xdns-interop.sh"]
async fn xdns_alone_and_around_salamander() {
    for salamander in [false, true] {
        timeout(Duration::from_secs(90), scenario(salamander))
            .await
            .unwrap();
    }
}
