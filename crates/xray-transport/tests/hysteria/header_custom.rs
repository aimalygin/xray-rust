//! Hysteria with a `header-custom` UDP mask against Xray-core's server,
//! which applies the same `finalmask.udp` list.
use super::support::{ReferenceServer, Task, DEADLINE, SALAMANDER_PASSWORD};
use serde_json::{json, Value};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    header_custom::{CustomArg, CustomExpr, CustomItem, HeaderCustomUdpConfig},
    hysteria::{HeaderCustomCarrier, HysteriaClient},
};

fn item(packet: &[u8]) -> CustomItem {
    CustomItem {
        delay: (0, 0),
        rand: 0,
        rand_range: (0, 255),
        packet: packet.to_vec(),
        capture: String::new(),
        reuse: String::new(),
        transform: None,
    }
}

/// The mask in Xray's JSON and as the client's carrier takes it. A prefix
/// carries fixed and random bytes, since QUIC keeps many packets in flight;
/// the standalone exchange echoes a captured token.
fn header(standalone: bool) -> (Value, HeaderCustomUdpConfig) {
    if standalone {
        let json = json!({"type":"header-custom","settings":{"mode":"standalone",
            "client":[{"rand":8,"capture":"token"},{"type":"str","packet":"hello"}],
            "server":[{"reuse":"token"},{"transform":{"op":"be16","args":[{"u64":443}]}}]}});
        let config = HeaderCustomUdpConfig {
            standalone,
            client: vec![
                CustomItem {
                    rand: 8,
                    capture: "token".into(),
                    ..item(b"")
                },
                item(b"hello"),
            ],
            server: vec![
                CustomItem {
                    reuse: "token".into(),
                    ..item(b"")
                },
                CustomItem {
                    transform: Some(CustomExpr {
                        op: "be16".into(),
                        args: vec![CustomArg::U64(443)],
                    }),
                    ..item(b"")
                },
            ],
        };
        (json, config)
    } else {
        let json = json!({"type":"header-custom","settings":{
            "client":[{"rand":4},{"type":"str","packet":"hello"}],
            "server":[{"type":"str","packet":"world"}]}});
        let config = HeaderCustomUdpConfig {
            standalone,
            client: vec![
                CustomItem {
                    rand: 4,
                    ..item(b"")
                },
                item(b"hello"),
            ],
            server: vec![item(b"world")],
        };
        (json, config)
    }
}

async fn scenario(standalone: bool, salamander: Option<bool>) {
    let (mask, header) = header(standalone);
    let obfuscation = json!({"type":"salamander","settings":{"password":SALAMANDER_PASSWORD}});
    let masks = match salamander {
        None => json!([mask]),
        Some(true) => json!([mask, obfuscation]),
        Some(false) => json!([obfuscation, mask]),
    };
    let Some(server) = ReferenceServer::start_with_udp_masks(masks.clone()).await else {
        eprintln!("native Hysteria has no finalmask; skipped");
        return;
    };
    eprintln!("Hysteria header-custom {masks}");
    let config = |header: HeaderCustomUdpConfig| {
        let mut config = server.config();
        if salamander.is_some() {
            config.carrier.salamander_password = Some(Arc::new(zeroize::Zeroizing::new(
                SALAMANDER_PASSWORD.into(),
            )));
        }
        config.carrier.header_custom = Some(HeaderCustomCarrier {
            config: Arc::new(header),
            before_salamander: salamander == Some(true),
            before_noise: false,
        });
        config
    };
    // A client whose own sequence the server does not expect gets nowhere:
    // its prefixes are dropped, or its request is never answered.
    let mut wrong = header.clone();
    wrong.client[1] = item(b"HELLO");
    let refused = timeout(
        Duration::from_secs(3),
        HysteriaClient::connect(config(wrong), &server.connector),
    )
    .await;
    assert!(!matches!(refused, Ok(Ok(_))), "a wrong header connected");
    let client = HysteriaClient::connect(config(header), &server.connector)
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
    // Before and after a rebind, which keeps the mask's state.
    for phase in 0..2u8 {
        if phase == 1 {
            let old = client.local_addr().unwrap();
            assert!(client.rebind());
            timeout(Duration::from_secs(7), async {
                while client.local_addr().unwrap() == old {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
        let mut tcp = client.open_tcp(&target).await.unwrap();
        let payload = vec![0x41 + phase; 128 * 1024];
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
        let packet = vec![phase; 1200];
        timeout(DEADLINE, async {
            loop {
                udp.send(&udp_target, &packet).await.unwrap();
                if let Ok(reply) = timeout(Duration::from_millis(300), udp.recv()).await {
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

#[tokio::test]
#[ignore = "requires pinned Xray Hysteria; use check-header-custom-interop.sh"]
async fn header_custom_prefix_with_and_around_salamander() {
    for salamander in [None, Some(true), Some(false)] {
        timeout(Duration::from_secs(60), scenario(false, salamander))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires pinned Xray Hysteria; use check-header-custom-interop.sh"]
async fn header_custom_standalone_with_and_around_salamander() {
    for salamander in [None, Some(true), Some(false)] {
        timeout(Duration::from_secs(60), scenario(true, salamander))
            .await
            .unwrap();
    }
}
