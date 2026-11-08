//! Hysteria with a `sudoku` UDP mask against Xray-core's server, which
//! applies the same `finalmask.udp` list. Every QUIC packet goes out at
//! least four times its size; on a link with a smaller MTU the system
//! fragments it, which the carrier allows.
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
    hysteria::{HysteriaClient, SudokuCarrier},
    sudoku::SudokuConfig,
};

const PASSWORD: &str = "synthetic-sudoku";

fn carrier(password: &str, before_salamander: bool) -> SudokuCarrier {
    SudokuCarrier {
        config: Arc::new(SudokuConfig {
            password: password.into(),
            padding_min: 5,
            padding_max: 25,
            ..Default::default()
        }),
        before_salamander,
        before_noise: false,
        before_header_custom: false,
    }
}

/// `salamander` is where Salamander goes: none, after sudoku (`Some(true)`)
/// or before it.
async fn scenario(salamander: Option<bool>) {
    let mask =
        json!({"type":"sudoku","settings":{"password":PASSWORD,"paddingMin":5,"paddingMax":25}});
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
    eprintln!("Hysteria sudoku {masks}");
    let config = |sudoku: SudokuCarrier| {
        let mut config = server.config();
        if salamander.is_some() {
            config.carrier.salamander_password = Some(Arc::new(zeroize::Zeroizing::new(
                SALAMANDER_PASSWORD.into(),
            )));
        }
        config.carrier.sudoku = Some(sudoku);
        config
    };
    // A client with other tables gets nowhere: the server drops what does
    // not decode.
    let refused = timeout(
        Duration::from_secs(3),
        HysteriaClient::connect(
            config(carrier("another-password", salamander == Some(true))),
            &server.connector,
        ),
    )
    .await;
    assert!(!matches!(refused, Ok(Ok(_))), "another password connected");
    let client = HysteriaClient::connect(
        config(carrier(PASSWORD, salamander == Some(true))),
        &server.connector,
    )
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
    // Before and after a rebind, whose new socket must allow fragments too.
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
        let packet = vec![phase; 1000];
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

/// Alone, and outside Salamander. Inside it, Xray-core's server drops every
/// reply: Salamander sits in its header group, which takes at most 4096
/// bytes, and sudoku's datagrams are longer.
#[tokio::test]
#[ignore = "requires pinned Xray Hysteria; use check-sudoku-interop.sh"]
async fn sudoku_alone_and_outside_salamander() {
    for salamander in [None, Some(false)] {
        timeout(Duration::from_secs(60), scenario(salamander))
            .await
            .unwrap();
    }
}
