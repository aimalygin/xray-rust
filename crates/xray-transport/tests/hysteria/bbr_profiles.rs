//! Xray's BBR profiles over Hysteria against the pinned server: the
//! controller Xray's dialer installs after authentication runs, and data
//! crosses it both ways intact.
use super::support::{ReferenceServer, Task, DEADLINE};
use std::{net::Ipv4Addr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::hysteria::HysteriaClient;
use xray_transport::stream::{H3BbrProfile, H3Congestion};

const PAYLOAD: usize = 2 * 1024 * 1024;

fn pattern(index: usize) -> u8 {
    (index % 251) as u8
}

/// A target that takes `b'U'` and `PAYLOAD` bytes, answering `1` if they
/// were the pattern, or gives `PAYLOAD` pattern bytes for `b'D'`.
async fn endpoint() -> (Target, Task) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = Task(tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut direction = [0];
                socket.read_exact(&mut direction).await.unwrap();
                if direction[0] == b'U' {
                    let mut buffer = vec![0; PAYLOAD];
                    socket.read_exact(&mut buffer).await.unwrap();
                    let intact = buffer.iter().enumerate().all(|(i, b)| *b == pattern(i));
                    socket.write_all(&[u8::from(intact)]).await.unwrap();
                } else {
                    let data: Vec<u8> = (0..PAYLOAD).map(pattern).collect();
                    socket.write_all(&data).await.unwrap();
                }
                let _ = socket.shutdown().await;
            });
        }
    }));
    let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
    (target, task)
}

async fn round_trip(client: &HysteriaClient, target: &Target) {
    let mut upload = client.open_tcp(target).await.unwrap();
    upload.write_all(b"U").await.unwrap();
    let data: Vec<u8> = (0..PAYLOAD).map(pattern).collect();
    upload.write_all(&data).await.unwrap();
    let mut verdict = [0];
    timeout(DEADLINE * 2, upload.read_exact(&mut verdict))
        .await
        .expect("upload deadline")
        .unwrap();
    assert_eq!(verdict, [1], "the upload arrived intact");

    let mut download = client.open_tcp(target).await.unwrap();
    download.write_all(b"D").await.unwrap();
    let mut received = vec![0; PAYLOAD];
    timeout(DEADLINE * 2, download.read_exact(&mut received))
        .await
        .expect("download deadline")
        .unwrap();
    assert!(received.iter().enumerate().all(|(i, b)| *b == pattern(i)));
}

async fn check(
    server: &ReferenceServer,
    target: &Target,
    congestion: H3Congestion,
    expected: &str,
) {
    let mut config = server.config();
    config.quic.congestion = congestion;
    let client = HysteriaClient::connect(config, &server.connector)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    round_trip(&client, target).await;
    eprintln!(
        "{congestion:?}: 2 MiB up and down in {:?} with {expected}",
        started.elapsed()
    );
    assert_eq!(
        client.congestion_controller(),
        Some(expected),
        "{congestion:?}"
    );
    client.close();
}

#[tokio::test]
#[ignore = "requires pinned reference; use check-hysteria-interop.sh, check-native-hysteria-interop.sh or check-bbr-interop.sh"]
async fn pinned_reference_runs_each_bbr_profile_after_authentication() {
    let (target, _endpoint) = endpoint().await;
    // This server announces no receive rate, so `brutal` falls back to the
    // profile's BBR.
    let server = ReferenceServer::start().await;
    let brutal = |bbr_profile| H3Congestion::Brutal {
        up_bytes_per_second: 10 << 20,
        bbr_profile,
    };
    for (congestion, expected) in [
        (H3Congestion::BbrConservative, "xray-bbr-conservative"),
        (H3Congestion::BbrAggressive, "xray-bbr-aggressive"),
        (H3Congestion::BbrStandard, "quinn-bbr"),
        (brutal(H3BbrProfile::Conservative), "xray-bbr-conservative"),
        (brutal(H3BbrProfile::Aggressive), "xray-bbr-aggressive"),
        (brutal(H3BbrProfile::Standard), "quinn-bbr"),
    ] {
        check(&server, &target, congestion, expected).await;
    }
    drop(server);

    // A server that announces its rate: Brutal replaces quic-go's startup
    // Reno instead, whatever the profile.
    let server = ReferenceServer::start_with_bandwidth("100 mbps", "100 mbps").await;
    check(&server, &target, brutal(H3BbrProfile::Aggressive), "brutal").await;
    check(
        &server,
        &target,
        H3Congestion::ForceBrutal {
            bytes_per_second: 100 << 17,
        },
        "brutal",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(10)).await;
}
