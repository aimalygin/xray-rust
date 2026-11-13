use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use xray_config::{
    BurstObservatoryConfig, BurstPingConfig, CoreConfig, InboundConfig, InboundProtocol, Network,
    ObservatoryConfig, OutboundConfig, OutboundSettings, RoutingConfig, StreamSecurity,
    StreamSettings, StreamTransport,
};
use xray_core_rs::{Core, CoreState, OutboundHealthState};

fn freedom_outbound(tag: &str) -> OutboundConfig {
    OutboundConfig {
        mux: None,
        tag: Some(tag.to_owned()),
        proxy_settings: None,
        stream: StreamSettings {
            network: Network::Tcp,
            transport: StreamTransport::Raw,
            security: StreamSecurity::None,
            quic_params: None,
            tcp_fragment: None,
            tcp_header_custom: None,
            udp_header_custom: None,
            tcp_sudoku: None,
            tcp_xmc: None,
            udp_xdns: None,
            udp_realm: None,
            udp_xicmp: None,
            udp_salamander: None,
            udp_sudoku: None,
            udp_noise: None,
            socket_options: None,
        },
        settings: OutboundSettings::Freedom(Default::default()),
    }
}

fn observatory_config(probe_url: String) -> CoreConfig {
    CoreConfig {
        inbounds: vec![InboundConfig {
            tag: Some("socks-in".to_owned()),
            protocol: InboundProtocol::Socks(Default::default()),
            listen: "127.0.0.1".to_owned(),
            port: 0,
            allow_unauthenticated_lan: false,
            sniffing: None,
            user_level: None,
        }],
        outbounds: vec![freedom_outbound("proxy-a"), freedom_outbound("proxy-b")],
        default_outbound_tag: Some("proxy-a".to_owned()),
        routing: RoutingConfig::default(),
        observatory: Some(ObservatoryConfig {
            subject_selectors: vec!["proxy-".to_owned()],
            probe_url,
            probe_interval: Duration::from_secs(1),
            enable_concurrency: true,
        }),
        burst_observatory: None,
        dns: Default::default(),
        policy: Default::default(),
    }
}

#[tokio::test]
async fn observatory_probes_selected_outbounds_and_stops_with_core() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local probe server");
    let addr = listener.local_addr().expect("local probe address");
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("accept health probe");
            let mut request = [0u8; 1024];
            let _ = stream
                .read(&mut request)
                .await
                .expect("read health request");
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .expect("write health response");
        }
    });
    let mut core = Core::new(observatory_config(format!(
        "http://127.0.0.1:{}/generate_204",
        addr.port()
    )))
    .expect("build core with observatory");

    core.start().await.expect("start core");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = core.outbound_health_snapshot();
            if snapshot.outbounds.len() == 2
                && snapshot
                    .outbounds
                    .iter()
                    .all(|status| status.state == OutboundHealthState::Healthy)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("health probes should complete");

    core.stop().await.expect("stop core");
    assert_eq!(core.state(), CoreState::Stopped);
    server.await.expect("probe server should finish");
}

/// Xray-core's observatory marks an outbound alive as soon as
/// `http.Client.Do` returns, whatever the status (`app/observatory/
/// observer.go`), and sends its masqueraded Chrome navigation headers rather
/// than a client-identifying User-Agent.
#[tokio::test]
async fn observatory_counts_any_http_status_alive_and_sends_browser_headers() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local probe server");
    let addr = listener.local_addr().expect("local probe address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("accept health probe");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.expect("read health request");
                assert_ne!(read, 0, "probe closed before the end of its head");
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
                .await
                .expect("write health response");
            requests.push(String::from_utf8(request).expect("ASCII request head"));
        }
        requests
    });
    let mut core = Core::new(observatory_config(format!(
        "http://127.0.0.1:{}/generate_204",
        addr.port()
    )))
    .expect("build core with observatory");

    core.start().await.expect("start core");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = core.outbound_health_snapshot();
            if snapshot.outbounds.len() == 2
                && snapshot
                    .outbounds
                    .iter()
                    .all(|status| status.state == OutboundHealthState::Healthy)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a 503 response should still mark the outbounds healthy");

    core.stop().await.expect("stop core");
    let requests = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("probe server should finish")
        .expect("probe server task");
    for request in requests {
        assert!(
            request.starts_with("GET /generate_204 HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request.contains("\r\nUser-Agent: Mozilla/5.0 "),
            "{request}"
        );
        assert!(
            request.contains("\r\nSec-Fetch-Mode: navigate\r\n"),
            "{request}"
        );
        assert!(
            request.ends_with("\r\nAccept-Encoding: gzip\r\n\r\n"),
            "{request}"
        );
        assert!(!request.to_ascii_lowercase().contains("xray"), "{request}");
    }
}

#[test]
fn invalid_observatory_url_is_rejected_before_runtime_start() {
    let error = match Core::new(observatory_config("file:///private/config".to_owned())) {
        Ok(_) => panic!("unsafe probe URL should fail closed"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        xray_core_rs::CoreError::InvalidObservatoryProbeUrl
    ));
}

fn burst_observatory_config(ping: BurstPingConfig) -> CoreConfig {
    CoreConfig {
        observatory: None,
        burst_observatory: Some(BurstObservatoryConfig {
            subject_selectors: vec!["proxy-".to_owned()],
            ping,
        }),
        ..observatory_config(String::new())
    }
}

/// A local address nothing listens on: a connection to it is refused.
async fn refused_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a port to release");
    let port = listener.local_addr().expect("released address").port();
    drop(listener);
    format!("http://127.0.0.1:{port}/generate_204")
}

async fn wait_for_health(core: &Core, state: OutboundHealthState) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = core.outbound_health_snapshot();
            if snapshot.outbounds.len() == 2
                && snapshot
                    .outbounds
                    .iter()
                    .all(|status| status.state == state)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "outbounds should become {state:?}: {:?}",
            core.outbound_health_snapshot()
        )
    });
}

/// `app/observatory/burst/healthping.go`: every subject is pinged once when
/// the scheduler starts, with `pingConfig.httpMethod` (HEAD unless named) and
/// the navigation persona `ping.go` sets.
#[tokio::test]
async fn burst_observatory_pings_subjects_at_start_with_the_configured_method() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local ping server");
    let addr = listener.local_addr().expect("local ping address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("accept burst ping");
            let mut request = [0u8; 2048];
            let read = stream.read(&mut request).await.expect("read burst ping");
            requests.push(String::from_utf8_lossy(&request[..read]).into_owned());
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .expect("write burst response");
        }
        requests
    });
    let mut core = Core::new(burst_observatory_config(BurstPingConfig {
        destination: format!("http://127.0.0.1:{}/generate_204", addr.port()),
        ..BurstPingConfig::default()
    }))
    .expect("build core with burst observatory");

    core.start().await.expect("start core");
    wait_for_health(&core, OutboundHealthState::Healthy).await;
    core.stop().await.expect("stop core");

    for request in server.await.expect("ping server should finish") {
        assert!(
            request.starts_with("HEAD /generate_204 HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request.contains("Sec-Fetch-Mode: navigate\r\n"),
            "{request}"
        );
    }
}

/// `healthping.go` `doCheck`: a failed ping counts against the outbound when
/// the connectivity URL answers over the device's own network.
#[tokio::test]
async fn burst_observatory_counts_a_failed_ping_while_connectivity_answers() {
    let connectivity = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind connectivity server");
    let addr = connectivity.local_addr().expect("connectivity address");
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = connectivity.accept().await.expect("accept connectivity");
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).await;
            let _ = stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await;
        }
    });
    let mut core = Core::new(burst_observatory_config(BurstPingConfig {
        destination: refused_url().await,
        connectivity: Some(format!("http://127.0.0.1:{}/", addr.port())),
        ..BurstPingConfig::default()
    }))
    .expect("build core with burst observatory");

    core.start().await.expect("start core");
    wait_for_health(&core, OutboundHealthState::Unhealthy).await;
    core.stop().await.expect("stop core");
    server.abort();
}

/// `healthping.go` `doCheck`: when the connectivity URL fails too the network
/// is down and the ping is not a sample, so no outbound is marked dead.
#[tokio::test]
async fn burst_observatory_does_not_count_pings_while_connectivity_fails() {
    let connectivity = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind connectivity server");
    let addr = connectivity.local_addr().expect("connectivity address");
    let (checked, mut checks) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        loop {
            // Closing without an answer fails the check.
            let (stream, _) = connectivity.accept().await.expect("accept connectivity");
            drop(stream);
            let _ = checked.send(());
        }
    });
    let mut core = Core::new(burst_observatory_config(BurstPingConfig {
        destination: refused_url().await,
        connectivity: Some(format!("http://127.0.0.1:{}/", addr.port())),
        ..BurstPingConfig::default()
    }))
    .expect("build core with burst observatory");

    core.start().await.expect("start core");
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(3), checks.recv())
            .await
            .expect("each failed ping should check connectivity")
            .expect("connectivity server is running");
    }
    // Long enough for a failure to be recorded if it were counted.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let snapshot = core.outbound_health_snapshot();
    assert_eq!(snapshot.outbounds.len(), 2, "{snapshot:?}");
    assert!(
        snapshot
            .outbounds
            .iter()
            .all(|status| status.state == OutboundHealthState::Unknown
                && status.last_failure.is_none()),
        "{snapshot:?}"
    );

    core.stop().await.expect("stop core");
    server.abort();
}

/// xray-rust only: after the device changes network every subject is pinged
/// again within seconds instead of at its next random point of the period.
#[tokio::test]
async fn burst_observatory_pings_subjects_again_after_a_network_change() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local ping server");
    let addr = listener.local_addr().expect("local ping address");
    let (pinged, mut pings) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept burst ping");
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).await;
            let _ = stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await;
            let _ = pinged.send(());
        }
    });
    // Ten pings per outbound over a day leave the test's seconds to the
    // pings a start and a network change add.
    let mut core = Core::new(burst_observatory_config(BurstPingConfig {
        destination: format!("http://127.0.0.1:{}/generate_204", addr.port()),
        interval: Duration::from_secs(8_640),
        ..BurstPingConfig::default()
    }))
    .expect("build core with burst observatory");
    core.start().await.expect("start core");
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(3), pings.recv())
            .await
            .expect("every subject is pinged at start")
            .expect("ping server is running");
    }

    assert_eq!(
        core.rebind_quic(),
        0,
        "the observatory is not a connection asked to move"
    );

    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(5), pings.recv())
            .await
            .expect("every subject is pinged again on the new network")
            .expect("ping server is running");
    }
    core.stop().await.expect("stop core");
    server.abort();
}

#[test]
fn invalid_burst_observatory_urls_are_rejected_before_runtime_start() {
    for ping in [
        BurstPingConfig {
            destination: "file:///private/config".to_owned(),
            ..BurstPingConfig::default()
        },
        BurstPingConfig {
            connectivity: Some("ftp://example.com/".to_owned()),
            ..BurstPingConfig::default()
        },
    ] {
        let error = match Core::new(burst_observatory_config(ping)) {
            Ok(_) => panic!("invalid burst observatory URL must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            xray_core_rs::CoreError::InvalidObservatoryProbeUrl
        ));
    }
}
