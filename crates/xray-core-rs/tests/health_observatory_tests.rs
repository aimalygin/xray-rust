use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use xray_config::{
    CoreConfig, InboundConfig, InboundProtocol, Network, ObservatoryConfig, OutboundConfig,
    OutboundSettings, RoutingConfig, StreamSecurity, StreamSettings, StreamTransport,
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
