use super::*;
use xray_core_rs::{TunAdmissionPolicy, TunFlow};

fn policy(callback: impl Fn(TunFlow) -> bool + Send + Sync + 'static) -> TunAdmissionPolicy {
    TunAdmissionPolicy::new(Arc::new(callback), Duration::from_millis(500), false).unwrap()
}

#[tokio::test]
async fn denied_tcp_resets_without_opening_an_outbound_and_reports_original_tuple() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = Arc::clone(&seen);
    let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
    core.set_tun_admission(Some(policy(move |flow| {
        capture.lock().unwrap().push(flow);
        false
    })))
    .unwrap();
    core.start().await.unwrap();
    let mut client = TunTcpClient::new();
    client.connect(target);
    pump_tun_until(&mut client, core.tun(), |client| !client.is_open()).await;
    let flows = seen.lock().unwrap().clone();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].protocol, 6);
    assert_eq!(flows[0].source, "10.10.0.2:49152".parse().unwrap());
    assert_eq!(flows[0].destination, target);
    assert!(timeout(Duration::from_millis(50), listener.accept())
        .await
        .is_err());
    assert!(core.connection_snapshot().connections.is_empty());
    core.stop().await.unwrap();
}

#[tokio::test]
async fn allowed_tcp_calls_host_once_and_preserves_echo() {
    let (target, server) = spawn_echo_server().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
    core.set_tun_admission(Some(policy(move |_| {
        count.fetch_add(1, Ordering::Relaxed);
        true
    })))
    .unwrap();
    core.start().await.unwrap();
    let mut client = TunTcpClient::new();
    client.connect(target);
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;
    for _ in 0..3 {
        client.send_payload(b"admitted");
        let mut data = Vec::new();
        pump_tun_until(&mut client, core.tun(), |client| {
            data.extend(client.recv_available());
            data.len() >= 8
        })
        .await;
        assert_eq!(data, b"admitted");
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    core.stop().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn udp_denial_is_cached_and_does_not_block_other_flows() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = server.local_addr().unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let count = Arc::clone(&calls);
    let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
    core.set_tun_admission(Some(policy(move |flow| {
        count.lock().unwrap().push(flow);
        flow.source.port() == 40001
    })))
    .unwrap();
    core.start().await.unwrap();
    let client = Ipv4Addr::new(10, 10, 0, 2);
    for port in [40000, 40000, 40001, 40000] {
        core.tun()
            .push_inbound(Bytes::from(ipv4_udp_packet(
                client,
                port,
                Ipv4Addr::LOCALHOST,
                target.port(),
                b"admitted-udp",
            )))
            .await
            .unwrap();
    }
    let mut data = [0; 32];
    let (size, peer) = timeout(Duration::from_secs(1), server.recv_from(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&data[..size], b"admitted-udp");
    server.send_to(&data[..size], peer).await.unwrap();
    poll_tun_outbound_until(core.tun(), |packet| {
        ipv4_udp_payload(packet) == Some(b"admitted-udp")
    })
    .await;
    assert!(
        timeout(Duration::from_millis(50), server.recv_from(&mut data))
            .await
            .is_err()
    );
    let flows = calls.lock().unwrap().clone();
    assert_eq!(flows.len(), 2);
    assert!(flows
        .iter()
        .all(|flow| flow.protocol == 17 && flow.destination == target));
    core.stop().await.unwrap();
}

#[tokio::test]
async fn denied_dns_cannot_get_local_fake_dns_answer_or_query_upstream() {
    let dns = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    for fake_dns in [false, true] {
        let config = if fake_dns {
            runtime_tun_config_with_mobile_fake_dns_freedom(dns.local_addr().unwrap())
        } else {
            runtime_tun_config_with_dns_proxy_servers(vec![dns.local_addr().unwrap()])
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let capture = Arc::clone(&calls);
        let mut core = Core::new(config).unwrap();
        core.set_tun_admission(Some(policy(move |flow| {
            capture.lock().unwrap().push(flow);
            false
        })))
        .unwrap();
        core.start().await.unwrap();
        let query = build_dns_a_query(12, "admission.example");
        let dns_anchor = Ipv4Addr::new(198, 18, 0, 1);
        core.tun()
            .push_inbound(Bytes::from(ipv4_udp_packet(
                Ipv4Addr::new(10, 10, 0, 2),
                42000,
                dns_anchor,
                53,
                &query,
            )))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), core.tun().poll_outbound())
                .await
                .is_err()
        );
        let mut data = [0; 512];
        assert!(timeout(Duration::from_millis(25), dns.recv_from(&mut data))
            .await
            .is_err());
        let seen = calls.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].destination, SocketAddr::new(dns_anchor.into(), 53));
        core.stop().await.unwrap();
    }
}

#[tokio::test]
async fn fake_dns_is_allowed_but_mapped_tcp_and_udp_are_checked_as_raw_ip() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = Arc::clone(&seen);
    let mut core = Core::new(runtime_tun_config_with_mobile_fake_dns_freedom(
        "127.0.0.1:9".parse().unwrap(),
    ))
    .unwrap();
    core.set_tun_admission(Some(policy(move |flow| {
        capture.lock().unwrap().push(flow);
        flow.destination.port() == 53
    })))
    .unwrap();
    core.start().await.unwrap();
    let fake_ip = request_tun_fake_ip(&core, 43000, "admission.example").await;
    let mut client = TunTcpClient::new();
    client.connect(SocketAddr::new(fake_ip.into(), port));
    pump_tun_until(&mut client, core.tun(), |client| !client.is_open()).await;
    core.tun()
        .push_inbound(Bytes::from(ipv4_udp_packet(
            Ipv4Addr::new(10, 10, 0, 2),
            44000,
            fake_ip,
            port,
            b"denied",
        )))
        .await
        .unwrap();
    timeout(Duration::from_secs(1), async {
        while seen.lock().unwrap().len() < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let flows = seen.lock().unwrap().clone();
    assert!(flows[1..]
        .iter()
        .all(|flow| flow.destination.ip() == IpAddr::V4(fake_ip)));
    assert_eq!(flows[1].protocol, 6);
    assert_eq!(flows[2].protocol, 17);
    assert!(timeout(Duration::from_millis(50), listener.accept())
        .await
        .is_err());
    assert!(core.connection_snapshot().connections.is_empty());
    core.stop().await.unwrap();
}

#[tokio::test]
async fn denied_dns_tcp_is_reset_before_local_fake_dns_answer() {
    let mut core = Core::new(runtime_tun_config_with_mobile_fake_dns_freedom(
        "127.0.0.1:9".parse().unwrap(),
    ))
    .unwrap();
    let seen = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&seen);
    core.set_tun_admission(Some(policy(move |flow| {
        *capture.lock().unwrap() = Some(flow);
        false
    })))
    .unwrap();
    core.start().await.unwrap();
    let mut client = TunTcpClient::new();
    client.connect("198.18.0.1:53".parse().unwrap());
    pump_tun_until(&mut client, core.tun(), |client| !client.is_open()).await;
    assert_eq!(
        seen.lock().unwrap().unwrap().destination,
        "198.18.0.1:53".parse().unwrap()
    );
    assert!(client.recv_available().is_empty());
    assert!(core.connection_snapshot().connections.is_empty());
    core.stop().await.unwrap();
}

#[tokio::test]
async fn ipv6_udp_admission_preserves_original_tuple() {
    let server = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
    let target = server.local_addr().unwrap();
    let source: Ipv6Addr = "fd00:7872::2".parse().unwrap();
    for allowed in [false, true] {
        let seen = Arc::new(Mutex::new(None));
        let capture = Arc::clone(&seen);
        let mut core = Core::new(runtime_tun_config_with_freedom_outbound()).unwrap();
        core.set_tun_admission(Some(policy(move |flow| {
            *capture.lock().unwrap() = Some(flow);
            allowed
        })))
        .unwrap();
        core.start().await.unwrap();
        let mut packet = vec![0u8; 52];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&12u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[40..42].copy_from_slice(&45000u16.to_be_bytes());
        packet[42..44].copy_from_slice(&target.port().to_be_bytes());
        packet[44..46].copy_from_slice(&12u16.to_be_bytes());
        packet[48..].copy_from_slice(b"ipv6");
        let checksum = ipv6_transport_checksum(source, Ipv6Addr::LOCALHOST, 17, &packet[40..]);
        packet[46..48].copy_from_slice(&checksum.to_be_bytes());
        core.tun().push_inbound(Bytes::from(packet)).await.unwrap();
        let mut data = [0; 32];
        let received = timeout(Duration::from_millis(150), server.recv_from(&mut data)).await;
        assert_eq!(received.is_ok(), allowed);
        let flow = seen.lock().unwrap().unwrap();
        assert_eq!(flow.source, SocketAddr::new(source.into(), 45000));
        assert_eq!(flow.destination, target);
        assert_eq!(flow.protocol, 17);
        core.stop().await.unwrap();
    }
}
