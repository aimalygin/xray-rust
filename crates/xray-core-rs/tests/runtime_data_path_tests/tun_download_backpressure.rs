use super::*;

fn connect_one(client: &mut TunTcpMultiClient, index: usize, target: SocketAddr) {
    let SocketAddr::V4(target) = target else {
        panic!("IPv4 fixture")
    };
    client
        .sockets
        .get_mut::<smol_tcp::Socket>(client.tcp[index])
        .connect(
            client.iface.context(),
            (*target.ip(), target.port()),
            49152 + index as u16,
        )
        .unwrap();
}

#[tokio::test]
async fn stalled_tun_download_allows_tcp_udp_upload_and_host_cancellation() {
    timeout(Duration::from_secs(10), async {
        let slow_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let slow_addr = slow_listener.local_addr().unwrap();
        let (upload_tx, mut upload_rx) = tokio::sync::oneshot::channel();
        let slow_server = tokio::spawn(async move {
            let (stream, _) = slow_listener.accept().await.unwrap();
            let (mut read, mut write) = stream.into_split();
            let upload = async {
                let mut bytes = [0; 4];
                read.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"ping");
                upload_tx.send(()).unwrap();
            };
            let download = async {
                let _ = write.write_all(&vec![0xa5; 8 * 1024 * 1024]).await;
            };
            tokio::join!(upload, download);
        });
        let fast_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let fast_addr = fast_listener.local_addr().unwrap();
        let expected = (0..65536).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let response = expected.clone();
        let fast_server = tokio::spawn(async move {
            let (mut stream, _) = fast_listener.accept().await.unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"fast");
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut core = Core::with_tun_runtime_options(
            runtime_tun_config_with_freedom_outbound(),
            TunRuntimeOptions {
                profile: TunRuntimeProfile::LowMemory,
                ..Default::default()
            },
        )
        .unwrap();
        core.start().await.unwrap();
        let mut client = TunTcpMultiClient::new(2);
        connect_one(&mut client, 0, slow_addr);
        // Keep ACKing the connection but never read its receive buffer.
        let deadline = TokioInstant::now() + Duration::from_secs(3);
        loop {
            pump_multi_tun_once(&mut client, core.tun()).await;
            if core.tun().stats().await.tcp_pending_remote_bytes > 0 {
                break;
            }
            assert!(
                TokioInstant::now() < deadline,
                "slow reader did not retain a pending TUN download"
            );
        }

        let stalled = core.tun().stats().await;
        assert!(
            stalled.tcp_pending_remote_bytes <= 256 * 1024,
            "one unread flow must not fill a multi-megabyte TUN queue"
        );
        assert!(
            stalled.tcp_remote_read_bytes <= 512 * 1024,
            "backpressure must reach the remote reader after bounded local prefetch"
        );

        // The same connection's upload remains usable while its download waits.
        client.send_payload(0, b"ping");
        let deadline = TokioInstant::now() + Duration::from_secs(1);
        loop {
            pump_multi_tun_once(&mut client, core.tun()).await;
            if upload_rx.try_recv().is_ok() {
                break;
            }
            assert!(
                TokioInstant::now() < deadline,
                "download backpressure blocked upload"
            );
        }

        let (udp_addr, udp_server) = spawn_udp_echo_server().await;
        let udp_payload = b"UDP beside a stalled TCP reader";
        core.tun()
            .push_inbound(Bytes::from(ipv4_udp_packet(
                Ipv4Addr::new(10, 10, 0, 2),
                60000,
                Ipv4Addr::LOCALHOST,
                udp_addr.port(),
                udp_payload,
            )))
            .await
            .unwrap();
        let deadline = TokioInstant::now() + Duration::from_secs(1);
        let mut received_udp = false;
        while !received_udp {
            while let Some(packet) = core.tun().try_poll_outbound().await.unwrap() {
                if ipv4_udp_payload(&packet) == Some(udp_payload.as_slice()) {
                    received_udp = true;
                } else {
                    client.device.push_inbound(packet);
                }
            }
            client.poll();
            while let Some(packet) = client.device.pop_outbound() {
                core.tun().push_inbound(packet).await.unwrap();
            }
            assert!(
                TokioInstant::now() < deadline,
                "TCP backpressure blocked UDP delivery"
            );
            tokio::task::yield_now().await;
        }
        udp_server.await.unwrap();
        let udp = core
            .connection_snapshot()
            .connections
            .into_iter()
            .find(|connection| {
                connection.target.port == udp_addr.port()
                    && connection.target.network == RoutingNetwork::Udp
            })
            .unwrap();
        core.close_connection(udp.id).unwrap();

        connect_one(&mut client, 1, fast_addr);
        pump_multi_tun_until(&mut client, core.tun(), TunTcpMultiClient::all_may_send).await;
        client.send_payload(1, b"fast");
        let mut received = Vec::new();
        pump_multi_tun_until(&mut client, core.tun(), |client| {
            received.extend(client.recv_available(1));
            received.len() == expected.len()
                && !client
                    .sockets
                    .get::<smol_tcp::Socket>(client.tcp[1])
                    .may_recv()
        })
        .await;
        assert_eq!(
            received, expected,
            "the new flow must deliver every byte before EOF"
        );
        client
            .sockets
            .get_mut::<smol_tcp::Socket>(client.tcp[1])
            .close();

        let slow = core
            .connection_snapshot()
            .connections
            .into_iter()
            .find(|connection| connection.target.port == slow_addr.port())
            .unwrap();
        core.close_connection(slow.id).unwrap();
        pump_multi_tun_until(&mut client, core.tun(), |client| {
            !client
                .sockets
                .get::<smol_tcp::Socket>(client.tcp[0])
                .is_open()
        })
        .await;
        wait_for_empty_connection_snapshot(&core).await;
        core.stop().await.unwrap();
        slow_server.await.unwrap();
        fast_server.await.unwrap();
    })
    .await
    .unwrap();
}
