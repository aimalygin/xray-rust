use super::*;

struct BoundedConnector(Mutex<Option<tokio::io::DuplexStream>>);
#[async_trait]
impl xray_transport::ResolvedTcpConnector for BoundedConnector {
    async fn connect_resolved(
        &self,
        _: &Target,
        _: &[SocketAddr],
        _: Option<&xray_transport::HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        Ok(Box::new(
            self.0.lock().unwrap().take().expect("one test connection"),
        ))
    }
}

async fn blocked_upload() -> (Core, TunTcpClient, tokio::io::DuplexStream) {
    let (stream, mut peer) = tokio::io::duplex(32);
    let dialer = TransportDialer::system()
        .unwrap()
        .with_resolved_tcp_connector(Arc::new(BoundedConnector(Mutex::new(Some(stream)))));
    let mut core = Core::with_transport_dialer_and_tun_options(
        runtime_tun_config_with_freedom_outbound(),
        Arc::new(dialer),
        TunRuntimeOptions {
            profile: TunRuntimeProfile::LowMemory,
            ..Default::default()
        },
    )
    .unwrap();
    core.start().await.unwrap();
    let mut client = TunTcpClient::new();
    client.connect("198.51.100.7:443".parse().unwrap());
    pump_tun_until(&mut client, core.tun(), TunTcpClient::may_send).await;
    client.send_payload(&vec![0x51; 8192]);
    let mut first = [0; 32];
    let read = peer.read_exact(&mut first);
    tokio::pin!(read);
    timeout(Duration::from_secs(1), async {
        loop {
            tokio::select! {
                result = &mut read => { result.unwrap(); break; },
                _ = sleep(Duration::from_millis(5)) => {
                    client.poll();
                    while let Some(packet) = client.device.pop_outbound() { core.tun().push_inbound(packet).await.unwrap(); }
                    while let Some(packet) = core.tun().try_poll_outbound().await.unwrap() { client.device.push_inbound(packet); }
                }
            }
        }
    }).await.unwrap();
    assert_eq!(first, [0x51; 32]);
    (core, client, peer)
}

#[tokio::test]
async fn stalled_tun_upload_allows_same_flow_download() {
    timeout(Duration::from_secs(4), async {
        let (mut core, mut client, mut peer) = blocked_upload().await;
        // The outbound upload is still blocked in its 32-byte buffer. A reply
        // in the opposite direction must not wait for that upload to drain.
        peer.write_all(b"reply while upload is stalled")
            .await
            .unwrap();
        let mut received = Vec::new();
        pump_tun_until_with_timeout(&mut client, core.tun(), Duration::from_secs(1), |client| {
            received.extend(client.recv_available());
            received.len() == b"reply while upload is stalled".len()
        })
        .await;
        assert_eq!(received, b"reply while upload is stalled");
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stalled_tun_upload_allows_host_close() {
    timeout(Duration::from_secs(4), async {
        let (mut core, _client, _peer) = blocked_upload().await;
        let connections = core.connection_snapshot().connections;
        assert_eq!(connections.len(), 1);
        core.close_connection(connections[0].id).unwrap();
        timeout(Duration::from_secs(1), async {
            while !core.connection_snapshot().connections.is_empty() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("host closure must cancel a blocked upload");
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}
