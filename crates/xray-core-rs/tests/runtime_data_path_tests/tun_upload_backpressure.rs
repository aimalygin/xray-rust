use super::*;
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};

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
async fn freeing_upload_capacity_resumes_buffered_tcp_without_new_packets() {
    timeout(Duration::from_secs(10), async {
        let (mut core, mut client, mut peer) = blocked_upload().await;
        client
            .sockets
            .get_mut::<smol_tcp::Socket>(client.tcp)
            .set_congestion_control(smol_tcp::CongestionControl::None);
        let payload = [0x51; 8192];
        // Saturate the bridge while its bounded writer is stalled. Leave
        // additional bytes inside the TCP receive window, then stop input.
        while core
            .tun()
            .stats()
            .await
            .tcp_stack_to_remote_backpressure_events
            == 0
        {
            client
                .sockets
                .get_mut::<smol_tcp::Socket>(client.tcp)
                .send_slice(&payload)
                .unwrap();
            pump_tun_once(&mut client, core.tun()).await;
        }
        sleep(Duration::from_millis(30)).await;
        let before = core.tun().stats().await.tcp_stack_to_remote_bytes;
        let drain = tokio::spawn(async move {
            let mut bytes = [0; 8192];
            while peer.read(&mut bytes).await.unwrap_or(0) != 0 {}
        });
        // No pump/client poll here: a TCP retransmission or zero-window probe
        // must not be required to wake the stack after the writer frees space.
        let resumed = timeout(Duration::from_millis(500), async {
            while core.tun().stats().await.tcp_stack_to_remote_bytes == before {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        core.stop().await.unwrap();
        drain.abort();
        assert!(
            resumed.is_ok(),
            "freed upload capacity did not wake the TCP stack"
        );
    })
    .await
    .unwrap();
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

#[tokio::test]
async fn client_fin_drains_upload_and_preserves_reply_until_remote_eof() {
    timeout(Duration::from_secs(5), async {
        let (mut core, mut client, mut peer) = blocked_upload().await;
        // FIN follows an upload already stalled in a 32-byte transport. The
        // server only replies after receiving EOF, as with half-closed requests.
        client
            .sockets
            .get_mut::<smol_tcp::Socket>(client.tcp)
            .close();
        let server = tokio::spawn(async move {
            let mut tail = Vec::new();
            peer.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, vec![0x51; 8192 - 32]);
            peer.write_all(b"response after client FIN").await.unwrap();
            peer.shutdown().await.unwrap();
        });
        let mut received = Vec::new();
        pump_tun_until_with_timeout(&mut client, core.tun(), Duration::from_secs(2), |client| {
            received.extend(client.recv_available());
            received.len() == b"response after client FIN".len()
                && !client
                    .sockets
                    .get::<smol_tcp::Socket>(client.tcp)
                    .may_recv()
        })
        .await;
        assert_eq!(received, b"response after client FIN");
        server.await.unwrap();
        timeout(Duration::from_secs(1), async {
            while !core.connection_snapshot().connections.is_empty() {
                pump_tun_once(&mut client, core.tun()).await;
            }
        })
        .await
        .expect("natural close must remove the connection without host cancellation");
        assert_eq!(core.tun().stats().await.tcp_pending_upload_bytes, 0);
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn client_fin_bounds_an_idle_download_without_remote_eof() {
    timeout(Duration::from_secs(5), async {
        let (mut core, mut client, mut peer) = blocked_upload().await;
        client
            .sockets
            .get_mut::<smol_tcp::Socket>(client.tcp)
            .close();
        let (eof, observed) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut tail = Vec::new();
            peer.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, vec![0x51; 8192 - 32]);
            eof.send(()).unwrap();
            // Like an independent packet-up download, leave this direction open.
            std::future::pending::<()>().await;
            drop(peer);
        });
        timeout(Duration::from_secs(3), async {
            while !core.connection_snapshot().connections.is_empty() {
                pump_tun_once(&mut client, core.tun()).await;
            }
        })
        .await
        .expect("half-close must use downlinkOnly, not 300-second connIdle");
        observed.await.unwrap();
        server.abort();
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

const RAW_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 3);
const RAW_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const RAW_CLIENT_PORT: u16 = 49_300;
const RAW_SERVER_PORT: u16 = 443;
const RAW_MSS: usize = 1460;

struct RawSegment {
    syn: bool,
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    window: usize,
}

fn raw_client_segment(
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    control: TcpControl,
    payload: &[u8],
) -> Bytes {
    let tcp = TcpRepr {
        src_port: RAW_CLIENT_PORT,
        dst_port: RAW_SERVER_PORT,
        control,
        seq_number: seq,
        ack_number: ack,
        window_len: u16::MAX,
        window_scale: None,
        max_seg_size: (control == TcpControl::Syn).then_some(RAW_MSS as u16),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload,
    };
    let ip = Ipv4Repr {
        src_addr: RAW_CLIENT,
        dst_addr: RAW_SERVER,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let checksums = ChecksumCapabilities::default();
    let mut buffer = vec![0; ip.buffer_len() + tcp.buffer_len()];
    let mut packet = Ipv4Packet::new_unchecked(&mut buffer);
    ip.emit(&mut packet, &checksums);
    tcp.emit(
        &mut TcpPacket::new_unchecked(packet.payload_mut()),
        &SmolIpAddress::Ipv4(RAW_CLIENT),
        &SmolIpAddress::Ipv4(RAW_SERVER),
        &checksums,
    );
    Bytes::from(buffer)
}

fn parse_raw_server_segment(packet: &[u8]) -> Option<RawSegment> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Tcp || ip.dst_addr() != RAW_CLIENT {
        return None;
    }
    let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
    assert!(!tcp.rst(), "TUN stack reset the raw upload flow");
    (tcp.dst_port() == RAW_CLIENT_PORT).then(|| RawSegment {
        syn: tcp.syn(),
        seq: tcp.seq_number(),
        ack: tcp.ack().then(|| tcp.ack_number()),
        // The client offers no window scaling, so the field is the window.
        window: usize::from(tcp.window_len()),
    })
}

async fn next_raw_server_segment(tun: &TunEndpoint) -> RawSegment {
    loop {
        while let Some(packet) = tun.try_poll_outbound().await.unwrap() {
            if let Some(segment) = parse_raw_server_segment(&packet) {
                return segment;
            }
        }
        sleep(Duration::from_millis(1)).await;
    }
}

/// Models how Linux and Darwin TCP send into a peer's receive window: whole
/// MSS segments only, never a partial segment into a window below one MSS
/// (Linux `tcp_snd_wnd_test`). Such a sender stalls until a window update.
struct KernelLikeSender {
    snd_una: TcpSeqNumber,
    snd_nxt: TcpSeqNumber,
    rcv_nxt: TcpSeqNumber,
    window: usize,
}

impl KernelLikeSender {
    fn on_segment(&mut self, segment: &RawSegment) {
        if let Some(ack) = segment.ack.filter(|ack| *ack >= self.snd_una) {
            self.snd_una = ack;
            self.window = segment.window;
        }
    }

    fn usable_window(&self) -> usize {
        self.window.saturating_sub(self.snd_nxt - self.snd_una)
    }

    fn segment(&mut self, payload: &[u8]) -> Bytes {
        let packet = raw_client_segment(self.snd_nxt, Some(self.rcv_nxt), TcpControl::Psh, payload);
        self.snd_nxt += payload.len();
        packet
    }
}

#[tokio::test]
async fn ack_after_full_window_upload_burst_advertises_drained_window() {
    timeout(Duration::from_secs(10), async {
        let (stream, mut peer) = tokio::io::duplex(1 << 20);
        let dialer = TransportDialer::system()
            .unwrap()
            .with_resolved_tcp_connector(Arc::new(BoundedConnector(Mutex::new(Some(stream)))));
        let mut core = Core::with_transport_dialer_and_tun_options(
            runtime_tun_config_with_freedom_outbound(),
            Arc::new(dialer),
            TunRuntimeOptions::default(),
        )
        .unwrap();
        core.start().await.unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let drain = tokio::spawn({
            let received = Arc::clone(&received);
            async move {
                let mut bytes = vec![0; 64 * 1024];
                while let Ok(read @ 1..) = peer.read(&mut bytes).await {
                    received.fetch_add(read, Ordering::SeqCst);
                }
            }
        });
        let tun = core.tun();

        let isn = TcpSeqNumber(0x1000);
        tun.push_inbound(raw_client_segment(isn, None, TcpControl::Syn, &[]))
            .await
            .unwrap();
        let syn_ack = next_raw_server_segment(tun).await;
        assert!(syn_ack.syn && syn_ack.ack == Some(isn + 1));
        let mut sender = KernelLikeSender {
            snd_una: isn + 1,
            snd_nxt: isn + 1,
            rcv_nxt: syn_ack.seq + 1,
            window: syn_ack.window,
        };
        // Data reaches the remote only after the bridge opens; afterwards the
        // stack hands received bytes over as soon as it reads its sockets.
        let opening = sender.segment(b"open");
        tun.push_inbound(opening).await.unwrap();
        while received.load(Ordering::SeqCst) < 4 || sender.snd_una != sender.snd_nxt {
            sender.on_segment(&next_raw_server_segment(tun).await);
        }

        let payload = [0x5a; RAW_MSS];
        let mut sent = 4;
        for burst in 0..8 {
            while sender.snd_una != sender.snd_nxt || sender.usable_window() < RAW_MSS {
                sender.on_segment(&next_raw_server_segment(tun).await);
            }
            // Queue the whole burst before the TUN task runs, as a sender
            // filling the window within one wakeup of the stack does.
            let mut segments = 0;
            while sender.usable_window() >= RAW_MSS {
                let packet = sender.segment(&payload);
                tun.push_inbound(packet).await.unwrap();
                segments += 1;
                sent += RAW_MSS;
            }
            assert!(segments > 1, "burst {burst} must fill the window");
            let burst_end = sender.snd_nxt;
            let ack = loop {
                let segment = next_raw_server_segment(tun).await;
                sender.on_segment(&segment);
                if segment.ack == Some(burst_end) {
                    break segment;
                }
            };
            assert!(
                ack.window >= RAW_MSS,
                "burst {burst}: the ACK for {segments} full segments advertised \
                 window {} below one MSS ({RAW_MSS}); it was built before the stack \
                 read its socket, so a kernel sender stalls until a later window update",
                ack.window
            );
        }

        while received.load(Ordering::SeqCst) < sent {
            sleep(Duration::from_millis(1)).await;
        }
        core.stop().await.unwrap();
        drain.abort();
    })
    .await
    .unwrap();
}
