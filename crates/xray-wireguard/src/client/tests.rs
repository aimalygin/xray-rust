use super::*;
use gotatun::packet::Packet;
use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, TcpSeqNumber};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_proxy::wireguard::KeyMaterial;

// Exercise real smoltcp state transitions through the same IP/command channels
// used by the engine, without relying on a proxy server's FIN/RST translation.
#[tokio::test]
async fn tcp_reset_is_an_error_after_buffered_bytes_and_releases_flow() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let config = Config {
            secret_key: KeyMaterial::parse(&"42".repeat(32)).unwrap(),
            peers: vec![crate::PeerConfig {
                public_key: KeyMaterial::parse(&"53".repeat(32)).unwrap(),
                preshared_key: None,
                endpoint: "127.0.0.1:51820".parse().unwrap(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                keepalive: 0,
            }],
            addresses: vec!["10.44.0.2".parse().unwrap()],
            mtu: 1420,
        };
        let wake = Arc::new(Notify::new());
        let (out, mut packets) = mpsc::channel(PACKET_QUEUE);
        let (incoming, input) = mpsc::channel(PACKET_QUEUE);
        let (commands, requests) = mpsc::channel(COMMAND_QUEUE);
        let stop = Stop::new();
        let stack = stack::Stack::<Packet<gotatun::packet::Ip>>::new(
            &config.addresses,
            config.mtu,
            FlowLimits::MOBILE.tcp_buffer(),
            out,
            input,
            requests,
            wake.clone(),
        );
        let task = tokio::spawn(stack.run(stop.clone()));
        let slots = Arc::new(Semaphore::new(1));
        let flow = Arc::new(Flow {
            id: 1,
            closed: AtomicBool::new(false),
            reset: AtomicBool::new(false),
            wake,
        });
        let (stream, bridge) = tokio::io::duplex(STREAM_BUFFER);
        let mut stream = TcpStream {
            stream,
            _guard: FlowGuard(flow.clone()),
        };
        let (reply, ready) = oneshot::channel();
        commands
            .send(Command::Tcp {
                local: config.addresses[0],
                remote: "198.51.100.7:443".parse().unwrap(),
                bridge,
                reply,
                flow,
                permit: slots.clone().acquire_owned().await.unwrap(),
            })
            .await
            .unwrap();
        let syn = packets.recv().await.unwrap();
        let bytes = syn.into_bytes();
        let ip = Ipv4Packet::new_checked(&bytes[..]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let ack = tcp.seq_number() + 1;
        let local_port = tcp.src_port();
        incoming
            .send(reply_packet(local_port, 100, ack, true, false, &[]))
            .await
            .unwrap();
        ready.await.unwrap().unwrap();
        incoming
            .send(reply_packet(
                local_port,
                101,
                ack,
                false,
                false,
                b"received",
            ))
            .await
            .unwrap();
        // Read the payload before resetting: this also waits for the actor to
        // move it through the smoltcp receive buffer into the application bridge.
        let mut payload = [0; 8];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"received");
        incoming
            .send(reply_packet(local_port, 109, ack, false, true, &[]))
            .await
            .unwrap();
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            stream.write_all(b"after reset").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(slots.available_permits(), 1);
        stop.close();
        task.await.unwrap();
    })
    .await
    .unwrap();
}
fn reply_packet(
    port: u16,
    seq: i32,
    ack: TcpSeqNumber,
    syn: bool,
    rst: bool,
    payload: &[u8],
) -> Packet<gotatun::packet::Ip> {
    let mut bytes = bytes::BytesMut::zeroed(40 + payload.len());
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
    ip.set_version(4);
    ip.set_header_len(20);
    ip.set_total_len((40 + payload.len()) as u16);
    ip.set_hop_limit(64);
    ip.set_next_header(IpProtocol::Tcp);
    ip.set_src_addr("198.51.100.7".parse().unwrap());
    ip.set_dst_addr("10.44.0.2".parse().unwrap());
    ip.fill_checksum();
    let source = ip.src_addr().into();
    let dest = ip.dst_addr().into();
    let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
    tcp.set_src_port(443);
    tcp.set_dst_port(port);
    tcp.set_seq_number(TcpSeqNumber(seq));
    tcp.set_ack_number(ack);
    tcp.set_ack(true);
    tcp.set_syn(syn);
    tcp.set_rst(rst);
    tcp.set_header_len(20);
    tcp.set_window_len(65535);
    tcp.payload_mut().copy_from_slice(payload);
    tcp.fill_checksum(&source, &dest);
    Packet::from_bytes(bytes).try_into_ip().unwrap()
}

#[tokio::test]
async fn idle_carrier_receive_follows_rebind_and_releases_old_sockets() {
    use crate::io::Factory;
    use gotatun::{
        packet::PacketBufPool,
        udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
    };
    use std::future::Future;
    use tokio::{net::UdpSocket, time::timeout};
    timeout(Duration::from_secs(10), async {
        for ip in ["127.0.0.1", "::1"] {
            let remote = UdpSocket::bind((ip, 0)).await.unwrap();
            let mut factory = Factory {
                ipv4: true,
                ipv6: true,
                protector: None,
                protection_failed: Arc::new(AtomicBool::new(false)),
                stop: Stop::new(),
                carrier: watch::channel(None).0,
                masks: None,
            };
            let (send, mut receive) = factory
                .bind(&UdpTransportFactoryParams {
                    addr: None,
                    port: 0,
                    #[cfg(target_os = "linux")]
                    fwmark: None,
                })
                .await
                .unwrap();
            let old = Arc::downgrade(factory.carrier.borrow().as_ref().unwrap());
            let mut bytes = [0; 32];
            send.send_to(
                Packet::from_bytes(bytes::BytesMut::from(&b"old request"[..])),
                remote.local_addr().unwrap(),
            )
            .await
            .unwrap();
            let (_, old_address) = remote.recv_from(&mut bytes).await.unwrap();
            let mut pool = PacketBufPool::new(1);
            let mut pending = Box::pin(receive.recv_from(&mut pool));
            std::future::poll_fn(|cx| {
                assert!(
                    pending.as_mut().poll(cx).is_pending(),
                    "no old socket traffic"
                );
                Poll::Ready(())
            })
            .await;
            factory.rebind().await.unwrap();
            send.send_to(
                Packet::from_bytes(bytes::BytesMut::from(&b"new socket"[..])),
                remote.local_addr().unwrap(),
            )
            .await
            .unwrap();
            let mut bytes = [0; 32];
            let (n, address) = remote.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..n], b"new socket");
            remote
                .send_to(b"reply on new socket", address)
                .await
                .unwrap();
            let (packet, _) = pending.await.unwrap();
            assert_eq!(&packet[..], b"reply on new socket");
            remote
                .send_to(b"delayed old reply", old_address)
                .await
                .unwrap();
            let (packet, _) = receive.recv_from(&mut pool).await.unwrap();
            assert_eq!(&packet[..], b"delayed old reply");
            assert!(
                timeout(Duration::from_millis(3200), receive.recv_from(&mut pool))
                    .await
                    .is_err()
            );
            assert!(
                old.upgrade().is_none(),
                "retired socket set must expire even without traffic"
            );
        }
    })
    .await
    .expect("idle receive must wake on carrier replacement");
}

fn queue_test_client(commands: mpsc::Sender<Command>, udp_limit: usize) -> Client {
    let mut flows = Flows::new(
        vec!["10.44.0.2".parse().unwrap()],
        1420,
        Routes::AllowedIps(vec!["0.0.0.0/0".parse().unwrap()]),
        commands,
        Stop::new(),
        Arc::new(Notify::new()),
        FlowLimits::default(),
    );
    flows.udp = Arc::new(Semaphore::new(udp_limit));
    Client(Arc::new(Owner {
        flows,
        finished: watch::channel(false).1,
        rebind: Arc::default(),
    }))
}

// Sends of busy UDP flows share the actor's command queue with opens. A full
// queue is backpressure, not an exhausted flow budget.
#[tokio::test]
async fn opens_wait_for_a_full_command_queue_and_busy_means_no_flow_slot() {
    use std::future::Future;
    tokio::time::timeout(Duration::from_secs(5), async {
        let (commands, mut requests) = mpsc::channel(COMMAND_QUEUE);
        let client = queue_test_client(commands.clone(), UDP_LIMIT);
        for _ in 0..COMMAND_QUEUE {
            commands
                .try_send(Command::Send {
                    id: 0,
                    payload: Bytes::new(),
                    reply: oneshot::channel().0,
                })
                .unwrap();
        }
        let mut udp = Box::pin(client.open_udp("198.51.100.7:53".parse().unwrap()));
        let mut tcp = Box::pin(client.connect("198.51.100.7:443".parse().unwrap()));
        std::future::poll_fn(|cx| {
            assert!(udp.as_mut().poll(cx).is_pending(), "UDP open waits");
            assert!(tcp.as_mut().poll(cx).is_pending(), "TCP open waits");
            Poll::Ready(())
        })
        .await;

        let actor = tokio::spawn(async move {
            let mut opened = 0;
            while let Some(command) = requests.recv().await {
                if let Command::Tcp { reply, .. } | Command::Udp { reply, .. } = command {
                    reply.send(Ok(())).unwrap();
                    opened += 1;
                    if opened == 2 {
                        break;
                    }
                }
            }
            opened
        });
        let (udp, tcp) = tokio::join!(udp, tcp);
        assert!(udp.is_ok());
        assert!(tcp.is_ok());
        assert_eq!(actor.await.unwrap(), 2);

        let (commands, _requests) = mpsc::channel(COMMAND_QUEUE);
        let exhausted = queue_test_client(commands, 0);
        assert!(matches!(
            exhausted.open_udp("198.51.100.7:53".parse().unwrap()).await,
            Err(Error::Busy)
        ));
    })
    .await
    .unwrap();
}

fn limited_client(limits: FlowLimits) -> (Client, mpsc::Receiver<Command>) {
    let (commands, requests) = mpsc::channel(COMMAND_QUEUE);
    let flows = Flows::new(
        vec!["10.44.0.2".parse().unwrap()],
        1420,
        Routes::AllowedIps(vec!["0.0.0.0/0".parse().unwrap()]),
        commands,
        Stop::new(),
        Arc::new(Notify::new()),
        limits,
    );
    let client = Client(Arc::new(Owner {
        flows,
        finished: watch::channel(false).1,
        rebind: Arc::default(),
    }));
    (client, requests)
}
/// An actor that opens every TCP flow and hands its place to the test, which
/// closes the flow by dropping the place, as the stack drops it with the flow.
fn open_every_tcp_flow(
    mut requests: mpsc::Receiver<Command>,
) -> mpsc::UnboundedReceiver<OwnedSemaphorePermit> {
    let (opened, places) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(command) = requests.recv().await {
            if let Command::Tcp { reply, permit, .. } = command {
                let _ = reply.send(Ok(()));
                let _ = opened.send(permit);
            }
        }
    });
    places
}
async fn until(mut condition: impl FnMut() -> bool) {
    while !condition() {
        tokio::task::yield_now().await;
    }
}
fn small(tcp: usize, tcp_waiting: usize) -> FlowLimits {
    FlowLimits::new(tcp, tcp_waiting, FlowLimits::MIN_TCP_BUFFER).unwrap()
}
const TARGET: &str = "198.51.100.7:443";

#[tokio::test]
async fn tcp_flows_past_the_limit_wait_in_turn_and_a_full_queue_is_busy() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, requests) = limited_client(small(2, 3));
        let mut places = open_every_tcp_flow(requests);
        let target = TARGET.parse().unwrap();
        let _streams = [
            client.connect(target).await.unwrap(),
            client.connect(target).await.unwrap(),
        ];
        let mut open = vec![places.recv().await.unwrap(), places.recv().await.unwrap()];
        assert_eq!(client.available_tcp_slots(), 0);

        let (done, mut finished) = mpsc::unbounded_channel();
        let mut waiters = Vec::new();
        for (index, name) in ["first", "second", "third"].into_iter().enumerate() {
            waiters.push(tokio::spawn({
                let client = client.clone();
                let done = done.clone();
                async move {
                    let stream = client.connect(target).await;
                    done.send((name, stream.is_ok())).unwrap();
                    stream
                }
            }));
            until(|| client.waiting_tcp_flows() == index + 1).await;
        }
        // The queue holds three: the next is refused at once.
        assert!(matches!(client.connect(target).await, Err(Error::Busy)));

        // A waiter that gives up leaves the queue at once.
        let second = waiters.remove(1);
        second.abort();
        assert!(matches!(second.await, Err(error) if error.is_cancelled()));
        assert_eq!(client.waiting_tcp_flows(), 2);

        // Each place a closed flow frees goes to the longest waiter.
        drop(open.remove(0));
        assert_eq!(finished.recv().await.unwrap(), ("first", true));
        open.push(places.recv().await.unwrap());
        assert_eq!(client.waiting_tcp_flows(), 1);
        drop(open.remove(0));
        assert_eq!(finished.recv().await.unwrap(), ("third", true));
        open.push(places.recv().await.unwrap());
        assert_eq!(client.waiting_tcp_flows(), 0);
        for waiter in waiters {
            assert!(waiter.await.unwrap().is_ok());
        }
        drop(open);
        assert_eq!(client.available_tcp_slots(), 2);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_tcp_flow_that_waits_out_its_wait_is_busy_and_leaves_the_queue() {
    let (client, requests) = limited_client(small(1, 1));
    let mut places = open_every_tcp_flow(requests);
    let target = TARGET.parse().unwrap();
    let _stream = client.connect(target).await.unwrap();
    let place = places.recv().await.unwrap();

    // The wait gives up as Busy before the open deadlines around it, the
    // outbound's ten seconds and the handshake timeout, would time it out.
    let started = tokio::time::Instant::now();
    assert!(matches!(client.connect(target).await, Err(Error::Busy)));
    assert!(started.elapsed() >= TCP_SLOT_WAIT);
    assert!(started.elapsed() < OPEN_TIMEOUT);
    assert_eq!(client.waiting_tcp_flows(), 0);
    assert_eq!(client.available_tcp_slots(), 0);

    // A place freed within the deadline ends the wait.
    let waiter = tokio::spawn({
        let client = client.clone();
        async move { client.connect(target).await }
    });
    until(|| client.waiting_tcp_flows() == 1).await;
    tokio::time::advance(TCP_SLOT_WAIT / 2).await;
    drop(place);
    assert!(waiter.await.unwrap().is_ok());
    drop(places.recv().await.unwrap());
    assert_eq!(client.available_tcp_slots(), 1);
    assert_eq!(client.waiting_tcp_flows(), 0);
}

#[tokio::test]
async fn closing_the_client_ends_tcp_waits_and_slots_stay_with_their_stack() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, requests) = limited_client(small(1, 4));
        let _places = open_every_tcp_flow(requests);
        let target = TARGET.parse().unwrap();
        let slot = client.tcp_slot().await.unwrap();
        assert_eq!(client.available_tcp_slots(), 0);

        // A place belongs to the stack that gave it.
        let (other, _requests) = limited_client(small(1, 4));
        assert!(matches!(
            other.connect_with_slot(slot, target).await,
            Err(Error::Configuration)
        ));
        assert_eq!(client.available_tcp_slots(), 1);

        let slot = client.tcp_slot().await.unwrap();
        let waiter = tokio::spawn({
            let client = client.clone();
            async move { client.connect(target).await }
        });
        until(|| client.waiting_tcp_flows() == 1).await;
        client.close();
        assert!(matches!(waiter.await.unwrap(), Err(Error::Closed)));
        assert_eq!(client.waiting_tcp_flows(), 0);
        assert!(matches!(client.tcp_slot().await, Err(Error::Closed)));
        drop(slot);
        assert_eq!(client.available_tcp_slots(), 1);
    })
    .await
    .unwrap();
}

#[test]
fn flow_limits_bound_their_memory_and_reject_what_the_stack_cannot_hold() {
    for limits in [
        FlowLimits::LOW_MEMORY,
        FlowLimits::MOBILE,
        FlowLimits::DESKTOP,
        FlowLimits::default(),
    ] {
        assert_eq!(
            FlowLimits::new(limits.tcp(), limits.tcp_waiting(), limits.tcp_buffer()).unwrap(),
            limits
        );
        assert!(limits.tcp() > 16, "a browser opens more than 16 at once");
        assert!(limits.tcp_waiting() > 0);
    }
    let buffers = |limits: FlowLimits| 2 * limits.tcp() * limits.tcp_buffer();
    assert_eq!(buffers(FlowLimits::LOW_MEMORY), 16 << 20);
    // The bound 16 flows of 1 MiB each way had.
    assert_eq!(buffers(FlowLimits::MOBILE), 32 << 20);
    assert_eq!(buffers(FlowLimits::DESKTOP), 256 << 20);
    for (tcp, waiting, buffer) in [
        (0, 0, FlowLimits::MIN_TCP_BUFFER),
        (FlowLimits::MAX_TCP + 1, 0, FlowLimits::MIN_TCP_BUFFER),
        (
            1,
            FlowLimits::MAX_TCP_WAITING + 1,
            FlowLimits::MIN_TCP_BUFFER,
        ),
        (1, 0, FlowLimits::MIN_TCP_BUFFER - 1),
        (1, 0, FlowLimits::MAX_TCP_BUFFER + 1),
    ] {
        assert!(matches!(
            FlowLimits::new(tcp, waiting, buffer),
            Err(Error::Configuration)
        ));
    }
    // No queue: the old refusal at once.
    assert!(FlowLimits::new(16, 0, FlowLimits::MAX_TCP_BUFFER).is_ok());
}
