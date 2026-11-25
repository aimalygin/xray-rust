use super::*;
use std::future::Future;
use std::task::{Context, Poll, Waker};

enum ReadStep {
    Data(Bytes),
    Pending,
    End(RemoteReadEnd),
}

struct FramedReader(VecDeque<ReadStep>);

impl AsyncRead for FramedReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self
            .0
            .pop_front()
            .expect("unexpected read after terminal result")
        {
            ReadStep::Pending => Poll::Pending,
            ReadStep::End(RemoteReadEnd::Closed) => Poll::Ready(Ok(())),
            ReadStep::End(RemoteReadEnd::Failed) => {
                Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
            }
            ReadStep::Data(data) => {
                let n = buffer.remaining().min(data.len());
                buffer.put_slice(&data[..n]);
                if n < data.len() {
                    self.0.push_front(ReadStep::Data(data.slice(n..)));
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[tokio::test]
async fn ready_frames_are_batched_without_waiting_for_more_data() {
    let mut reader = FramedReader(VecDeque::from([
        ReadStep::Data(Bytes::from_static(b"first")),
        ReadStep::Data(Bytes::from_static(b"second")),
        ReadStep::Pending,
        ReadStep::Data(Bytes::from_static(b"tail")),
        ReadStep::End(RemoteReadEnd::Closed),
    ]));
    // The reader deliberately cannot wake this task. Waiting for another
    // frame after Pending would leave this future pending instead of returning.
    let mut batch = Box::pin(read_remote_batch(&mut reader, 32));
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(
        batch.as_mut().poll(&mut cx),
        Poll::Ready((Bytes::from_static(b"firstsecond"), None))
    );
    drop(batch);
    assert_eq!(
        read_remote_batch(&mut reader, 32).await,
        (Bytes::from_static(b"tail"), Some(RemoteReadEnd::Closed))
    );
}

#[tokio::test]
async fn batching_keeps_tail_bytes_before_eof_or_error_and_respects_capacity() {
    for end in [RemoteReadEnd::Closed, RemoteReadEnd::Failed] {
        let mut reader = FramedReader(VecDeque::from([
            ReadStep::Data(Bytes::from_static(b"12345")),
            ReadStep::Data(Bytes::from_static(b"67890")),
            ReadStep::End(end),
        ]));
        assert_eq!(
            read_remote_batch(&mut reader, 8).await,
            (Bytes::from_static(b"12345678"), None)
        );
        assert_eq!(
            read_remote_batch(&mut reader, 8).await,
            (Bytes::from_static(b"90"), Some(end))
        );
        assert!(reader.0.is_empty());
    }
}

#[tokio::test]
async fn a_pending_download_read_holds_no_buffer_and_coalesces_up_to_a_chunk() {
    // Nothing ready: the read waits without a buffer of its own.
    let mut reader = FramedReader(VecDeque::from([ReadStep::Pending]));
    let mut batch = Box::pin(read_remote_batch(&mut reader, TCP_DOWNLOAD_CHUNK_SIZE));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(batch.as_mut().poll(&mut cx).is_pending());
    drop(batch);

    // Ready frames are coalesced up to the chunk size, whatever their sizes,
    // and handed on at the size they came to.
    let frames: Vec<Bytes> = (0..5u8)
        .map(|i| Bytes::from(vec![i; 20 * 1024 + usize::from(i)]))
        .collect();
    let expected: Vec<u8> = frames.iter().flat_map(|frame| frame.to_vec()).collect();
    let mut steps: VecDeque<_> = frames.into_iter().map(ReadStep::Data).collect();
    steps.push_back(ReadStep::Pending);
    let mut reader = FramedReader(steps);
    let (first, end) = read_remote_batch(&mut reader, TCP_DOWNLOAD_CHUNK_SIZE).await;
    assert_eq!(end, None);
    assert_eq!(first.as_ref(), &expected[..TCP_DOWNLOAD_CHUNK_SIZE]);
    let (rest, end) = read_remote_batch(&mut reader, TCP_DOWNLOAD_CHUNK_SIZE).await;
    assert_eq!(end, None);
    assert_eq!(rest.as_ref(), &expected[TCP_DOWNLOAD_CHUNK_SIZE..]);

    for len in [16 * 1024, TCP_DOWNLOAD_CHUNK_SIZE / 2 + 1] {
        let mut reader = FramedReader(VecDeque::from([
            ReadStep::Data(Bytes::from(vec![0x5a; len])),
            ReadStep::End(RemoteReadEnd::Closed),
        ]));
        let (data, end) = read_remote_batch(&mut reader, TCP_DOWNLOAD_CHUNK_SIZE).await;
        assert_eq!((data.len(), end), (len, Some(RemoteReadEnd::Closed)));
        assert!(data.iter().all(|byte| *byte == 0x5a));
    }
}

fn add_flow(
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
) -> SocketHandle {
    let handle = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
    ));
    let (to_remote, _) = mpsc::channel(1);
    flows.insert(
        handle,
        TcpFlow {
            generation: 1,
            to_remote: Some(to_remote),
            task: None,
            remote_open: false,
            upload_queue_packets: None,
            upload_pending: Arc::default(),
            upload_max_bytes: TCP_BRIDGE_FLOW_MAX_BYTES,
            pending_remote: VecDeque::new(),
            pending_remote_bytes: 0,
            has_deferred_remote_data: false,
            pending_remote_delivery: None,
            remote_closed: false,
            remote_aborted: false,
            send_buffer_idle_ticks: 0,
        },
    );
    handle
}

fn data_event(handle: SocketHandle, data: &'static [u8]) -> StackEvent {
    StackEvent::RemoteData {
        handle,
        generation: 1,
        data: Bytes::from_static(data),
        delivery: DownloadDelivery::test(),
    }
}

#[test]
fn stalled_reader_does_not_block_tcp_udp_or_close_events() {
    let mut sockets = SocketSet::new(Vec::new());
    let mut flows = HashMap::new();
    let slow = add_flow(&mut sockets, &mut flows);
    let fast = add_flow(&mut sockets, &mut flows);
    let mut budget = FlowBudgetState::new(MOBILE_FLOW_BUDGET_POLICY);
    let limit = budget.per_flow_limit();
    let flow = flows.get_mut(&slow).unwrap();
    flow.pending_remote.push_back(Bytes::from(vec![0; limit]));
    flow.pending_remote_bytes = limit;
    budget.record_pending_remote_enqueue(0, limit);
    let mut delayed = VecDeque::new();
    let mut udp = HashMap::new();
    let mut device = PacketDevice::new(1500);
    let (tx, mut rx) = mpsc::channel(8);
    for event in [
        data_event(slow, b"slow"),
        StackEvent::RemoteOpened {
            handle: fast,
            generation: 1,
            upload_queue_packets: None,
        },
        data_event(fast, b"fast"),
        StackEvent::UdpDatagram {
            client: IpEndpoint::new(IpAddress::v4(198, 18, 0, 2), 12000),
            source: IpEndpoint::new(IpAddress::v4(192, 0, 2, 1), 53),
            payload: Bytes::from_static(b"udp"),
        },
        StackEvent::RemoteClosed {
            handle: fast,
            generation: 1,
        },
    ] {
        tx.try_send(event).unwrap();
    }
    drain_stack_events(
        &mut rx,
        &mut delayed,
        &mut flows,
        &mut budget,
        &mut udp,
        &mut device,
        None,
    );
    let fast_flow = &flows[&fast];
    assert!(
        fast_flow.remote_open,
        "a full reader must not block another flow's open event"
    );
    assert_eq!(fast_flow.pending_remote.front().unwrap().as_ref(), b"fast");
    assert!(fast_flow.remote_closed);
    assert!(
        device.has_pending_outbound(),
        "UDP delivery must bypass a stalled TCP reader"
    );
    assert_eq!(delayed.len(), 1);
    assert_eq!(budget.pending_total_bytes(), limit + 4);
    tx.try_send(StackEvent::RemoteAborted {
        handle: slow,
        generation: 1,
    })
    .unwrap();
    drain_stack_events(
        &mut rx,
        &mut delayed,
        &mut flows,
        &mut budget,
        &mut udp,
        &mut device,
        None,
    );
    assert!(
        flows[&slow].remote_aborted,
        "host cancellation must bypass data backpressure"
    );
}

#[tokio::test]
async fn cancelled_delivery_keeps_one_deferred_chunk_per_flow() {
    let (tx, mut rx) = mpsc::channel(8);
    let serial = Arc::new(tokio::sync::Mutex::new(()));
    let mut cx = Context::from_waker(Waker::noop());
    let handle = SocketHandle::default();
    let mut first = Box::pin(send_remote_data(
        &tx,
        &serial,
        handle,
        1,
        Bytes::from(vec![1; 100_000]),
    ));
    assert!(first.as_mut().poll(&mut cx).is_pending());
    let held = rx.try_recv().unwrap();
    assert!(rx.try_recv().is_err());
    let StackEvent::RemoteData { ref data, .. } = held else {
        panic!("data event")
    };
    assert_eq!(data.len(), TCP_DOWNLOAD_CHUNK_SIZE);
    drop(first);
    assert!(
        serial.clone().try_lock_owned().is_err(),
        "cancelling the sender must retain the gate until the queued event is handled"
    );
    let mut second = Box::pin(send_remote_data(
        &tx,
        &serial,
        handle,
        1,
        Bytes::from_static(b"second"),
    ));
    assert!(second.as_mut().poll(&mut cx).is_pending());
    assert!(rx.try_recv().is_err());
    drop(held); // Same release path as a stale-generation or aborted event.
    assert!(second.as_mut().poll(&mut cx).is_pending());
    let StackEvent::RemoteData { data, delivery, .. } = rx.try_recv().unwrap() else {
        panic!("data event")
    };
    assert_eq!(data.as_ref(), b"second");
    delivery.complete();
    assert!(matches!(second.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
}

#[tokio::test]
async fn concurrent_dns_frames_keep_order_and_bound_each_chunk() {
    let (tx, mut rx) = mpsc::channel(8);
    let serial = Arc::new(tokio::sync::Mutex::new(()));
    let mut cx = Context::from_waker(Waker::noop());
    let handle = SocketHandle::default();
    let expected = vec![0xa5; 2 * TCP_DOWNLOAD_CHUNK_SIZE + 7];
    let mut first = Box::pin(send_remote_data(
        &tx,
        &serial,
        handle,
        1,
        Bytes::from(expected.clone()),
    ));
    let mut second = Box::pin(send_remote_data(
        &tx,
        &serial,
        handle,
        1,
        Bytes::from_static(b"next frame"),
    ));
    let mut received = Vec::new();
    for length in [TCP_DOWNLOAD_CHUNK_SIZE, TCP_DOWNLOAD_CHUNK_SIZE, 7] {
        assert!(first.as_mut().poll(&mut cx).is_pending());
        assert!(second.as_mut().poll(&mut cx).is_pending());
        let event = rx.try_recv().unwrap();
        assert!(
            rx.try_recv().is_err(),
            "only one unacknowledged chunk per TCP flow"
        );
        let StackEvent::RemoteData { data, delivery, .. } = event else {
            panic!("data event")
        };
        assert_eq!(data.len(), length);
        received.extend_from_slice(&data);
        delivery.complete();
    }
    assert_eq!(received, expected);
    assert!(matches!(first.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    assert!(second.as_mut().poll(&mut cx).is_pending());
    let StackEvent::RemoteData { data, delivery, .. } = rx.try_recv().unwrap() else {
        panic!("data event")
    };
    assert_eq!(data.as_ref(), b"next frame");
    delivery.complete();
    assert!(matches!(second.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
}

#[test]
fn global_upload_pressure_defers_data_but_not_control_and_recovers() {
    let mut sockets = SocketSet::new(Vec::new());
    let mut flows = HashMap::new();
    let handle = add_flow(&mut sockets, &mut flows);
    let mut budget = FlowBudgetState::new(LOW_MEMORY_FLOW_BUDGET_POLICY);
    let upload = budget
        .reserve_pending_upload(budget.hard_total_bytes(), None)
        .unwrap();
    let mut delayed = VecDeque::new();
    let mut udp = HashMap::new();
    let mut device = PacketDevice::new(1500);
    let (tx, mut rx) = mpsc::channel(8);
    tx.try_send(data_event(handle, b"tail")).unwrap();
    tx.try_send(StackEvent::RemoteClosed {
        handle,
        generation: 1,
    })
    .unwrap();
    drain_stack_events(
        &mut rx,
        &mut delayed,
        &mut flows,
        &mut budget,
        &mut udp,
        &mut device,
        None,
    );
    assert!(flows[&handle].remote_closed);
    assert!(
        flows[&handle].has_deferred_remote_data,
        "EOF must wait for deferred data"
    );
    assert!(flows[&handle].pending_remote.is_empty());
    assert_eq!(budget.pending_tcp_buffer_bytes(), budget.hard_total_bytes());
    drop(upload);
    drain_stack_events(
        &mut rx,
        &mut delayed,
        &mut flows,
        &mut budget,
        &mut udp,
        &mut device,
        None,
    );
    assert!(delayed.is_empty());
    assert!(!flows[&handle].has_deferred_remote_data);
    assert_eq!(
        flows[&handle].pending_remote.front().unwrap().as_ref(),
        b"tail"
    );
    assert_eq!(budget.pending_tcp_buffer_bytes(), 4);
    assert!(!budget.pressure_active());
}

#[tokio::test]
async fn remote_prefetch_stops_at_256_kib_and_resumes_after_stack_progress() {
    let mut sockets = SocketSet::new(Vec::new());
    let mut flows = HashMap::new();
    let handle = add_flow(&mut sockets, &mut flows);
    let mut budget = FlowBudgetState::new(MOBILE_FLOW_BUDGET_POLICY);
    let serial = Arc::new(tokio::sync::Mutex::new(()));
    let (tx, mut rx) = mpsc::channel(8);
    let mut delayed = VecDeque::new();
    let mut udp = HashMap::new();
    let mut device = PacketDevice::new(1500);
    let mut sender = Box::pin(send_remote_data(
        &tx,
        &serial,
        handle,
        1,
        Bytes::from(vec![0xa5; 5 * TCP_DOWNLOAD_CHUNK_SIZE]),
    ));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..4 {
        assert!(sender.as_mut().poll(&mut cx).is_pending());
        drain_stack_events(
            &mut rx,
            &mut delayed,
            &mut flows,
            &mut budget,
            &mut udp,
            &mut device,
            None,
        );
    }
    assert_eq!(flows[&handle].pending_remote_bytes, 256 * 1024);
    assert!(sender.as_mut().poll(&mut cx).is_pending());
    assert!(
        rx.try_recv().is_err(),
        "a fifth chunk must stay at the producer"
    );

    // Model one complete chunk copied into smoltcp's send buffer.
    let flow = flows.get_mut(&handle).unwrap();
    let consumed = flow.pending_remote.pop_front().unwrap();
    budget.record_pending_remote_dequeue(flow.pending_remote_bytes, consumed.len());
    flow.pending_remote_bytes -= consumed.len();
    acknowledge_remote_data(flow);
    assert!(sender.as_mut().poll(&mut cx).is_pending());
    drain_stack_events(
        &mut rx,
        &mut delayed,
        &mut flows,
        &mut budget,
        &mut udp,
        &mut device,
        None,
    );
    assert_eq!(flows[&handle].pending_remote_bytes, 256 * 1024);
    assert_eq!(budget.pending_total_bytes(), 256 * 1024);
    assert!(delayed.is_empty());
}

#[test]
fn stale_deferred_data_does_not_change_reused_flow() {
    let mut sockets = SocketSet::new(Vec::new());
    let mut flows = HashMap::new();
    let handle = add_flow(&mut sockets, &mut flows);
    flows.get_mut(&handle).unwrap().generation = 2;
    let mut budget = FlowBudgetState::new(MOBILE_FLOW_BUDGET_POLICY);
    let mut delayed = VecDeque::from([data_event(handle, b"old")]);
    let (_tx, mut rx) = mpsc::channel(1);
    drain_stack_events(
        &mut rx,
        &mut delayed,
        &mut flows,
        &mut budget,
        &mut HashMap::new(),
        &mut PacketDevice::new(1500),
        None,
    );
    assert!(delayed.is_empty());
    assert!(flows[&handle].pending_remote.is_empty());
    assert!(!flows[&handle].has_deferred_remote_data);
    assert_eq!(budget.pending_total_bytes(), 0);
}

#[test]
fn fin_waits_for_deferred_tail_before_closing_the_local_tcp_socket() {
    use super::tests::{build_ipv4_tcp_packet, ipv4_tcp_sequence};
    let client_ip = Ipv4Addr::new(10, 10, 0, 2);
    let server_ip = Ipv4Addr::new(203, 0, 113, 7);
    let mut device = PacketDevice::new(1500);
    let mut iface = Interface::new(
        InterfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        Instant::now(),
    );
    iface.set_any_ip(true);
    let mut sockets = SocketSet::new(Vec::new());
    let mut flows = HashMap::new();
    let handle = add_flow(&mut sockets, &mut flows);
    sockets.get_mut::<tcp::Socket>(handle).listen(443).unwrap();
    device.push_inbound(Bytes::from(build_ipv4_tcp_packet(
        client_ip,
        49152,
        server_ip,
        443,
        1000,
        0,
        0x02,
        &[],
    )));
    iface.poll(Instant::now(), &mut device, &mut sockets);
    let server_seq = ipv4_tcp_sequence(&device.pop_outbound().unwrap()).unwrap();
    device.push_inbound(Bytes::from(build_ipv4_tcp_packet(
        client_ip,
        49152,
        server_ip,
        443,
        1001,
        server_seq + 1,
        0x10,
        &[],
    )));
    iface.poll(Instant::now(), &mut device, &mut sockets);
    assert_eq!(
        sockets.get::<tcp::Socket>(handle).state(),
        tcp::State::Established
    );

    let mut budget = FlowBudgetState::new(MOBILE_FLOW_BUDGET_POLICY);
    let upload = budget
        .reserve_pending_upload(budget.hard_total_bytes(), None)
        .unwrap();
    let mut delayed = VecDeque::new();
    let mut udp = HashMap::new();
    let (tx, mut rx) = mpsc::channel(2);
    tx.try_send(data_event(handle, b"last bytes")).unwrap();
    tx.try_send(StackEvent::RemoteClosed {
        handle,
        generation: 1,
    })
    .unwrap();
    drain_stack_events(
        &mut rx,
        &mut delayed,
        &mut flows,
        &mut budget,
        &mut udp,
        &mut device,
        None,
    );
    assert_eq!(
        write_remote_data_to_sockets(&mut sockets, &mut flows, &mut budget),
        0
    );
    assert_eq!(
        sockets.get::<tcp::Socket>(handle).state(),
        tcp::State::Established,
        "a close notification must not overtake data held by global backpressure"
    );
    drop(upload);
    drain_stack_events(
        &mut rx,
        &mut delayed,
        &mut flows,
        &mut budget,
        &mut udp,
        &mut device,
        None,
    );
    assert_eq!(
        write_remote_data_to_sockets(&mut sockets, &mut flows, &mut budget),
        b"last bytes".len()
    );
    let socket = sockets.get::<tcp::Socket>(handle);
    assert_eq!(socket.send_queue(), b"last bytes".len());
    assert_eq!(socket.state(), tcp::State::FinWait1);
    assert!(flows[&handle].pending_remote_delivery.is_none());
    assert_eq!(budget.pending_total_bytes(), 0);
}

fn test_udp_flow(
    budget: &FlowBudgetState,
) -> (UdpFlowKey, UdpFlow, mpsc::Receiver<QueuedDatagram>) {
    let key = UdpFlowKey::new(
        IpEndpoint::new(IpAddress::v4(198, 18, 0, 2), 12000),
        IpEndpoint::new(IpAddress::v4(192, 0, 2, 1), 443),
    );
    let (to_remote, from_stack) = mpsc::channel(UDP_BRIDGE_CHANNEL_DEPTH);
    let flow = UdpFlow {
        to_remote,
        queued: budget.udp_queued_bytes_for_new_flow(),
        generation: 7,
        last_used_sequence: 0,
        task: None,
        permit: None,
    };
    (key, flow, from_stack)
}

#[test]
fn full_udp_queue_drops_the_datagram_but_keeps_the_flow() {
    let mut budget = FlowBudgetState::new(MOBILE_FLOW_BUDGET_POLICY);
    let (key, flow, mut from_stack) = test_udp_flow(&budget);
    let mut flows = HashMap::from([(key, flow)]);
    for _ in 0..UDP_BRIDGE_CHANNEL_DEPTH {
        forward_udp_payload(&mut flows, key, Bytes::from_static(b"burst"), &mut budget);
    }
    assert_eq!(budget.udp_channel_dropped_packets(), 0);

    forward_udp_payload(&mut flows, key, Bytes::from_static(b"over"), &mut budget);
    assert_eq!(budget.udp_channel_dropped_packets(), 1);
    assert_eq!(flows[&key].generation, 7, "a full queue must keep the flow");

    from_stack.try_recv().unwrap();
    assert!(
        matches!(
            budget.admit_udp_flow(&mut flows, key),
            UdpFlowAdmission::Existing
        ),
        "the next datagram must reuse the flow instead of opening a new one"
    );
    forward_udp_payload(&mut flows, key, Bytes::from_static(b"later"), &mut budget);
    let queued: Vec<_> = std::iter::from_fn(|| from_stack.try_recv().ok())
        .map(QueuedDatagram::into_payload)
        .collect();
    assert_eq!(queued.len(), UDP_BRIDGE_CHANNEL_DEPTH);
    assert_eq!(queued.last().unwrap().as_ref(), b"later");
    assert_eq!(budget.udp_channel_dropped_packets(), 1);
    assert_eq!(budget.udp_queued_bytes.load(Ordering::Acquire), 0);

    drop(from_stack);
    forward_udp_payload(&mut flows, key, Bytes::from_static(b"closed"), &mut budget);
    assert!(
        flows.is_empty(),
        "a closed queue means the bridge ended, so the flow is forgotten"
    );
    assert_eq!(budget.udp_channel_dropped_packets(), 2);
    assert_eq!(budget.udp_queued_bytes.load(Ordering::Acquire), 0);
}

fn other_udp_flow(
    budget: &FlowBudgetState,
    flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    port: u16,
) -> (UdpFlowKey, mpsc::Receiver<QueuedDatagram>) {
    let key = UdpFlowKey::new(
        IpEndpoint::new(IpAddress::v4(198, 18, 0, 2), port),
        IpEndpoint::new(IpAddress::v4(192, 0, 2, 1), 443),
    );
    let (_, mut flow, receiver) = test_udp_flow(budget);
    flow.generation = u64::from(port);
    flows.insert(key, flow);
    (key, receiver)
}

fn forward_udp_datagrams(
    flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    key: UdpFlowKey,
    count: usize,
    len: usize,
    budget: &mut FlowBudgetState,
) {
    for _ in 0..count {
        forward_udp_payload(flows, key, Bytes::from(vec![7; len]), budget);
    }
}

#[test]
fn udp_queues_are_bounded_in_bytes_per_flow_and_in_total() {
    let policy = LOW_MEMORY_FLOW_BUDGET_POLICY;
    let per_flow = policy.udp.max_queued_bytes_per_flow;
    let total = policy.udp.max_queued_bytes_total;
    let mut budget = FlowBudgetState::new(policy);
    let (key, flow, mut from_stack) = test_udp_flow(&budget);
    let mut flows = HashMap::from([(key, flow)]);

    // A full channel of datagrams from a 1500-byte MTU fits in the bytes.
    let full_mtu = 1500 - 28;
    forward_udp_datagrams(
        &mut flows,
        key,
        UDP_BRIDGE_CHANNEL_DEPTH,
        full_mtu,
        &mut budget,
    );
    assert_eq!(budget.udp_channel_dropped_packets(), 0);
    while from_stack.try_recv().is_ok() {}
    assert_eq!(budget.udp_queued_bytes.load(Ordering::Acquire), 0);

    // Datagrams from a 9000-byte MTU fill the bytes first.
    let datagram = 9000 - 28;
    let fit = per_flow / datagram;
    assert!(fit < UDP_BRIDGE_CHANNEL_DEPTH);
    forward_udp_datagrams(&mut flows, key, fit + 1, datagram, &mut budget);
    assert_eq!(budget.udp_channel_dropped_packets(), 1);
    assert_eq!(flows[&key].queued.flow(), fit * datagram);
    assert_eq!(
        budget.udp_queued_bytes.load(Ordering::Acquire),
        fit * datagram
    );

    // Taking a datagram out of the queue makes room for another.
    let first = from_stack.try_recv().unwrap().into_payload();
    assert_eq!(first.len(), datagram);
    forward_udp_datagrams(&mut flows, key, 1, datagram, &mut budget);
    assert_eq!(budget.udp_channel_dropped_packets(), 1);

    // Other flows share the total.
    let mut others = Vec::new();
    let mut port = 20000;
    while budget.udp_queued_bytes.load(Ordering::Acquire) + per_flow <= total {
        let (other_key, receiver) = other_udp_flow(&budget, &mut flows, port);
        others.push(receiver);
        forward_udp_datagrams(&mut flows, other_key, fit, datagram, &mut budget);
        port += 1;
    }
    let drops = budget.udp_channel_dropped_packets();
    let room = total - budget.udp_queued_bytes.load(Ordering::Acquire);
    assert!(
        room >= datagram,
        "the last flow below takes some by the total"
    );
    let (last_key, last_receiver) = other_udp_flow(&budget, &mut flows, port);
    forward_udp_datagrams(&mut flows, last_key, fit, datagram, &mut budget);
    assert_eq!(flows[&last_key].queued.flow(), room / datagram * datagram);
    assert_eq!(
        budget.udp_channel_dropped_packets() - drops,
        (fit - room / datagram) as u64,
        "the total is shared by every flow"
    );
    assert!(budget.udp_queued_bytes.load(Ordering::Acquire) <= total);

    // Queues that end give back what they held.
    drop(others);
    drop(last_receiver);
    drop(from_stack);
    assert_eq!(budget.udp_queued_bytes.load(Ordering::Acquire), 0);
}

#[test]
fn a_udp_flow_keeps_a_floor_when_other_flows_fill_the_total() {
    let policy = MOBILE_FLOW_BUDGET_POLICY;
    let total = policy.udp.max_queued_bytes_total;
    let mut budget = FlowBudgetState::new(policy);
    let mut flows = HashMap::new();

    // Bulk flows to a slow outbound fill the total, with room left in
    // their channels.
    let mut bulk = Vec::new();
    let mut port = 20000;
    while budget.udp_queued_bytes.load(Ordering::Acquire) < total {
        let (key, receiver) = other_udp_flow(&budget, &mut flows, port);
        bulk.push((key, receiver));
        forward_udp_datagrams(&mut flows, key, 200, 1200, &mut budget);
        port += 1;
    }
    let (bulk_key, _) = bulk[0];
    let drops = budget.udp_channel_dropped_packets();
    forward_udp_datagrams(&mut flows, bulk_key, 1, 1200, &mut budget);
    assert_eq!(
        budget.udp_channel_dropped_packets(),
        drops + 1,
        "a flow past its floor waits for the total"
    );

    // Another flow still queues a few datagrams of its own.
    let (quiet, mut quiet_rx) = other_udp_flow(&budget, &mut flows, 30000);
    let floor = UDP_FLOW_QUEUE_FLOOR_BYTES / 1200;
    assert!(floor >= 4);
    forward_udp_datagrams(&mut flows, quiet, floor + 1, 1200, &mut budget);
    assert_eq!(flows[&quiet].queued.flow(), floor * 1200);
    assert_eq!(budget.udp_channel_dropped_packets(), drops + 2);
    assert!(
        budget.udp_queued_bytes.load(Ordering::Acquire)
            <= total + flows.len() * UDP_FLOW_QUEUE_FLOOR_BYTES
    );

    // An empty queue takes a datagram larger than the floor.
    let (jumbo, _jumbo_rx) = other_udp_flow(&budget, &mut flows, 30001);
    forward_udp_datagrams(&mut flows, jumbo, 1, 9000 - 28, &mut budget);
    assert_eq!(flows[&jumbo].queued.flow(), 9000 - 28);

    // Draining frees the floor for the next datagrams.
    while quiet_rx.try_recv().is_ok() {}
    forward_udp_datagrams(&mut flows, quiet, 1, 1200, &mut budget);
    assert_eq!(flows[&quiet].queued.flow(), 1200);
    assert_eq!(budget.udp_channel_dropped_packets(), drops + 2);
}

#[test]
fn queued_udp_datagrams_do_not_share_the_tun_read_buffer() {
    let mut budget = FlowBudgetState::new(MOBILE_FLOW_BUDGET_POLICY);
    let (key, flow, mut from_stack) = test_udp_flow(&budget);
    let mut flows = HashMap::from([(key, flow)]);
    let read_buffer = Bytes::from(vec![3; 64 * 1024]);
    let payload = read_buffer.slice(100..1300);
    forward_udp_payload(&mut flows, key, payload.clone(), &mut budget);
    let queued = from_stack.try_recv().unwrap().into_payload();
    assert_eq!(queued, payload);
    assert!(
        !std::ptr::eq(queued.as_ptr(), payload.as_ptr()),
        "a queued datagram must not keep the 64 KiB read buffer alive"
    );
}

#[test]
fn tun_tcp_socket_buffers_grow_only_when_the_flow_carries_data() {
    use super::tests::{build_ipv4_tcp_packet, ipv4_tcp_sequence};
    assert_eq!(tcp_initial_rx_buffer_size(1500), TCP_INITIAL_RX_BUFFER_SIZE);
    assert_eq!(tcp_initial_rx_buffer_size(9000), 2 * (9000 - 40));
    assert!(tcp_initial_rx_buffer_size(9000) < tcp_rx_buffer_size(9000));

    let tun = TunEndpoint::new(xray_tun::TunConfig {
        mtu: 1500,
        queue_depth: 16,
    });
    let client_ip = Ipv4Addr::new(10, 10, 0, 2);
    let server_ip = Ipv4Addr::new(192, 0, 2, 1);
    let endpoint = IpEndpoint::new(IpAddress::Ipv4(server_ip), 443);
    let mut device = PacketDevice::new(1500);
    let mut iface = Interface::new(
        InterfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        Instant::now(),
    );
    iface.set_any_ip(true);
    let mut sockets = SocketSet::new(Vec::new());
    let mut listeners = HashMap::new();
    add_tcp_listener(&mut sockets, &mut listeners, endpoint, 1500);
    let handle = listeners[&endpoint].handle;
    let capacities = |sockets: &SocketSet<'static>| {
        let socket = sockets.get::<tcp::Socket>(handle);
        (socket.recv_capacity(), socket.send_capacity())
    };
    assert_eq!(capacities(&sockets), (TCP_INITIAL_RX_BUFFER_SIZE, 0));

    device.push_inbound(Bytes::from(build_ipv4_tcp_packet(
        client_ip,
        49152,
        server_ip,
        443,
        1000,
        0,
        0x02,
        &[],
    )));
    iface.poll(Instant::now(), &mut device, &mut sockets);
    let server_seq = ipv4_tcp_sequence(&device.pop_outbound().unwrap()).unwrap();
    device.push_inbound(Bytes::from(build_ipv4_tcp_packet(
        client_ip,
        49152,
        server_ip,
        443,
        1001,
        server_seq + 1,
        0x10,
        &[],
    )));
    iface.poll(Instant::now(), &mut device, &mut sockets);
    assert_eq!(
        sockets.get::<tcp::Socket>(handle).state(),
        tcp::State::Established
    );

    let (to_remote, mut from_stack) = mpsc::channel(1);
    let mut flows = HashMap::from([(
        handle,
        TcpFlow {
            generation: 1,
            to_remote: Some(to_remote),
            task: None,
            remote_open: false,
            upload_queue_packets: None,
            upload_pending: Arc::default(),
            upload_max_bytes: TCP_BRIDGE_FLOW_MAX_BYTES,
            pending_remote: VecDeque::new(),
            pending_remote_bytes: 0,
            has_deferred_remote_data: false,
            pending_remote_delivery: None,
            remote_closed: false,
            remote_aborted: false,
            send_buffer_idle_ticks: 0,
        },
    )]);
    let mut budget = FlowBudgetState::new(LOW_MEMORY_FLOW_BUDGET_POLICY);

    // A flow whose outbound is still opening keeps the small buffers.
    read_socket_data_to_remote(&tun, &mut sockets, &mut flows, &mut budget);
    write_remote_data_to_sockets(&mut sockets, &mut flows, &mut budget);
    assert_eq!(capacities(&sockets), (TCP_INITIAL_RX_BUFFER_SIZE, 0));

    // So does an open one whose client has sent nothing.
    flows.get_mut(&handle).unwrap().remote_open = true;
    read_socket_data_to_remote(&tun, &mut sockets, &mut flows, &mut budget);
    write_remote_data_to_sockets(&mut sockets, &mut flows, &mut budget);
    assert_eq!(capacities(&sockets), (TCP_INITIAL_RX_BUFFER_SIZE, 0));

    // The client's first data gives it the full receive buffer, and the
    // larger window goes out at once.
    while device.pop_outbound().is_some() {}
    device.push_inbound(Bytes::from(build_ipv4_tcp_packet(
        client_ip,
        49152,
        server_ip,
        443,
        1001,
        server_seq + 1,
        0x18,
        b"hello",
    )));
    iface.poll(Instant::now(), &mut device, &mut sockets);
    read_socket_data_to_remote(&tun, &mut sockets, &mut flows, &mut budget);
    assert_eq!(capacities(&sockets), (tcp_rx_buffer_size(1500), 0));
    assert_eq!(from_stack.try_recv().unwrap().data.as_ref(), b"hello");
    iface.poll(Instant::now(), &mut device, &mut sockets);
    let window = std::iter::from_fn(|| device.pop_outbound())
        .last()
        .map(|packet| u16::from_be_bytes([packet[34], packet[35]]))
        .expect("the stack acknowledges the data");
    assert!(
        usize::from(window) > TCP_INITIAL_RX_BUFFER_SIZE,
        "window {window}"
    );

    // The remote's first bytes give it the send buffer.
    let flow = flows.get_mut(&handle).unwrap();
    flow.pending_remote
        .push_back(Bytes::from_static(b"response"));
    flow.pending_remote_bytes = 8;
    budget.record_pending_remote_enqueue(0, 8);
    write_remote_data_to_sockets(&mut sockets, &mut flows, &mut budget);
    assert_eq!(
        capacities(&sockets),
        (tcp_rx_buffer_size(1500), TCP_BUFFER_SIZE)
    );
}
