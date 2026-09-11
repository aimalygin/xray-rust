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
    let mut buffer = [0; 32];
    // The reader deliberately cannot wake this task. Waiting for another
    // frame after Pending would leave this future pending instead of returning.
    let mut batch = Box::pin(read_remote_batch(&mut reader, &mut buffer));
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(batch.as_mut().poll(&mut cx), Poll::Ready((11, None)));
    drop(batch);
    assert_eq!(&buffer[..11], b"firstsecond");
    assert_eq!(
        read_remote_batch(&mut reader, &mut buffer).await,
        (4, Some(RemoteReadEnd::Closed))
    );
    assert_eq!(&buffer[..4], b"tail");
}

#[tokio::test]
async fn batching_keeps_tail_bytes_before_eof_or_error_and_respects_capacity() {
    for end in [RemoteReadEnd::Closed, RemoteReadEnd::Failed] {
        let mut reader = FramedReader(VecDeque::from([
            ReadStep::Data(Bytes::from_static(b"12345")),
            ReadStep::Data(Bytes::from_static(b"67890")),
            ReadStep::End(end),
        ]));
        let mut buffer = [0; 8];
        assert_eq!(read_remote_batch(&mut reader, &mut buffer).await, (8, None));
        assert_eq!(&buffer, b"12345678");
        assert_eq!(
            read_remote_batch(&mut reader, &mut buffer).await,
            (2, Some(end))
        );
        assert_eq!(&buffer[..2], b"90");
        assert!(reader.0.is_empty());
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
            to_remote,
            task: None,
            remote_open: false,
            pending_remote: VecDeque::new(),
            pending_remote_bytes: 0,
            has_deferred_remote_data: false,
            pending_remote_delivery: None,
            remote_closed: false,
            remote_aborted: false,
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
        .reserve_pending_upload(budget.hard_total_bytes())
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
        .reserve_pending_upload(budget.hard_total_bytes())
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
