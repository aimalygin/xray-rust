//! Receive credit, backpressure and latency regressions for issue #28.
use super::*;
use h2::SendStream;
use tokio::time::{sleep_until, Instant};

const STREAM_WINDOW: usize = 4 * 1024 * 1024;

#[tokio::test(start_paused = true)]
async fn configured_receive_windows_bound_unread_data_and_replenish_only_consumed_bytes() {
    for window in [65535, 1024 * 1024, 8 * 1024 * 1024, 16 * 1024 * 1024] {
        let (client, mut server) = pair_with_window(server::Builder::new(), Some(window)).await;
        let (mut body, mut send) = response_pair(&client, &mut server).await;
        timeout(DEADLINE, send_bytes(&mut send, window as usize))
            .await
            .unwrap();
        assert_blocked(&mut send).await;
        let count = window as usize / 2;
        let mut bytes = vec![0; count];
        body.read_exact(&mut bytes).await.unwrap();
        assert!(bytes.iter().all(|b| *b == 0xa5));
        timeout(DEADLINE, send_bytes(&mut send, count))
            .await
            .unwrap();
        assert_blocked(&mut send).await;
        drop(body);
        assert_eq!(
            timeout(DEADLINE, poll_fn(|cx| send.poll_reset(cx)))
                .await
                .unwrap()
                .unwrap(),
            Reason::CANCEL
        );
        server.close().await;
    }
}

#[tokio::test]
async fn invalid_receive_window_is_rejected_before_writing_the_preface() {
    for window in [0, 65534, 16 * 1024 * 1024 + 1, u32::MAX] {
        let (client, mut server) = tokio::io::duplex(64);
        assert!(matches!(
            connect_h2_with_receive_window(Box::new(client), None, window).await,
            Err(H2Error::Configuration(_))
        ));
        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.unwrap();
        assert!(wire.is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn a_larger_stream_override_does_not_raise_shared_connection_credit() {
    let (client, mut server) =
        pair_with_window(server::Builder::new(), Some(8 * 1024 * 1024)).await;
    let mut stalled = Vec::new();
    for _ in 0..2 {
        let (body, mut send) = response_pair(&client, &mut server).await;
        timeout(DEADLINE, send_bytes(&mut send, 8 * 1024 * 1024))
            .await
            .unwrap();
        stalled.push((body, send));
    }
    let (mut victim, mut send) = response_pair(&client, &mut server).await;
    assert_blocked(&mut send).await;
    let (body, mut cancelled_send) = stalled.remove(0);
    drop(body);
    assert_eq!(
        timeout(DEADLINE, poll_fn(|cx| cancelled_send.poll_reset(cx)))
            .await
            .unwrap()
            .unwrap(),
        Reason::CANCEL
    );
    timeout(DEADLINE, send_bytes(&mut send, 1)).await.unwrap();
    let mut byte = [0];
    timeout(DEADLINE, victim.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(byte, [0xa5]);
    drop(stalled);
    drop(victim);
    server.close().await;
}

async fn response_pair(
    client: &H2Client,
    server: &mut TestServer,
) -> (impl tokio::io::AsyncRead + Unpin, SendStream<Bytes>) {
    let pending = client
        .start_fixed(
            request(Method::GET, "http://example.test/window"),
            Bytes::new(),
        )
        .await
        .unwrap();
    let (_, mut respond) = server.accept().await.unwrap().unwrap();
    let send = respond
        .send_response(response(StatusCode::OK), false)
        .unwrap();
    (pending.open().await.unwrap(), send)
}

async fn send_bytes(send: &mut SendStream<Bytes>, mut count: usize) {
    let chunk = Bytes::from(vec![0xa5; 16 * 1024]);
    while count > 0 {
        send.reserve_capacity(count.min(chunk.len()));
        let granted = poll_fn(|cx| send.poll_capacity(cx)).await.unwrap().unwrap();
        let take = granted.min(count).min(chunk.len());
        assert!(take > 0);
        send.send_data(chunk.slice(..take), false).unwrap();
        count -= take;
    }
}

async fn assert_blocked(send: &mut SendStream<Bytes>) {
    send.reserve_capacity(1);
    assert!(
        timeout(
            Duration::from_millis(25),
            poll_fn(|cx| send.poll_capacity(cx))
        )
        .await
        .is_err(),
        "unread DATA must remain flow controlled"
    );
    send.reserve_capacity(0);
}

#[tokio::test(start_paused = true)]
async fn unread_response_is_bounded_and_partial_reads_return_credit() {
    let (client, mut server) = pair().await;
    let (mut body, mut send) = response_pair(&client, &mut server).await;
    timeout(DEADLINE, send_bytes(&mut send, STREAM_WINDOW))
        .await
        .expect("one stream must accept a mobile-path bandwidth-delay product");
    assert_blocked(&mut send).await;

    // Return enough credit for h2's coalesced WINDOW_UPDATE while reading in
    // awkward pieces, including a partial DATA frame. Never grant unread bytes.
    let mut read = 0;
    let mut buffer = [0; 8191];
    while read < STREAM_WINDOW / 2 {
        let limit = buffer.len().min(STREAM_WINDOW / 2 - read);
        let n = body.read(&mut buffer[..limit]).await.unwrap();
        assert!(n > 0);
        assert!(buffer[..n].iter().all(|byte| *byte == 0xa5));
        read += n;
    }
    timeout(DEADLINE, send_bytes(&mut send, read))
        .await
        .expect("consumed bytes must replenish the stream");
    assert_blocked(&mut send).await;
    drop(body);
    assert_eq!(
        timeout(DEADLINE, poll_fn(|cx| send.poll_reset(cx)))
            .await
            .unwrap()
            .unwrap(),
        Reason::CANCEL
    );
    server.close().await;
}

#[tokio::test(start_paused = true)]
async fn stalled_responses_share_a_bounded_connection_and_cancel_restores_progress() {
    let (client, mut server) = pair().await;
    let mut stalled = Vec::new();
    for _ in 0..3 {
        let (body, mut send) = response_pair(&client, &mut server).await;
        timeout(DEADLINE, send_bytes(&mut send, STREAM_WINDOW))
            .await
            .unwrap();
        stalled.push((body, send));
    }
    // Three entirely unread streams must leave room for a fast stream to
    // recycle credit repeatedly, including beyond the connection's 16 MiB.
    let (mut fast, mut send) = response_pair(&client, &mut server).await;
    let sender = tokio::spawn(async move {
        send_bytes(&mut send, 5 * STREAM_WINDOW + 1).await;
        send.send_data(Bytes::new(), true).unwrap();
    });
    let mut received = Vec::new();
    timeout(DEADLINE, fast.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.len(), 5 * STREAM_WINDOW + 1);
    assert!(received.iter().all(|byte| *byte == 0xa5));
    sender.await.unwrap();

    // Four unread streams can fill the entire connection. This is an explicit
    // memory/backpressure boundary, not a promise of unlimited stalled peers.
    let (body, mut send) = response_pair(&client, &mut server).await;
    timeout(DEADLINE, send_bytes(&mut send, STREAM_WINDOW))
        .await
        .unwrap();
    stalled.push((body, send));
    let (mut victim, mut send) = response_pair(&client, &mut server).await;
    assert_blocked(&mut send).await;
    let (body, mut cancelled_send) = stalled.remove(0);
    drop(body);
    assert_eq!(
        timeout(DEADLINE, poll_fn(|cx| cancelled_send.poll_reset(cx)))
            .await
            .unwrap()
            .unwrap(),
        Reason::CANCEL
    );
    timeout(DEADLINE, send_bytes(&mut send, 1)).await.unwrap();
    let mut byte = [0];
    timeout(DEADLINE, victim.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(byte, [0xa5]);
    drop(stalled);
    drop(victim);
    server.close().await;
}

/// A delay line, not a per-chunk sleep: chunks already in flight have their
/// own arrival times, so a larger window can actually pipeline DATA. Queues
/// and duplex pipes are bounded, and both directions receive half the RTT.
fn delay_direction(
    mut read: tokio::io::ReadHalf<DuplexStream>,
    mut write: tokio::io::WriteHalf<DuplexStream>,
    delay: Duration,
) -> [JoinHandle<()>; 2] {
    let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(256);
    let reader = tokio::spawn(async move {
        loop {
            let mut bytes = vec![0; 16 * 1024];
            let Ok(n) = read.read(&mut bytes).await else {
                break;
            };
            if n == 0 {
                break;
            }
            bytes.truncate(n);
            if tx.send((Instant::now() + delay, bytes)).await.is_err() {
                break;
            }
        }
    });
    let writer = tokio::spawn(async move {
        while let Some((arrival, bytes)) = rx.recv().await {
            sleep_until(arrival).await;
            if write.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = write.shutdown().await;
    });
    [reader, writer]
}

#[tokio::test(start_paused = true)]
async fn single_download_pipelines_across_a_113ms_path() {
    let (client_io, client_wire) = tokio::io::duplex(1024 * 1024);
    let (server_wire, server_io) = tokio::io::duplex(1024 * 1024);
    let (client_read, client_write) = tokio::io::split(client_wire);
    let (server_read, server_write) = tokio::io::split(server_wire);
    let delay = Duration::from_micros(56_500);
    let forward = delay_direction(client_read, server_write, delay);
    let backward = delay_direction(server_read, client_write, delay);
    let peer = tokio::spawn(async move {
        let mut connection = server::handshake(server_io).await.unwrap();
        let (_, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut send = respond
            .send_response(response(StatusCode::OK), false)
            .unwrap();
        let sender = tokio::spawn(async move {
            send_bytes(&mut send, 2 * STREAM_WINDOW).await;
            send.send_data(Bytes::new(), true).unwrap();
        });
        while let Some(exchange) = connection.accept().await {
            exchange.unwrap();
        }
        sender.await.unwrap();
    });
    let client = connect_h2(Box::new(client_io)).await.unwrap();
    let started = Instant::now();
    let mut body = client
        .send_fixed(
            request(Method::GET, "http://example.test/latency"),
            Bytes::new(),
        )
        .await
        .unwrap();
    let mut received = Vec::new();
    timeout(Duration::from_secs(30), body.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(received.len(), 2 * STREAM_WINDOW);
    assert!(received.iter().all(|byte| *byte == 0xa5));
    // A 64 KiB window needs well over ten seconds; leave ample margin for
    // handshake, WINDOW_UPDATE batching and the bounded simulated link.
    assert!(
        elapsed < Duration::from_secs(2),
        "8 MiB took {elapsed:?} at RTT 113 ms"
    );
    eprintln!("XHTTP/H2: 8 MiB at simulated RTT 113 ms in {elapsed:?}");
    drop(body);
    drop(client);
    peer.abort();
    for task in forward.into_iter().chain(backward) {
        task.abort();
    }
}
