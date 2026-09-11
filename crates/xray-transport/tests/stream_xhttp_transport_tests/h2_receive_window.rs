use super::*;
use std::future::poll_fn;

pub(super) fn with_window(base: XhttpTransport, window: u32) -> XhttpTransport {
    let mut config = base.config().clone();
    config.h2_stream_receive_window = window;
    XhttpTransport::new(
        config,
        base.endpoint().clone(),
        base.http_version(),
        unlimited_xmux(),
    )
    .unwrap()
    .with_rng(Box::new(StepRng::new(0x0102_0304_0506_0708, 1)))
    .unwrap()
    .with_clock(Arc::new(Instant::now))
    .unwrap()
}

#[tokio::test]
async fn configured_window_reaches_all_h2_modes_reused_and_reopened_connections() {
    // Below h2's separate 400 KiB default send-buffer cap, so the grant
    // observes stream receive credit rather than local sender buffering.
    const WINDOW: u32 = 128 * 1024;
    for mode in [
        XhttpModeSelection::PacketUp,
        XhttpModeSelection::StreamUp,
        XhttpModeSelection::StreamOne,
    ] {
        let epoch = Instant::now();
        let seconds = Arc::new(AtomicU64::new(0));
        let clock_seconds = Arc::clone(&seconds);
        let clock: XhttpClock =
            Arc::new(move || epoch + Duration::from_secs(clock_seconds.load(Ordering::Acquire)));
        let transport = with_window(
            transport(mode, XhttpHttpVersion::Http2, unlimited_xmux(), 5),
            WINDOW,
        )
        .with_h2_idle_timeout(Duration::from_secs(1))
        .unwrap()
        .with_clock(clock)
        .unwrap();
        let dials = Arc::new(AtomicUsize::new(0));
        let (observed, mut windows) = mpsc::unbounded_channel();
        let dial = h2_dial(Arc::clone(&dials), move |request, mut respond| {
            let observed = observed.clone();
            async move {
                let mut send = respond.send_response(ok_response(), false).unwrap();
                send.reserve_capacity(WINDOW as usize + 1);
                let capacity = poll_fn(|cx| send.poll_capacity(cx)).await.unwrap().unwrap();
                let _ = observed.send(capacity);
                send.send_data(Bytes::from_static(b"ok"), true).unwrap();
                drain_h2_request(request.into_body()).await;
            }
        });
        for iteration in 0..3 {
            timeout(DEADLINE, async {
                let mut stream = transport
                    .open_stream_with_dial(Arc::clone(&dial))
                    .await
                    .unwrap();
                stream.write_all(b"ping").await.unwrap();
                stream.shutdown().await.unwrap();
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                assert_eq!(data, b"ok");
                drop(stream);
                while transport
                    .h2_connection_activity_counts()
                    .await
                    .iter()
                    .any(|n| *n != 0)
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("flow and pool reservations must finish");
            assert_eq!(
                dials.load(Ordering::Acquire),
                if iteration < 2 { 1 } else { 2 },
                "{mode:?}"
            );
            assert_eq!(windows.recv().await.unwrap(), WINDOW as usize);
            while let Ok(window) = windows.try_recv() {
                assert_eq!(window, WINDOW as usize);
            }
            if iteration == 1 {
                seconds.store(2, Ordering::Release);
            }
        }
    }
}
