use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Opens in-memory streams. Each writes its number into the stream, and the
/// fake keeps the other end to see the stream close.
#[derive(Default)]
struct Fake {
    attempts: Mutex<Vec<(Instant, Vec<SocketAddr>)>>,
    failures: AtomicUsize,
    opened: AtomicUsize,
    peers: Mutex<Vec<DuplexStream>>,
    /// The streams requests took, open for as long as the test runs.
    taken: Mutex<Vec<BoxedTransportStream>>,
    gone: AtomicBool,
}

#[async_trait]
impl Opener for Fake {
    async fn open(&self, spec: &DialSpec) -> Option<Result<BoxedTransportStream, CoreError>> {
        if self.gone.load(Ordering::SeqCst) {
            return None;
        }
        self.attempts
            .lock()
            .unwrap()
            .push((Instant::now(), spec.server.clone()));
        if self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Some(Err(io::Error::other("refused").into()));
        }
        let number = self.opened.fetch_add(1, Ordering::SeqCst);
        let (stream, mut peer) = tokio::io::duplex(64);
        // What one end writes, the other reads.
        peer.write_all(&[number as u8]).await.unwrap();
        self.peers.lock().unwrap().push(peer);
        Some(Ok(Box::new(stream)))
    }
}

impl Fake {
    fn opened(&self) -> usize {
        self.opened.load(Ordering::SeqCst)
    }

    /// Whether the `number`th stream was closed on our side.
    async fn closed(&self, number: usize) -> bool {
        let mut peer = self.peers.lock().unwrap().remove(number);
        let mut byte = [0];
        let closed = matches!(
            tokio::time::timeout(Duration::from_millis(1), peer.read(&mut byte)).await,
            Ok(Ok(0))
        );
        self.peers.lock().unwrap().insert(number, peer);
        closed
    }
}

fn spec(port: u16) -> DialSpec {
    DialSpec {
        server: vec![SocketAddr::from(([192, 0, 2, 1], port))],
        download: Vec::new(),
        dialer: TransportDialer::system().unwrap(),
    }
}

async fn take(pool: &PreConnections, fake: &Arc<Fake>, port: u16) -> Result<u8, CoreError> {
    let opener = Arc::clone(fake) as Arc<dyn Opener>;
    let mut stream = pool.take(spec(port), || opener).await?;
    let mut number = [0];
    stream.read_exact(&mut number).await.unwrap();
    // Keep the stream open, as a request using it would. The fake holds it
    // rather than `mem::forget`, so the test frees it when it ends.
    fake.taken.lock().unwrap().push(stream);
    Ok(number[0])
}

/// Lets spawned dialers run up to the paused clock's present.
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

#[test]
fn zero_keeps_none() {
    assert!(PreConnections::new(0).is_none());
}

#[tokio::test(start_paused = true)]
async fn nothing_is_opened_before_the_first_request() {
    let fake = Arc::new(Fake::default());
    let _pool = PreConnections::new(2).unwrap();
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(fake.opened(), 0);
}

/// Each dialer holds one connection until a request takes it, then pauses
/// 200 ms and opens the next.
#[tokio::test(start_paused = true)]
async fn each_dialer_keeps_one_connection_ready() {
    let fake = Arc::new(Fake::default());
    let pool = PreConnections::new(2).unwrap();
    assert!(take(&pool, &fake, 443).await.unwrap() < 2);
    settle().await;
    assert_eq!(fake.opened(), 2);
    tokio::time::sleep(Duration::from_millis(199)).await;
    settle().await;
    assert_eq!(fake.opened(), 2);
    tokio::time::sleep(Duration::from_millis(1)).await;
    settle().await;
    assert_eq!(fake.opened(), 3);
    // Nothing more while both are held.
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(fake.opened(), 3);
    // The next request takes a held one at once.
    let start = Instant::now();
    take(&pool, &fake, 443).await.unwrap();
    assert_eq!(start.elapsed(), Duration::ZERO);
}

/// A connection held two minutes closes when a request finds it, and the
/// request takes a newer one.
#[tokio::test(start_paused = true)]
async fn a_connection_held_two_minutes_is_closed_for_a_newer_one() {
    let fake = Arc::new(Fake::default());
    let pool = PreConnections::new(1).unwrap();
    assert_eq!(take(&pool, &fake, 443).await.unwrap(), 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    settle().await;
    assert_eq!(fake.opened(), 2);
    // Held 119.9 s, it is still taken.
    tokio::time::sleep(Duration::from_millis(119_900)).await;
    assert_eq!(take(&pool, &fake, 443).await.unwrap(), 1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    settle().await;
    assert_eq!(fake.opened(), 3);
    // Held 120 s, it is closed and the next one opened is taken.
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(take(&pool, &fake, 443).await.unwrap(), 3);
    assert!(fake.closed(2).await);
    assert!(!fake.closed(3).await);
}

/// A failed dial waits 200 ms, then twice as long each time, up to ten
/// seconds; a dial that opens starts over.
#[tokio::test(start_paused = true)]
async fn a_failed_dial_waits_longer_each_time() {
    let fake = Arc::new(Fake {
        failures: AtomicUsize::new(8),
        ..Fake::default()
    });
    let pool = PreConnections::new(1).unwrap();
    // Requests give up at 16 and 32 s; the ninth attempt, at 32.6 s, opens.
    let _ = take(&pool, &fake, 443).await;
    let _ = take(&pool, &fake, 443).await;
    assert_eq!(take(&pool, &fake, 443).await.unwrap(), 0);
    // The refill fails twice and starts from 200 ms again.
    fake.failures.store(2, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(1)).await;
    settle().await;
    let gaps: Vec<u64> = fake
        .attempts
        .lock()
        .unwrap()
        .windows(2)
        .map(|pair| (pair[1].0 - pair[0].0).as_millis() as u64)
        .collect();
    assert_eq!(
        gaps,
        [200, 400, 800, 1600, 3200, 6400, 10_000, 10_000, 200, 200, 400]
    );
    assert_eq!(fake.opened(), 2);
}

/// A request waits sixteen seconds for a connection; one that gives up
/// leaves the connection opened for it to the next request.
#[tokio::test(start_paused = true)]
async fn a_request_waits_sixteen_seconds_and_leaves_its_connection() {
    // Attempts at 0, 0.2, 0.6, 1.4, 3, 6.2 and 12.6 s fail; 22.6 s opens.
    let fake = Arc::new(Fake {
        failures: AtomicUsize::new(7),
        ..Fake::default()
    });
    let pool = PreConnections::new(1).unwrap();
    let start = Instant::now();
    let error = take(&pool, &fake, 443).await.unwrap_err();
    assert_eq!(start.elapsed(), Duration::from_secs(16));
    assert!(matches!(&error, CoreError::Io(error) if error.kind() == io::ErrorKind::TimedOut));
    tokio::time::sleep(Duration::from_secs(7)).await;
    settle().await;
    assert_eq!(fake.opened(), 1);
    let taken = Instant::now();
    assert_eq!(take(&pool, &fake, 443).await.unwrap(), 0);
    assert_eq!(taken.elapsed(), Duration::ZERO);
}

/// The next dial goes where the latest request says.
#[tokio::test(start_paused = true)]
async fn the_latest_request_names_the_next_dial() {
    let fake = Arc::new(Fake::default());
    let pool = PreConnections::new(1).unwrap();
    take(&pool, &fake, 1).await.unwrap();
    take(&pool, &fake, 2).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    settle().await;
    let ports: Vec<u16> = fake
        .attempts
        .lock()
        .unwrap()
        .iter()
        .map(|(_, server)| server[0].port())
        .collect();
    // The second request's port reached the dial after the first refill.
    assert_eq!(ports.first(), Some(&1));
    assert_eq!(ports.last(), Some(&2));
}

/// Closing stops the dialers, the one pausing before its next dial
/// included, and closes what they hold; requests then fail.
#[tokio::test(start_paused = true)]
async fn close_stops_the_dialers_and_closes_what_they_hold() {
    let fake = Arc::new(Fake::default());
    let pool = PreConnections::new(2).unwrap();
    // One dialer handed its connection over and pauses; the other holds.
    take(&pool, &fake, 443).await.unwrap();
    assert_eq!(fake.opened(), 2);
    pool.close();
    pool.join().await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(fake.opened(), 2);
    let mut closed = 0;
    for number in 0..2 {
        closed += usize::from(fake.closed(number).await);
    }
    // The held one closed; the taken one is the request's.
    assert_eq!(closed, 1);
    let error = take(&pool, &fake, 443).await.unwrap_err();
    assert!(matches!(&error, CoreError::Io(error) if error.kind() == io::ErrorKind::NotConnected));
}

/// Dialers end once the outbound is gone, and requests then fail at once.
#[tokio::test(start_paused = true)]
async fn the_outbound_gone_ends_the_dialers() {
    let fake = Arc::new(Fake::default());
    let pool = PreConnections::new(1).unwrap();
    take(&pool, &fake, 443).await.unwrap();
    fake.gone.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    settle().await;
    let start = Instant::now();
    let error = take(&pool, &fake, 443).await.unwrap_err();
    assert_eq!(start.elapsed(), Duration::ZERO);
    assert!(matches!(&error, CoreError::Io(error) if error.kind() == io::ErrorKind::NotConnected));
}

/// Dropping the outbound without closing it stops the dialers as well, the
/// one pausing before its next dial included.
#[tokio::test(start_paused = true)]
async fn dropping_the_pool_closes_what_it_holds() {
    let fake = Arc::new(Fake::default());
    let pool = PreConnections::new(2).unwrap();
    take(&pool, &fake, 443).await.unwrap();
    assert_eq!(fake.opened(), 2);
    drop(pool);
    settle().await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(fake.opened(), 2);
    let mut closed = 0;
    for number in 0..2 {
        closed += usize::from(fake.closed(number).await);
    }
    assert_eq!(closed, 1);
}
