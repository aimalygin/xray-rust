//! How XDRIVE's sessions share connections: Xray-core v26.10.31's
//! `XmuxManager` from `splithttp/mux.go`, with XDRIVE's `connPool`,
//! `poolConn` and `sessionTransport` from `client.go`. A session takes an
//! XMUX connection at its first request and keeps it until the connection
//! has no requests or time left; a connection retires once the manager
//! drops it and its requests end.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::Rng;
use tokio::time::Instant;

use crate::stream::{XhttpRange, XhttpXmuxPolicy};

/// Go's `crypto.RandBetween`: `from` when the bounds are equal or one apart,
/// else uniform in `[from, to)`, the bounds swapped when reversed.
pub(crate) fn rand_between(from: i64, to: i64) -> i64 {
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    if to - from <= 1 {
        return from;
    }
    rand::thread_rng().gen_range(from..to)
}

/// `RangeConfig.rand`.
fn draw(range: XhttpRange) -> i32 {
    rand_between(i64::from(range.from), i64::from(range.to)) as i32
}

/// One XMUX connection: its connections, and whether it still takes
/// sessions.
pub(crate) struct XmuxClient<C> {
    pub conn: C,
    /// Sessions on it.
    running: AtomicI32,
    /// Sessions it may still take; -1 for any number.
    left_usage: AtomicI32,
    /// Requests it may still carry.
    left_requests: AtomicI32,
    /// When it stops taking sessions and requests.
    unreusable_at: Option<Instant>,
    not_used: AtomicBool,
}

/// What an XMUX connection tells its manager.
pub(crate) trait XmuxConn {
    fn is_closed(&self) -> bool;
    fn close(&self);
}

impl<C: XmuxConn> XmuxClient<C> {
    fn add_running(&self) {
        self.running.fetch_add(1, Ordering::AcqRel);
    }

    fn done_running(&self) {
        self.running.fetch_sub(1, Ordering::AcqRel);
        self.maybe_close();
    }

    /// Closes the connection once it is dropped and nothing runs on it.
    fn maybe_close(&self) {
        if self.not_used.load(Ordering::Acquire) && self.running.load(Ordering::Acquire) <= 0 {
            self.conn.close();
        }
    }

    fn worn(&self, now: Instant) -> bool {
        self.left_requests.load(Ordering::Acquire) <= 0
            || self.unreusable_at.is_some_and(|at| now > at)
    }
}

/// `XmuxManager`.
pub(crate) struct XmuxManager<C> {
    policy: XhttpXmuxPolicy,
    concurrency: i32,
    connections: i32,
    new_conn: Box<dyn Fn() -> C + Send + Sync>,
    clients: Vec<Arc<XmuxClient<C>>>,
}

impl<C: XmuxConn> XmuxManager<C> {
    pub(crate) fn new(policy: XhttpXmuxPolicy, new_conn: Box<dyn Fn() -> C + Send + Sync>) -> Self {
        Self {
            policy,
            concurrency: draw(policy.max_concurrency),
            connections: draw(policy.max_connections),
            new_conn,
            clients: Vec::new(),
        }
    }

    fn new_client(&mut self) -> Arc<XmuxClient<C>> {
        let reuse = draw(self.policy.c_max_reuse_times);
        let requests = draw(self.policy.h_max_request_times);
        let secs = draw(self.policy.h_max_reusable_secs);
        let client = Arc::new(XmuxClient {
            conn: (self.new_conn)(),
            running: AtomicI32::new(0),
            left_usage: AtomicI32::new(if reuse > 0 { reuse - 1 } else { -1 }),
            left_requests: AtomicI32::new(if requests > 0 { requests } else { i32::MAX }),
            unreusable_at: (secs > 0)
                .then(|| Instant::now() + Duration::from_secs(u64::from(secs.unsigned_abs()))),
            not_used: AtomicBool::new(false),
        });
        self.clients.push(Arc::clone(&client));
        client
    }

    /// `GetXmuxClient`: drops the connections that are closed, used up or
    /// out of time, then opens one while fewer than `maxConnections` are
    /// open or every one runs `maxConcurrency` sessions, else picks one at
    /// random.
    pub(crate) fn get(&mut self) -> Arc<XmuxClient<C>> {
        let now = Instant::now();
        self.clients.retain(|client| {
            let drop = client.conn.is_closed()
                || client.left_usage.load(Ordering::Acquire) == 0
                || client.worn(now);
            if drop {
                client.not_used.store(true, Ordering::Release);
                client.maybe_close();
            }
            !drop
        });
        if self.clients.is_empty() {
            return self.new_client();
        }
        if self.connections > 0 && self.clients.len() < self.connections as usize {
            return self.new_client();
        }
        let candidates: Vec<Arc<XmuxClient<C>>> = if self.concurrency > 0 {
            self.clients
                .iter()
                .filter(|client| client.running.load(Ordering::Acquire) < self.concurrency)
                .cloned()
                .collect()
        } else {
            self.clients.clone()
        };
        if candidates.is_empty() {
            return self.new_client();
        }
        let client = Arc::clone(&candidates[rand::thread_rng().gen_range(0..candidates.len())]);
        let left = client.left_usage.load(Ordering::Acquire);
        if left > 0 {
            client.left_usage.store(left - 1, Ordering::Release);
        }
        client
    }
}

/// `stalledGrace`: a connection that has not answered yet is given this long
/// before its timeouts retire it, so that a dial or handshake is not cut
/// short again.
const STALLED_GRACE: Duration = Duration::from_secs(12);
/// Two timeouts this close together retire the connection.
const STALL_WINDOW: Duration = Duration::from_secs(3);
/// A session retires at most one connection this often.
const RETIRE_INTERVAL: Duration = Duration::from_secs(2);

/// `sessionTransport`: the XMUX connection one session's requests take, and
/// another once it has no requests or time left, or was retired for
/// stalling.
pub(crate) struct SessionLease<C: XmuxConn> {
    pool: Arc<Mutex<XmuxManager<C>>>,
    state: Mutex<LeaseState<C>>,
    closed: AtomicBool,
}

/// The connection a session holds and what its stalls left: `client`,
/// `slowAt`, `retiredAt`, `movedAt`, `takenAt` and `served`.
struct LeaseState<C> {
    current: Option<Arc<XmuxClient<C>>>,
    slow_at: Option<Instant>,
    retired_at: Option<Instant>,
    moved_at: Option<Instant>,
    taken_at: Option<Instant>,
    served: bool,
}

impl<C: XmuxConn> SessionLease<C> {
    pub(crate) fn new(pool: Arc<Mutex<XmuxManager<C>>>) -> Self {
        Self {
            pool,
            state: Mutex::new(LeaseState {
                current: None,
                slow_at: None,
                retired_at: None,
                moved_at: None,
                taken_at: None,
                served: false,
            }),
            closed: AtomicBool::new(false),
        }
    }

    /// The connection the next request goes over, or `None` once the
    /// session closed. A connection that closed, ran out of requests or of
    /// time gives way to the one XMUX hands out next.
    pub(crate) fn next(&self) -> Option<Arc<XmuxClient<C>>> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        let reuse = state.current.as_ref().filter(|client| {
            !client.conn.is_closed()
                && client.left_requests.fetch_sub(1, Ordering::AcqRel) > 0
                && client.unreusable_at.is_none_or(|at| Instant::now() <= at)
        });
        if let Some(client) = reuse {
            return Some(Arc::clone(client));
        }
        let next = self.pool.lock().unwrap().get();
        next.add_running();
        next.left_requests.fetch_sub(1, Ordering::AcqRel);
        let now = Instant::now();
        if let Some(previous) = state.current.replace(Arc::clone(&next)) {
            previous.done_running();
            state.moved_at = Some(now);
        }
        state.taken_at = Some(now);
        state.served = false;
        Some(next)
    }

    /// A request over `client` was answered.
    pub(crate) fn served(&self, client: &Arc<XmuxClient<C>>) {
        let mut state = self.state.lock().unwrap();
        if state
            .current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, client))
        {
            state.served = true;
        }
    }

    /// `stalled`: a request begun at `began` timed out. A second timeout
    /// within three seconds retires the connection -- at most one every two
    /// seconds, never for a request sent before the session last moved on,
    /// and never in the first twelve seconds of a connection that has not
    /// answered yet -- so that the next request takes another.
    pub(crate) fn stalled(&self, began: Instant) {
        let mut state = self.state.lock().unwrap();
        if state.moved_at.is_some_and(|moved| began < moved) {
            return;
        }
        let now = Instant::now();
        if !state.served
            && state
                .taken_at
                .is_some_and(|taken| now.duration_since(taken) < STALLED_GRACE)
        {
            return;
        }
        let slow = state
            .slow_at
            .is_some_and(|at| now.duration_since(at) < STALL_WINDOW);
        state.slow_at = Some(now);
        if !slow
            || state
                .retired_at
                .is_some_and(|at| now.duration_since(at) < RETIRE_INTERVAL)
        {
            return;
        }
        let Some(current) = state.current.clone() else {
            return;
        };
        state.retired_at = Some(now);
        current.conn.close();
    }

    /// `sessionTransport.Close`.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        if let Some(client) = self.state.lock().unwrap().current.take() {
            client.done_running();
        }
    }
}

impl<C: XmuxConn> Drop for SessionLease<C> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_cover_their_range_as_gos_do() {
        let draws: std::collections::HashSet<i64> =
            (0..400).map(|_| rand_between(1800, 3000)).collect();
        assert!(draws.iter().all(|d| (1800..3000).contains(d)));
        assert!(draws.len() > 100, "{} distinct draws", draws.len());
        assert_eq!(rand_between(5, 6), 5);
        assert_eq!(rand_between(7, 7), 7);
        assert!((3..9).contains(&rand_between(9, 3)));
    }
    use std::sync::atomic::AtomicUsize;

    #[derive(Default)]
    struct Conn {
        closed: AtomicBool,
    }

    impl XmuxConn for Arc<Conn> {
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::Acquire)
        }
        fn close(&self) {
            self.closed.store(true, Ordering::Release);
        }
    }

    fn policy(connections: i32, concurrency: i32, requests: i32) -> XhttpXmuxPolicy {
        XhttpXmuxPolicy {
            max_concurrency: XhttpRange {
                from: concurrency,
                to: concurrency,
            },
            max_connections: XhttpRange {
                from: connections,
                to: connections,
            },
            c_max_reuse_times: XhttpRange::default(),
            h_max_request_times: XhttpRange {
                from: requests,
                to: requests,
            },
            h_max_reusable_secs: XhttpRange::default(),
            h_keep_alive_period_secs: 0,
        }
    }

    fn manager(
        policy: XhttpXmuxPolicy,
        made: Arc<AtomicUsize>,
    ) -> Arc<Mutex<XmuxManager<Arc<Conn>>>> {
        Arc::new(Mutex::new(XmuxManager::new(
            policy,
            Box::new(move || {
                made.fetch_add(1, Ordering::SeqCst);
                Arc::new(Conn::default())
            }),
        )))
    }

    #[test]
    fn rand_between_follows_go() {
        assert_eq!(rand_between(5, 5), 5);
        assert_eq!(rand_between(5, 6), 5);
        assert_eq!(rand_between(6, 5), 5);
        for _ in 0..100 {
            let n = rand_between(10, 13);
            assert!((10..13).contains(&n));
        }
    }

    #[test]
    fn max_connections_opens_that_many_then_shares_them() {
        let made = Arc::new(AtomicUsize::new(0));
        let pool = manager(policy(2, 0, 0), Arc::clone(&made));
        let sessions: Vec<_> = (0..5)
            .map(|_| SessionLease::new(Arc::clone(&pool)))
            .collect();
        for session in &sessions {
            session.next().unwrap();
        }
        assert_eq!(made.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn max_concurrency_gives_each_session_its_own() {
        let made = Arc::new(AtomicUsize::new(0));
        let pool = manager(policy(0, 1, 0), Arc::clone(&made));
        let sessions: Vec<_> = (0..3)
            .map(|_| SessionLease::new(Arc::clone(&pool)))
            .collect();
        for session in &sessions {
            session.next().unwrap();
        }
        assert_eq!(made.load(Ordering::SeqCst), 3);
        // A closed session frees its connection for the next.
        sessions[0].close();
        let next = SessionLease::new(Arc::clone(&pool));
        next.next().unwrap();
        assert_eq!(made.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn a_session_moves_on_once_its_requests_are_spent() {
        let made = Arc::new(AtomicUsize::new(0));
        let pool = manager(policy(1, 0, 2), Arc::clone(&made));
        let session = SessionLease::new(Arc::clone(&pool));
        let first = session.next().unwrap();
        let again = session.next().unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        let third = session.next().unwrap();
        assert!(!Arc::ptr_eq(&first, &third));
        assert_eq!(made.load(Ordering::SeqCst), 2);
        // The spent connection closes once nothing runs on it.
        assert!(first.conn.is_closed());
        session.close();
        assert!(session.next().is_none());
    }

    /// `TestSessionRetiresStalledConn`: a second timeout within three
    /// seconds retires a connection that has answered, and the next request
    /// takes another.
    #[tokio::test(start_paused = true)]
    async fn a_session_retires_a_connection_that_stalls_twice() {
        let made = Arc::new(AtomicUsize::new(0));
        let lease = SessionLease::new(manager(policy(0, 1, 0), Arc::clone(&made)));
        let first = lease.next().unwrap();
        lease.served(&first);
        let began = Instant::now();
        tokio::time::advance(Duration::from_secs(1)).await;
        lease.stalled(began);
        assert!(!first.conn.is_closed(), "one timeout retires nothing");
        tokio::time::advance(Duration::from_secs(1)).await;
        lease.stalled(began);
        assert!(first.conn.is_closed(), "a second within 3 s retires it");
        let next = lease.next().unwrap();
        assert!(!Arc::ptr_eq(&first, &next));
        assert_eq!(made.load(Ordering::SeqCst), 2);
    }

    /// `TestSessionIgnoresStallOfRetiredConn` and
    /// `TestSessionSparesFreshConn`: a timeout of a request sent before the
    /// session moved on, or of a connection that has not answered in its
    /// first twelve seconds, retires nothing.
    #[tokio::test(start_paused = true)]
    async fn stale_stalls_and_fresh_connections_are_spared() {
        let made = Arc::new(AtomicUsize::new(0));
        let lease = SessionLease::new(manager(policy(0, 1, 0), Arc::clone(&made)));
        let fresh = lease.next().unwrap();
        let began = Instant::now();
        tokio::time::advance(Duration::from_secs(1)).await;
        lease.stalled(began);
        lease.stalled(began);
        assert!(!fresh.conn.is_closed(), "a fresh connection is spared");
        tokio::time::advance(Duration::from_secs(12)).await;
        lease.stalled(Instant::now());
        lease.stalled(Instant::now());
        assert!(fresh.conn.is_closed(), "past the grace it is retired");
        let before_move = Instant::now();
        tokio::time::advance(Duration::from_secs(1)).await;
        let next = lease.next().unwrap();
        lease.served(&next);
        tokio::time::advance(Duration::from_secs(3)).await;
        lease.stalled(before_move);
        lease.stalled(before_move);
        assert!(
            !next.conn.is_closed(),
            "a stall from before the move counts not"
        );
    }
}
