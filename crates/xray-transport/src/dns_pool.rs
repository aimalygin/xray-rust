//! Connections to encrypted DNS servers, kept between queries.
//!
//! One connection per server and route carries every query sent that way:
//! parallel HTTP/2 streams for DNS over HTTPS, one bidirectional QUIC stream
//! per query for DNS over QUIC. The pool is a map behind one lock that is
//! never held across an await; a per-key async lock lets one caller dial
//! while the others wait for its connection.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::Instant;

use crate::{NameServer, NetworkChanges};

/// How long an unused DNS-over-HTTPS connection is kept: Xray-core's
/// `IdleConnTimeout` for its DoH client.
pub(crate) const DNS_HTTPS_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Xray-core's `ReadIdleTimeout` for its DoH client: a connection that read
/// nothing for this long is probed with a PING and dropped if none returns.
pub(crate) const DNS_HTTPS_READ_IDLE: Duration = Duration::from_secs(45);
/// How long an unused DNS-over-QUIC connection lives: quic-go's default
/// `MaxIdleTimeout`, which Xray-core leaves in place.
pub(crate) const DNS_QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Connections one pool keeps; the least recently used one makes room.
pub(crate) const MAX_POOLED_DNS_CONNECTIONS: usize = 8;
/// How often kept connections are checked for idleness.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// A query abandoned after waiting this long takes its connection out of
/// the pool: nothing came back, so the next query should not wait on it too.
const STALLED_EXCHANGE: Duration = Duration::from_secs(2);
/// Bounds the attempts of one query whatever its dialer reports.
const MAX_EXCHANGE_ATTEMPTS: usize = 16;

/// What a kept DNS connection reaches and how it gets there. Queries share a
/// connection only when both match.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsConnectionKey {
    pub server: NameServer,
    pub route: DnsConnectionRoute,
}

/// The path a kept DNS connection was dialed through.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsConnectionRoute {
    /// Dialed directly, past configured routing.
    Local,
    /// Dialed through the outbound that routing picked for an inbound tag.
    Routed {
        inbound_tag: Option<String>,
        outbound_tag: Option<String>,
        /// The runtime identity of a `dns` outbound that takes the query.
        dns_outbound: Option<u64>,
    },
}

/// A connection that many queries can use at once through its clones. It
/// closes when its last clone is dropped.
pub(crate) trait DnsPooledConnection: Clone + Send + Sync + 'static {
    /// Whether new queries can still be sent on it.
    fn is_live(&self) -> bool;
}

/// Why one exchange on a connection failed.
pub(crate) struct DnsExchangeFailure {
    pub(crate) error: io::Error,
    /// No response arrived, so the query may go again on a fresh connection.
    retryable: bool,
}

impl DnsExchangeFailure {
    /// The connection failed before any response arrived.
    pub(crate) fn unanswered(error: io::Error) -> Self {
        Self {
            error,
            retryable: true,
        }
    }

    /// The server answered, or the query itself cannot be sent.
    pub(crate) fn rejected(error: io::Error) -> Self {
        Self {
            error,
            retryable: false,
        }
    }
}

/// One query and the way to reach its server.
#[async_trait]
pub(crate) trait DnsPooledExchange: Send + Sync {
    type Connection: DnsPooledConnection;

    /// Opens a fresh connection, passing over the `failed` server addresses.
    /// The address is `None` when the dialer cannot tell which one it
    /// reached; such a connection is not replaced by another candidate.
    async fn dial(
        &self,
        failed: &[SocketAddr],
    ) -> io::Result<(Self::Connection, Option<SocketAddr>)>;

    async fn exchange(&self, connection: &Self::Connection) -> Result<Vec<u8>, DnsExchangeFailure>;
}

pub(crate) struct DnsConnectionPool<C> {
    shared: Arc<Shared<C>>,
}

struct Shared<C> {
    state: Mutex<State<C>>,
    network_changes: NetworkChanges,
    idle_timeout: Duration,
    max_connections: usize,
}

struct State<C> {
    entries: HashMap<DnsConnectionKey, Entry<C>>,
    /// One lock per key that is being dialed or waited for.
    dialing: HashMap<DnsConnectionKey, Arc<tokio::sync::Mutex<()>>>,
    next_id: u64,
    /// Whether the idle sweep task is running.
    sweeping: bool,
}

struct Entry<C> {
    id: u64,
    connection: C,
    peer: Option<SocketAddr>,
    /// The network generation the dial started in.
    generation: u64,
    last_used: Instant,
}

impl<C: DnsPooledConnection> Entry<C> {
    fn is_usable(&self, now: Instant, generation: u64, idle_timeout: Duration) -> bool {
        self.generation == generation
            && now.saturating_duration_since(self.last_used) < idle_timeout
            && self.connection.is_live()
    }
}

struct Checkout<C> {
    connection: C,
    id: u64,
    peer: Option<SocketAddr>,
    /// Another query dialed it.
    reused: bool,
}

impl<C> Shared<C> {
    fn state(&self) -> MutexGuard<'_, State<C>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<C: DnsPooledConnection> DnsConnectionPool<C> {
    pub(crate) fn new(
        network_changes: NetworkChanges,
        idle_timeout: Duration,
        max_connections: usize,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    entries: HashMap::new(),
                    dialing: HashMap::new(),
                    next_id: 0,
                    sweeping: false,
                }),
                network_changes,
                idle_timeout,
                max_connections: max_connections.max(1),
            }),
        }
    }

    /// How many connections are kept right now.
    pub(crate) fn len(&self) -> usize {
        self.shared.state().entries.len()
    }

    /// The kept connection for `key`, unless it is closed, idle for too long
    /// or was dialed before the last network change.
    fn reuse(&self, key: &DnsConnectionKey) -> Option<Checkout<C>> {
        let now = Instant::now();
        let generation = self.shared.network_changes.generation();
        let mut state = self.shared.state();
        let entry = state.entries.get_mut(key)?;
        if entry.is_usable(now, generation, self.shared.idle_timeout) {
            entry.last_used = now;
            return Some(Checkout {
                connection: entry.connection.clone(),
                id: entry.id,
                peer: entry.peer,
                reused: true,
            });
        }
        let retired = state.entries.remove(key);
        drop(state);
        drop(retired);
        None
    }

    fn dial_lock(&self, key: &DnsConnectionKey) -> Arc<tokio::sync::Mutex<()>> {
        let mut state = self.shared.state();
        state.dialing.retain(|_, lock| Arc::strong_count(lock) > 1);
        Arc::clone(state.dialing.entry(key.clone()).or_default())
    }

    fn keep(
        &self,
        key: &DnsConnectionKey,
        connection: C,
        peer: Option<SocketAddr>,
        generation: u64,
    ) -> Checkout<C> {
        let mut retired = Vec::new();
        let mut state = self.shared.state();
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        retired.extend(state.entries.remove(key));
        while state.entries.len() >= self.shared.max_connections {
            let Some(oldest) = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            retired.extend(state.entries.remove(&oldest));
        }
        state.entries.insert(
            key.clone(),
            Entry {
                id,
                connection: connection.clone(),
                peer,
                generation,
                last_used: Instant::now(),
            },
        );
        if !state.sweeping {
            state.sweeping = true;
            tokio::spawn(sweep(
                Arc::downgrade(&self.shared),
                self.shared.idle_timeout.min(SWEEP_INTERVAL),
            ));
        }
        drop(state);
        drop(retired);
        Checkout {
            connection,
            id,
            peer,
            reused: false,
        }
    }

    /// Takes the connection out of the pool if it is still the kept one.
    /// Queries already on it finish; it closes with the last of them.
    fn discard(&self, key: &DnsConnectionKey, id: u64) {
        let mut state = self.shared.state();
        let retired = match state.entries.get(key) {
            Some(entry) if entry.id == id => state.entries.remove(key),
            Some(_) | None => None,
        };
        drop(state);
        drop(retired);
    }

    /// The kept connection, or a fresh one. Callers that find none dial one
    /// at a time per key, and those that waited take what the first dialed.
    async fn checkout<E>(
        &self,
        key: &DnsConnectionKey,
        exchange: &E,
        failed: &[SocketAddr],
    ) -> io::Result<Checkout<C>>
    where
        E: DnsPooledExchange<Connection = C>,
    {
        if let Some(kept) = self.reuse(key) {
            return Ok(kept);
        }
        let dialing = self.dial_lock(key);
        let _dialing = dialing.lock().await;
        if let Some(kept) = self.reuse(key) {
            return Ok(kept);
        }
        // Read before the dial: a change during it retires the connection.
        let generation = self.shared.network_changes.generation();
        let (connection, peer) = exchange.dial(failed).await?;
        Ok(self.keep(key, connection, peer, generation))
    }
}

/// Drops the connections that closed, sat idle or outlived a network change,
/// and ends once none is kept. Holds the pool weakly, so it ends with it.
async fn sweep<C: DnsPooledConnection>(shared: Weak<Shared<C>>, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let now = Instant::now();
        let generation = shared.network_changes.generation();
        let mut retired = Vec::new();
        let mut state = shared.state();
        let stale: Vec<DnsConnectionKey> = state
            .entries
            .iter()
            .filter(|(_, entry)| !entry.is_usable(now, generation, shared.idle_timeout))
            .map(|(key, _)| key.clone())
            .collect();
        for key in stale {
            retired.extend(state.entries.remove(&key));
        }
        state.dialing.retain(|_, lock| Arc::strong_count(lock) > 1);
        let finished = state.entries.is_empty();
        if finished {
            state.sweeping = false;
        }
        drop(state);
        drop(retired);
        if finished {
            return;
        }
    }
}

/// Retires a connection whose query was abandoned after a long wait.
struct RetireIfStalled<'a, C: DnsPooledConnection> {
    pool: &'a DnsConnectionPool<C>,
    key: &'a DnsConnectionKey,
    id: u64,
    started: Instant,
    /// Cleared once the exchange ran to its end, whatever it returned.
    abandoned: bool,
}

impl<C: DnsPooledConnection> Drop for RetireIfStalled<'_, C> {
    fn drop(&mut self) {
        if self.abandoned && self.started.elapsed() >= STALLED_EXCHANGE {
            self.pool.discard(self.key, self.id);
        }
    }
}

/// Sends one query on the kept connection for `key`, dialing it if needed.
///
/// A connection that fails a query leaves the pool. If another query dialed
/// it and no response arrived, the query goes once more on a fresh one. If
/// this query dialed it, the next server address is tried, as without a pool.
pub(crate) async fn exchange_pooled<E: DnsPooledExchange>(
    pool: &DnsConnectionPool<E::Connection>,
    key: &DnsConnectionKey,
    exchange: &E,
) -> io::Result<Vec<u8>> {
    let mut failed = Vec::new();
    let mut last_error = None;
    let mut retried = false;
    for _ in 0..MAX_EXCHANGE_ATTEMPTS {
        let checkout = match pool.checkout(key, exchange, &failed).await {
            Ok(checkout) => checkout,
            Err(error) => return Err(last_error.unwrap_or(error)),
        };
        let mut stalled = RetireIfStalled {
            pool,
            key,
            id: checkout.id,
            started: Instant::now(),
            abandoned: true,
        };
        let outcome = exchange.exchange(&checkout.connection).await;
        stalled.abandoned = false;
        drop(stalled);
        let failure = match outcome {
            Ok(response) => return Ok(response),
            Err(failure) => failure,
        };
        pool.discard(key, checkout.id);
        if checkout.reused {
            if !failure.retryable || retried {
                return Err(failure.error);
            }
            retried = true;
        } else if let Some(peer) = checkout.peer {
            failed.push(peer);
            last_error = Some(failure.error);
        } else {
            return Err(failure.error);
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("DNS exchange ran out of attempts")))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Clone)]
    struct TestConnection {
        number: usize,
        live: Arc<AtomicBool>,
    }

    impl DnsPooledConnection for TestConnection {
        fn is_live(&self) -> bool {
            self.live.load(Ordering::Relaxed)
        }
    }

    /// Answers with the number of the connection that carried the query.
    #[derive(Default)]
    struct TestExchange {
        dials: AtomicUsize,
        dial_delay: Duration,
        /// Connections with these numbers fail their queries unanswered.
        broken: Vec<usize>,
        stall: bool,
    }

    #[async_trait]
    impl DnsPooledExchange for TestExchange {
        type Connection = TestConnection;

        async fn dial(
            &self,
            _failed: &[SocketAddr],
        ) -> io::Result<(TestConnection, Option<SocketAddr>)> {
            tokio::time::sleep(self.dial_delay).await;
            let number = self.dials.fetch_add(1, Ordering::Relaxed);
            Ok((
                TestConnection {
                    number,
                    live: Arc::new(AtomicBool::new(true)),
                },
                None,
            ))
        }

        async fn exchange(
            &self,
            connection: &TestConnection,
        ) -> Result<Vec<u8>, DnsExchangeFailure> {
            if self.stall {
                std::future::pending::<()>().await;
            }
            if self.broken.contains(&connection.number) {
                return Err(DnsExchangeFailure::unanswered(io::Error::other("broken")));
            }
            Ok(vec![u8::try_from(connection.number).unwrap()])
        }
    }

    fn key(domain: &str) -> DnsConnectionKey {
        DnsConnectionKey {
            server: NameServer::Domain {
                domain: domain.to_owned(),
                port: 443,
            },
            route: DnsConnectionRoute::Local,
        }
    }

    fn pool(idle_timeout: Duration, max: usize) -> DnsConnectionPool<TestConnection> {
        DnsConnectionPool::new(NetworkChanges::default(), idle_timeout, max)
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_first_queries_share_one_dial() {
        let pool = pool(Duration::from_secs(300), 8);
        let exchange = TestExchange {
            dial_delay: Duration::from_millis(50),
            ..TestExchange::default()
        };
        let key = key("one.test");
        let queries = (0..16).map(|_| exchange_pooled(&pool, &key, &exchange));
        let answers = tokio::time::timeout(TEST_TIMEOUT, futures_util::future::join_all(queries))
            .await
            .expect("queries should finish");

        assert!(answers
            .iter()
            .all(|answer| answer.as_ref().unwrap() == &[0]));
        assert_eq!(exchange.dials.load(Ordering::Relaxed), 1);
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_connection_is_swept_and_redialed() {
        let pool = pool(Duration::from_secs(300), 8);
        let exchange = TestExchange::default();
        let key = key("idle.test");
        assert_eq!(exchange_pooled(&pool, &key, &exchange).await.unwrap(), [0]);
        tokio::time::sleep(Duration::from_secs(299)).await;
        assert_eq!(exchange_pooled(&pool, &key, &exchange).await.unwrap(), [0]);

        // The second query restarted the idle clock; the sweep closes the
        // connection with no further query to notice it.
        tokio::time::sleep(Duration::from_secs(331)).await;
        assert_eq!(pool.len(), 0);
        assert_eq!(exchange_pooled(&pool, &key, &exchange).await.unwrap(), [1]);
        assert_eq!(exchange.dials.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn network_change_retires_every_connection() {
        let changes = NetworkChanges::default();
        let pool = DnsConnectionPool::new(changes.clone(), Duration::from_secs(300), 8);
        let exchange = TestExchange::default();
        let (first, second) = (key("first.test"), key("second.test"));
        assert_eq!(
            exchange_pooled(&pool, &first, &exchange).await.unwrap(),
            [0]
        );
        assert_eq!(
            exchange_pooled(&pool, &second, &exchange).await.unwrap(),
            [1]
        );

        // The pool reads the generation and does not follow the signal, so
        // the count of connections asked to rebind stays what it was.
        assert_eq!(changes.notify(), 0);
        assert_eq!(
            exchange_pooled(&pool, &first, &exchange).await.unwrap(),
            [2]
        );
        tokio::time::sleep(SWEEP_INTERVAL * 2).await;
        assert_eq!(pool.len(), 1, "the sweep drops the other stale connection");
        assert_eq!(
            exchange_pooled(&pool, &second, &exchange).await.unwrap(),
            [3]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn closed_connection_is_replaced() {
        let pool = pool(Duration::from_secs(300), 8);
        let exchange = TestExchange::default();
        let key = key("closed.test");
        let first = pool.checkout(&key, &exchange, &[]).await.unwrap();
        first.connection.live.store(false, Ordering::Relaxed);

        assert_eq!(exchange_pooled(&pool, &key, &exchange).await.unwrap(), [1]);
    }

    #[tokio::test(start_paused = true)]
    async fn unanswered_query_on_a_reused_connection_goes_once_on_a_fresh_one() {
        let pool = pool(Duration::from_secs(300), 8);
        let key = key("retry.test");
        let exchange = TestExchange {
            broken: vec![0],
            ..TestExchange::default()
        };
        // Someone else dialed connection 0; this query only reuses it.
        pool.checkout(&key, &exchange, &[]).await.unwrap();
        assert_eq!(exchange_pooled(&pool, &key, &exchange).await.unwrap(), [1]);

        let exchange = TestExchange {
            broken: vec![0, 1],
            ..TestExchange::default()
        };
        let pool = self::pool(Duration::from_secs(300), 8);
        pool.checkout(&key, &exchange, &[]).await.unwrap();
        // The fresh connection fails too and has no other address to try.
        assert!(exchange_pooled(&pool, &key, &exchange).await.is_err());
        assert_eq!(exchange.dials.load(Ordering::Relaxed), 2);
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn pool_keeps_at_most_its_limit_and_drops_the_least_recently_used() {
        let pool = pool(Duration::from_secs(300), 2);
        let exchange = TestExchange::default();
        for domain in ["a.test", "b.test"] {
            exchange_pooled(&pool, &key(domain), &exchange)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        exchange_pooled(&pool, &key("a.test"), &exchange)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        exchange_pooled(&pool, &key("c.test"), &exchange)
            .await
            .unwrap();

        assert_eq!(pool.len(), 2);
        assert_eq!(exchange.dials.load(Ordering::Relaxed), 3);
        // `a.test` was used after `b.test`, so it is the one still kept.
        assert_eq!(
            exchange_pooled(&pool, &key("a.test"), &exchange)
                .await
                .unwrap(),
            [0]
        );
        assert_eq!(pool.shared.state().dialing.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn query_abandoned_after_a_long_wait_retires_its_connection() {
        let pool = pool(Duration::from_secs(300), 8);
        let key = key("stalled.test");
        let exchange = TestExchange {
            stall: true,
            ..TestExchange::default()
        };
        let quick = tokio::time::timeout(
            Duration::from_millis(100),
            exchange_pooled(&pool, &key, &exchange),
        );
        assert!(quick.await.is_err());
        assert_eq!(pool.len(), 1, "a query dropped early keeps the connection");

        let slow = tokio::time::timeout(
            STALLED_EXCHANGE * 2,
            exchange_pooled(&pool, &key, &exchange),
        );
        assert!(slow.await.is_err());
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_pool_closes_its_connections() {
        let pool = pool(Duration::from_secs(300), 8);
        let exchange = TestExchange::default();
        let checkout = pool
            .checkout(&key("drop.test"), &exchange, &[])
            .await
            .unwrap();
        let live = Arc::downgrade(&checkout.connection.live);
        drop(checkout);
        assert!(live.upgrade().is_some());

        drop(pool);

        assert!(live.upgrade().is_none());
    }
}
