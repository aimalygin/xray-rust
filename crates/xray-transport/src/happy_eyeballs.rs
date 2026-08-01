use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpStream;
use tokio::time::{sleep_until, Instant};

use crate::{connect_tcp_stream, SocketProtector, TransportError};

/// Controls raw TCP Happy Eyeballs candidate ordering and scheduling.
///
/// A zero `try_delay` starts successive attempts without an intentional gap.
/// Callers that use zero as a feature-off sentinel should skip the scheduler
/// instead of invoking it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HappyEyeballsConfig {
    /// Prefers IPv6 candidates when both address families are available.
    pub prioritize_ipv6: bool,
    /// Number of candidates consumed from one family before switching families.
    ///
    /// A zero value keeps consuming the preferred family until it is exhausted,
    /// matching Xray's `happyEyeballs.interleave` behavior.
    pub interleave: usize,
    /// Delay between attempts while an earlier attempt is still pending.
    pub try_delay: Duration,
    /// Maximum number of simultaneous raw TCP connect attempts.
    pub max_concurrent: NonZeroUsize,
}

impl Default for HappyEyeballsConfig {
    fn default() -> Self {
        let max_concurrent = match NonZeroUsize::new(4) {
            Some(value) => value,
            None => NonZeroUsize::MIN,
        };

        Self {
            prioritize_ipv6: false,
            interleave: 1,
            try_delay: Duration::ZERO,
            max_concurrent,
        }
    }
}

impl HappyEyeballsConfig {
    /// Returns candidates in stable, family-interleaved connection order.
    ///
    /// The original order within IPv4 and IPv6 candidates is preserved. When
    /// only one family is present, the input order is returned unchanged.
    pub fn order_candidates(&self, candidates: &[SocketAddr]) -> Vec<SocketAddr> {
        let mut ipv4 = Vec::with_capacity(candidates.len());
        let mut ipv6 = Vec::with_capacity(candidates.len());

        for candidate in candidates {
            if candidate.is_ipv4() {
                ipv4.push(*candidate);
            } else {
                ipv6.push(*candidate);
            }
        }

        if ipv4.is_empty() || ipv6.is_empty() {
            return candidates.to_vec();
        }

        let (preferred, alternate) = if self.prioritize_ipv6 {
            (&ipv6, &ipv4)
        } else {
            (&ipv4, &ipv6)
        };
        interleave_families(preferred, alternate, self.interleave)
    }
}

/// Connects to the first successful raw TCP candidate using Happy Eyeballs.
///
/// TCP failures immediately release a concurrency slot and accelerate the next
/// candidate instead of waiting for `try_delay`. A socket-protection failure is
/// fatal and stops the race. Returning from this function drops every losing
/// connect future, so no background connection attempts survive the call.
///
/// # Errors
///
/// Returns [`TransportError::SocketProtection`] immediately when a candidate
/// cannot be protected. If every TCP attempt fails, returns the most recently
/// completed TCP error. An empty candidate list returns a TCP `InvalidInput`
/// error.
pub async fn connect_tcp_happy_eyeballs(
    candidates: &[SocketAddr],
    socket_protector: Option<&dyn SocketProtector>,
    config: &HappyEyeballsConfig,
) -> Result<TcpStream, TransportError> {
    race_candidates(candidates, config, |candidate| {
        connect_tcp_stream(candidate, socket_protector)
    })
    .await
}

fn interleave_families(
    preferred: &[SocketAddr],
    alternate: &[SocketAddr],
    interleave: usize,
) -> Vec<SocketAddr> {
    let mut ordered = Vec::with_capacity(preferred.len() + alternate.len());
    if interleave == 0 {
        ordered.extend_from_slice(preferred);
        ordered.extend_from_slice(alternate);
        return ordered;
    }

    let mut preferred_index = 0;
    let mut alternate_index = 0;
    let chunk_size = interleave;
    let mut preferred_turn = true;

    while preferred_index < preferred.len() && alternate_index < alternate.len() {
        let (family, index) = if preferred_turn {
            (preferred, &mut preferred_index)
        } else {
            (alternate, &mut alternate_index)
        };
        let end = index.saturating_add(chunk_size).min(family.len());
        ordered.extend_from_slice(&family[*index..end]);
        *index = end;
        preferred_turn = !preferred_turn;
    }

    ordered.extend_from_slice(&preferred[preferred_index..]);
    ordered.extend_from_slice(&alternate[alternate_index..]);
    ordered
}

async fn race_candidates<T, Connect, ConnectFuture>(
    candidates: &[SocketAddr],
    config: &HappyEyeballsConfig,
    connect: Connect,
) -> Result<T, TransportError>
where
    Connect: Fn(SocketAddr) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<T, TransportError>>,
{
    let ordered = config.order_candidates(candidates);
    let Some(first) = ordered.first().copied() else {
        return Err(no_candidates_error());
    };

    let mut attempts = FuturesUnordered::new();
    attempts.push(connect(first));

    let max_concurrent = config.max_concurrent.get();
    let mut next_index = 1;
    let mut next_launch_at = Instant::now() + config.try_delay;
    let mut last_error = None;

    loop {
        if attempts.is_empty() {
            return Err(last_error.unwrap_or_else(no_candidates_error));
        }

        let result = if next_index < ordered.len() && attempts.len() < max_concurrent {
            tokio::select! {
                result = attempts.next() => result,
                () = sleep_until(next_launch_at) => {
                    attempts.push(connect(ordered[next_index]));
                    next_index += 1;
                    next_launch_at = Instant::now() + config.try_delay;
                    continue;
                }
            }
        } else {
            attempts.next().await
        };

        let Some(result) = result else {
            return Err(last_error.unwrap_or_else(no_candidates_error));
        };

        match result {
            Ok(stream) => return Ok(stream),
            Err(error @ TransportError::SocketProtection(_)) => return Err(error),
            Err(error) => last_error = Some(error),
        }

        if next_index < ordered.len() {
            attempts.push(connect(ordered[next_index]));
            next_index += 1;
            next_launch_at = Instant::now() + config.try_delay;
        }
    }
}

fn no_candidates_error() -> TransportError {
    TransportError::Tcp(io::Error::new(
        io::ErrorKind::InvalidInput,
        "happy eyeballs requires at least one TCP candidate",
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::future::pending;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use futures_util::FutureExt;
    use tokio::sync::Notify;
    use tokio::time::advance;

    use super::*;

    #[derive(Debug, Clone, Copy)]
    enum Outcome {
        Success(usize),
        TcpFailure(&'static str),
        ProtectionFailure,
        Pending,
    }

    #[derive(Debug, Clone)]
    struct Behavior {
        gate: Option<Arc<Notify>>,
        outcome: Outcome,
    }

    impl Behavior {
        fn immediate(outcome: Outcome) -> Self {
            Self {
                gate: None,
                outcome,
            }
        }

        fn gated(gate: Arc<Notify>, outcome: Outcome) -> Self {
            Self {
                gate: Some(gate),
                outcome,
            }
        }
    }

    #[derive(Debug, Default)]
    struct FakeState {
        started: Mutex<Vec<SocketAddr>>,
        active: AtomicUsize,
        max_active: AtomicUsize,
        cancelled: AtomicUsize,
    }

    #[derive(Debug, Clone)]
    struct FakeConnector {
        behaviors: Arc<HashMap<SocketAddr, Behavior>>,
        state: Arc<FakeState>,
    }

    impl FakeConnector {
        fn new(behaviors: impl IntoIterator<Item = (SocketAddr, Behavior)>) -> Self {
            Self {
                behaviors: Arc::new(behaviors.into_iter().collect()),
                state: Arc::new(FakeState::default()),
            }
        }

        async fn connect(&self, candidate: SocketAddr) -> Result<usize, TransportError> {
            self.state
                .started
                .lock()
                .expect("lock started attempts")
                .push(candidate);
            let active = self.state.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.state.max_active.fetch_max(active, Ordering::SeqCst);
            let mut guard = AttemptGuard::new(Arc::clone(&self.state));

            let behavior = self
                .behaviors
                .get(&candidate)
                .expect("candidate behavior")
                .clone();
            if let Some(gate) = behavior.gate {
                gate.notified().await;
            }

            let result = match behavior.outcome {
                Outcome::Success(value) => Ok(value),
                Outcome::TcpFailure(message) => Err(TransportError::Tcp(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    message,
                ))),
                Outcome::ProtectionFailure => Err(TransportError::SocketProtection(
                    io::Error::new(io::ErrorKind::PermissionDenied, "protect failed"),
                )),
                Outcome::Pending => pending().await,
            };
            guard.completed = true;
            result
        }

        fn started(&self) -> Vec<SocketAddr> {
            self.state
                .started
                .lock()
                .expect("lock started attempts")
                .clone()
        }
    }

    struct AttemptGuard {
        state: Arc<FakeState>,
        completed: bool,
    }

    impl AttemptGuard {
        fn new(state: Arc<FakeState>) -> Self {
            Self {
                state,
                completed: false,
            }
        }
    }

    impl Drop for AttemptGuard {
        fn drop(&mut self) {
            self.state.active.fetch_sub(1, Ordering::SeqCst);
            if !self.completed {
                self.state.cancelled.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn ipv4(last_octet: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, last_octet), 443))
    }

    fn ipv6(last_segment: u16) -> SocketAddr {
        SocketAddr::from((
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last_segment),
            443,
        ))
    }

    fn config(
        prioritize_ipv6: bool,
        interleave: usize,
        try_delay: Duration,
        max_concurrent: usize,
    ) -> HappyEyeballsConfig {
        HappyEyeballsConfig {
            prioritize_ipv6,
            interleave,
            try_delay,
            max_concurrent: NonZeroUsize::new(max_concurrent).expect("non-zero concurrency"),
        }
    }

    #[test]
    fn order_candidates_preserves_family_order_and_interleaves_chunks() {
        let v4_a = ipv4(1);
        let v6_a = ipv6(1);
        let v4_b = ipv4(2);
        let v6_b = ipv6(2);
        let v4_c = ipv4(3);
        let v6_c = ipv6(3);
        let candidates = [v6_a, v4_a, v6_b, v4_b, v6_c, v4_c];

        assert_eq!(
            config(false, 2, Duration::ZERO, 4).order_candidates(&candidates),
            [v4_a, v4_b, v6_a, v6_b, v4_c, v6_c]
        );
        assert_eq!(
            config(true, 1, Duration::ZERO, 4).order_candidates(&candidates),
            [v6_a, v4_a, v6_b, v4_b, v6_c, v4_c]
        );
        assert_eq!(
            config(false, 0, Duration::ZERO, 4).order_candidates(&candidates),
            [v4_a, v4_b, v4_c, v6_a, v6_b, v6_c]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_staggers_pending_attempts_until_try_delay() {
        let first = ipv4(1);
        let second = ipv6(1);
        let candidates = [first, second];
        let race_config = config(false, 1, Duration::from_millis(50), 2);
        let connector = FakeConnector::new([
            (first, Behavior::immediate(Outcome::Pending)),
            (second, Behavior::immediate(Outcome::Success(2))),
        ]);
        let race = race_candidates(&candidates, &race_config, {
            let connector = connector.clone();
            move |candidate| {
                let connector = connector.clone();
                async move { connector.connect(candidate).await }
            }
        });
        tokio::pin!(race);

        assert!(race.as_mut().now_or_never().is_none());
        assert_eq!(connector.started(), [first]);

        advance(Duration::from_millis(49)).await;
        assert!(race.as_mut().now_or_never().is_none());
        assert_eq!(connector.started(), [first]);

        advance(Duration::from_millis(1)).await;
        assert_eq!(race.await.expect("second candidate succeeds"), 2);
        assert_eq!(connector.started(), [first, second]);
    }

    #[tokio::test(start_paused = true)]
    async fn fast_tcp_failure_accelerates_next_candidate() {
        let first = ipv4(1);
        let second = ipv6(1);
        let connector = FakeConnector::new([
            (
                first,
                Behavior::immediate(Outcome::TcpFailure("first failed")),
            ),
            (second, Behavior::immediate(Outcome::Success(2))),
        ]);

        let result = race_candidates(
            &[first, second],
            &config(false, 1, Duration::from_secs(60), 2),
            {
                let connector = connector.clone();
                move |candidate| {
                    let connector = connector.clone();
                    async move { connector.connect(candidate).await }
                }
            },
        )
        .await;

        assert_eq!(result.expect("fallback candidate succeeds"), 2);
        assert_eq!(connector.started(), [first, second]);
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_never_exceeds_configured_concurrency() {
        let first = ipv4(1);
        let second = ipv6(1);
        let third = ipv4(2);
        let fourth = ipv6(2);
        let candidates = [first, second, third, fourth];
        let race_config = config(false, 1, Duration::ZERO, 2);
        let first_gate = Arc::new(Notify::new());
        let connector = FakeConnector::new([
            (
                first,
                Behavior::gated(Arc::clone(&first_gate), Outcome::TcpFailure("first failed")),
            ),
            (second, Behavior::immediate(Outcome::Pending)),
            (third, Behavior::immediate(Outcome::Success(3))),
            (fourth, Behavior::immediate(Outcome::Success(4))),
        ]);
        let race = race_candidates(&candidates, &race_config, {
            let connector = connector.clone();
            move |candidate| {
                let connector = connector.clone();
                async move { connector.connect(candidate).await }
            }
        });
        tokio::pin!(race);

        assert!(race.as_mut().now_or_never().is_none());
        assert_eq!(connector.started(), [first, second]);
        assert_eq!(connector.state.max_active.load(Ordering::SeqCst), 2);

        first_gate.notify_one();
        assert_eq!(race.await.expect("third candidate succeeds"), 3);
        assert_eq!(connector.started(), [first, second, third]);
        assert_eq!(connector.state.max_active.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn first_success_cancels_losing_connect_futures() {
        let first = ipv4(1);
        let second = ipv6(1);
        let candidates = [first, second];
        let race_config = config(false, 1, Duration::from_millis(10), 2);
        let connector = FakeConnector::new([
            (first, Behavior::immediate(Outcome::Pending)),
            (second, Behavior::immediate(Outcome::Success(2))),
        ]);

        let result = race_candidates(&candidates, &race_config, {
            let connector = connector.clone();
            move |candidate| {
                let connector = connector.clone();
                async move { connector.connect(candidate).await }
            }
        });
        tokio::pin!(result);
        assert!(result.as_mut().now_or_never().is_none());

        advance(Duration::from_millis(10)).await;
        assert_eq!(result.await.expect("second candidate wins"), 2);
        assert_eq!(connector.state.cancelled.load(Ordering::SeqCst), 1);
        assert_eq!(connector.state.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_outer_race_cancels_every_started_attempt() {
        let first = ipv4(1);
        let second = ipv6(1);
        let third = ipv4(2);
        let candidates = [first, second, third];
        let race_config = config(false, 1, Duration::ZERO, 2);
        let connector = FakeConnector::new([
            (first, Behavior::immediate(Outcome::Pending)),
            (second, Behavior::immediate(Outcome::Pending)),
            (third, Behavior::immediate(Outcome::Pending)),
        ]);
        let mut race = Box::pin(race_candidates(&candidates, &race_config, {
            let connector = connector.clone();
            move |candidate| {
                let connector = connector.clone();
                async move { connector.connect(candidate).await }
            }
        }));

        assert!(race.as_mut().now_or_never().is_none());
        assert_eq!(connector.started(), [first, second]);

        drop(race);
        assert_eq!(connector.state.cancelled.load(Ordering::SeqCst), 2);
        assert_eq!(connector.state.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn socket_protection_failure_is_fatal() {
        let first = ipv4(1);
        let second = ipv6(1);
        let connector = FakeConnector::new([
            (first, Behavior::immediate(Outcome::ProtectionFailure)),
            (second, Behavior::immediate(Outcome::Success(2))),
        ]);

        let error = race_candidates(
            &[first, second],
            &config(false, 1, Duration::from_secs(60), 2),
            {
                let connector = connector.clone();
                move |candidate| {
                    let connector = connector.clone();
                    async move { connector.connect(candidate).await }
                }
            },
        )
        .await
        .expect_err("protection failure must stop the race");

        assert!(matches!(error, TransportError::SocketProtection(_)));
        assert_eq!(connector.started(), [first]);
    }

    #[tokio::test]
    async fn all_tcp_failures_exhaust_every_candidate() {
        let first = ipv4(1);
        let second = ipv6(1);
        let third = ipv4(2);
        let connector = FakeConnector::new([
            (
                first,
                Behavior::immediate(Outcome::TcpFailure("first failed")),
            ),
            (
                second,
                Behavior::immediate(Outcome::TcpFailure("second failed")),
            ),
            (
                third,
                Behavior::immediate(Outcome::TcpFailure("third failed")),
            ),
        ]);

        let error = race_candidates(
            &[first, second, third],
            &config(false, 1, Duration::ZERO, 2),
            {
                let connector = connector.clone();
                move |candidate| {
                    let connector = connector.clone();
                    async move { connector.connect(candidate).await }
                }
            },
        )
        .await
        .expect_err("all candidates fail");

        assert!(matches!(error, TransportError::Tcp(_)));
        assert_eq!(connector.started(), [first, second, third]);
        assert_eq!(connector.state.active.load(Ordering::SeqCst), 0);
    }

    #[derive(Debug, Default)]
    struct CountingProtector {
        calls: AtomicUsize,
    }

    impl SocketProtector for CountingProtector {
        fn protect(&self, _socket: crate::SocketHandle) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn public_connector_falls_back_on_loopback_and_protects_each_socket() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind successful candidate");
        let success = listener.local_addr().expect("successful candidate address");
        let refused_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("reserve refused candidate");
        let refused = refused_listener
            .local_addr()
            .expect("refused candidate address");
        drop(refused_listener);

        let protector = CountingProtector::default();
        let stream = connect_tcp_happy_eyeballs(
            &[refused, success],
            Some(&protector),
            &config(false, 1, Duration::from_secs(60), 2),
        )
        .await
        .expect("fallback loopback candidate connects");

        assert!(stream.nodelay().expect("read TCP_NODELAY"));
        assert_eq!(protector.calls.load(Ordering::SeqCst), 2);
        listener.accept().await.expect("accept winning connection");
    }
}
