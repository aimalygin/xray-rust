use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpStream;
use tokio::time::{sleep_until, Instant};

use crate::{canonicalize_socket_addr, connect_tcp_stream, SocketProtector, TransportError};

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
    /// The original order within IPv4 and IPv6 candidates is preserved. Xray-style
    /// IPv4-mapped IPv6 addresses are canonicalized to IPv4 before grouping.
    pub fn order_candidates(&self, candidates: &[SocketAddr]) -> Vec<SocketAddr> {
        let mut ipv4 = Vec::with_capacity(candidates.len());
        let mut ipv6 = Vec::with_capacity(candidates.len());

        for candidate in candidates {
            let candidate = canonicalize_socket_addr(*candidate);
            if candidate.is_ipv4() {
                ipv4.push(candidate);
            } else {
                ipv6.push(candidate);
            }
        }

        if ipv4.is_empty() || ipv6.is_empty() {
            ipv4.extend(ipv6);
            return ipv4;
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

/// [`connect_tcp_happy_eyeballs`], returning the address that connected.
pub(crate) async fn connect_tcp_happy_eyeballs_with_peer(
    candidates: &[SocketAddr],
    socket_protector: Option<&dyn SocketProtector>,
    config: &HappyEyeballsConfig,
) -> Result<(TcpStream, SocketAddr), TransportError> {
    race_candidates(candidates, config, |candidate| async move {
        let peer = canonicalize_socket_addr(candidate);
        Ok((connect_tcp_stream(peer, socket_protector).await?, peer))
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
    let mut next_launch_at = Instant::now().checked_add(config.try_delay);
    let mut last_error = None;

    loop {
        if attempts.is_empty() {
            return Err(last_error.unwrap_or_else(no_candidates_error));
        }

        let result = if next_index < ordered.len() && attempts.len() < max_concurrent {
            match next_launch_at {
                Some(deadline) => {
                    tokio::select! {
                        result = attempts.next() => result,
                        () = sleep_until(deadline) => {
                            attempts.push(connect(ordered[next_index]));
                            next_index += 1;
                            next_launch_at = Instant::now().checked_add(config.try_delay);
                            continue;
                        }
                    }
                }
                None => attempts.next().await,
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
            next_launch_at = Instant::now().checked_add(config.try_delay);
        }
    }
}

/// Go's `net.Dialer` defaults, which Xray-core dials with when `happyEyeballs`
/// is not configured: a 16-second dial timeout (`DefaultSystemDialer`) and a
/// 300 ms head start for the first address family.
const GO_DIAL_TIMEOUT: Duration = Duration::from_secs(16);
const GO_FALLBACK_DELAY: Duration = Duration::from_millis(300);
/// Go's `partialDeadline` gives each serial attempt at least this long.
const GO_MIN_ATTEMPT: Duration = Duration::from_secs(2);

/// Connects the way Go's `net.Dialer` does without `happyEyeballs`.
///
/// Candidates of the first address's family are tried one after another,
/// each with an even share of what remains of the 16-second budget but at
/// least two seconds. The other family starts 300 ms later, or as soon as the
/// first one has failed. The first connection wins; if both families fail, the
/// first family's first error is returned. A socket-protection failure stops
/// both at once.
pub async fn connect_tcp_dual_stack(
    candidates: &[SocketAddr],
    socket_protector: Option<&dyn SocketProtector>,
) -> Result<TcpStream, TransportError> {
    dial_dual_stack(candidates, |candidate| {
        connect_tcp_stream(candidate, socket_protector)
    })
    .await
}

/// [`connect_tcp_dual_stack`], returning the address that connected.
pub(crate) async fn connect_tcp_dual_stack_with_peer(
    candidates: &[SocketAddr],
    socket_protector: Option<&dyn SocketProtector>,
) -> Result<(TcpStream, SocketAddr), TransportError> {
    dial_dual_stack(candidates, |candidate| async move {
        let peer = canonicalize_socket_addr(candidate);
        Ok((connect_tcp_stream(peer, socket_protector).await?, peer))
    })
    .await
}

async fn dial_dual_stack<T, Connect, ConnectFuture>(
    candidates: &[SocketAddr],
    connect: Connect,
) -> Result<T, TransportError>
where
    Connect: Fn(SocketAddr) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<T, TransportError>>,
{
    let candidates: Vec<SocketAddr> = candidates
        .iter()
        .map(|candidate| canonicalize_socket_addr(*candidate))
        .collect();
    let Some(first) = candidates.first() else {
        return Err(no_candidates_error());
    };
    let (primaries, fallbacks): (Vec<_>, Vec<_>) = candidates
        .iter()
        .partition(|candidate| candidate.is_ipv4() == first.is_ipv4());
    let deadline = Instant::now() + GO_DIAL_TIMEOUT;

    let primary = dial_serial(&primaries, deadline, &connect);
    tokio::pin!(primary);
    if fallbacks.is_empty() {
        return primary.await;
    }
    // Go starts the fallbacks after the delay, or at once when the primaries
    // have failed; once started they run on even if that happens later.
    let (primary_failed, primary_failed_rx) = tokio::sync::oneshot::channel::<()>();
    let fallback = async {
        tokio::select! {
            () = tokio::time::sleep(GO_FALLBACK_DELAY) => {}
            _ = primary_failed_rx => {}
        }
        dial_serial(&fallbacks, deadline, &connect).await
    };
    tokio::pin!(fallback);

    tokio::select! {
        result = &mut primary => match result {
            Ok(stream) => Ok(stream),
            Err(error @ TransportError::SocketProtection(_)) => Err(error),
            Err(primary_error) => {
                let _ = primary_failed.send(());
                fallback
                    .await
                    .map_err(|fallback_error| keep_fatal(primary_error, fallback_error))
            }
        },
        result = &mut fallback => match result {
            Ok(stream) => Ok(stream),
            Err(error @ TransportError::SocketProtection(_)) => Err(error),
            Err(fallback_error) => primary
                .await
                .map_err(|primary_error| keep_fatal(primary_error, fallback_error)),
        },
    }
}

/// Go's `dialSerial`: each attempt gets `remaining / attempts_left`, but at
/// least two seconds unless the deadline is nearer.
async fn dial_serial<T, Connect, ConnectFuture>(
    candidates: &[SocketAddr],
    deadline: Instant,
    connect: &Connect,
) -> Result<T, TransportError>
where
    Connect: Fn(SocketAddr) -> ConnectFuture,
    ConnectFuture: Future<Output = Result<T, TransportError>>,
{
    let mut first_error = None;
    for (index, candidate) in candidates.iter().enumerate() {
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            break;
        }
        let share = remaining / u32::try_from(candidates.len() - index).unwrap_or(u32::MAX);
        let attempt = share.max(GO_MIN_ATTEMPT).min(remaining);
        let result = tokio::time::timeout(attempt, connect(*candidate))
            .await
            .unwrap_or_else(|_| {
                Err(TransportError::Tcp(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("TCP connect to {candidate} timed out"),
                )))
            });
        match result {
            Ok(stream) => return Ok(stream),
            Err(error @ TransportError::SocketProtection(_)) => return Err(error),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    Err(first_error.unwrap_or_else(|| {
        TransportError::Tcp(io::Error::new(
            io::ErrorKind::TimedOut,
            "TCP dial deadline passed",
        ))
    }))
}

/// Both families failed: report the primary's error, unless the fallback hit
/// a protection failure, which must not be hidden.
fn keep_fatal(primary: TransportError, fallback: TransportError) -> TransportError {
    match fallback {
        TransportError::SocketProtection(_) => fallback,
        _ => primary,
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
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};
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

    #[test]
    fn order_candidates_canonicalizes_ipv4_mapped_ipv6_like_xray() {
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            "::ffff:192.0.2.9".parse().expect("mapped IPv6 literal"),
            443,
            17,
            42,
        ));
        let native_v4 = ipv4(1);
        let native_v6 = ipv6(1);

        assert_eq!(
            config(false, 0, Duration::ZERO, 4).order_candidates(&[native_v6, mapped, native_v4]),
            [ipv4(9), native_v4, native_v6]
        );
    }

    #[tokio::test]
    async fn scheduler_dials_ipv4_mapped_ipv6_as_ipv4_like_xray() {
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            "::ffff:192.0.2.9".parse().expect("mapped IPv6 literal"),
            443,
            17,
            42,
        ));
        let canonical = ipv4(9);
        let connector = FakeConnector::new([(canonical, Behavior::immediate(Outcome::Success(9)))]);

        let result = race_candidates(&[mapped], &config(false, 1, Duration::ZERO, 1), {
            let connector = connector.clone();
            move |candidate| {
                let connector = connector.clone();
                async move { connector.connect(candidate).await }
            }
        })
        .await;

        assert_eq!(result.expect("mapped candidate succeeds"), 9);
        assert_eq!(connector.started(), [canonical]);
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
    async fn unrepresentable_try_deadline_does_not_panic_or_launch_early() {
        let first = ipv4(1);
        let second = ipv6(1);
        let connector = FakeConnector::new([
            (first, Behavior::immediate(Outcome::Pending)),
            (second, Behavior::immediate(Outcome::Success(2))),
        ]);
        let candidates = [first, second];
        let race_config = config(false, 1, Duration::MAX, 2);
        let mut race = Box::pin(race_candidates(&candidates, &race_config, {
            let connector = connector.clone();
            move |candidate| {
                let connector = connector.clone();
                async move { connector.connect(candidate).await }
            }
        }));

        assert!(race.as_mut().now_or_never().is_none());
        assert_eq!(connector.started(), [first]);

        drop(race);
        assert_eq!(connector.state.cancelled.load(Ordering::SeqCst), 1);
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

    /// When each candidate was tried and how it ends, for Go-style dialing.
    #[derive(Clone, Copy)]
    enum Dial {
        Hang,
        FailAfter(u64),
        SucceedAfter(u64),
        Unprotectable,
    }

    async fn go_dial(
        plan: &[(SocketAddr, Dial)],
    ) -> (Result<SocketAddr, TransportError>, Vec<(SocketAddr, u64)>) {
        let started = Arc::new(Mutex::new(Vec::new()));
        let epoch = Instant::now();
        let plan: HashMap<SocketAddr, Dial> = plan.iter().copied().collect();
        // Candidates are dialed in port order, so tests read top to bottom.
        let mut candidates: Vec<SocketAddr> = plan.keys().copied().collect();
        candidates.sort_by_key(SocketAddr::port);
        let log = Arc::clone(&started);
        let result = dial_dual_stack(&candidates, move |candidate| {
            let log = Arc::clone(&log);
            let dial = plan[&candidate];
            async move {
                let at = Instant::now().duration_since(epoch).as_millis() as u64;
                log.lock().unwrap().push((candidate, at));
                match dial {
                    Dial::Hang => pending().await,
                    Dial::FailAfter(ms) => {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        Err(TransportError::Tcp(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            candidate.to_string(),
                        )))
                    }
                    Dial::SucceedAfter(ms) => {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        Ok(candidate)
                    }
                    Dial::Unprotectable => Err(TransportError::SocketProtection(io::Error::other(
                        "protect failed",
                    ))),
                }
            }
        })
        .await;
        let started = started.lock().unwrap().clone();
        (result, started)
    }

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), port))
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), port))
    }

    #[tokio::test(start_paused = true)]
    async fn go_dialing_starts_the_other_family_300ms_later_or_when_the_first_fails() {
        let (result, started) =
            go_dial(&[(v6(1), Dial::Hang), (v4(2), Dial::SucceedAfter(0))]).await;
        assert_eq!(result.unwrap(), v4(2));
        assert_eq!(started, [(v6(1), 0), (v4(2), 300)]);

        let (result, started) =
            go_dial(&[(v6(1), Dial::FailAfter(50)), (v4(2), Dial::SucceedAfter(0))]).await;
        assert_eq!(result.unwrap(), v4(2));
        assert_eq!(started, [(v6(1), 0), (v4(2), 50)]);

        // The first family can still win after the other has started.
        let (result, _) = go_dial(&[(v4(1), Dial::SucceedAfter(400)), (v6(2), Dial::Hang)]).await;
        assert_eq!(result.unwrap(), v4(1));

        // A primary failure after the fallback started does not restart it.
        let (result, started) = go_dial(&[
            (v6(1), Dial::FailAfter(500)),
            (v4(2), Dial::SucceedAfter(400)),
        ])
        .await;
        assert_eq!(result.unwrap(), v4(2));
        assert_eq!(started, [(v6(1), 0), (v4(2), 300)]);
    }

    #[tokio::test(start_paused = true)]
    async fn go_dialing_tries_one_family_serially_with_even_shares_of_16_seconds() {
        let (result, started) = go_dial(&[
            (v4(1), Dial::Hang),
            (v4(2), Dial::FailAfter(1_000)),
            (v4(3), Dial::SucceedAfter(0)),
        ])
        .await;
        assert_eq!(result.unwrap(), v4(3));
        // 16 s / 3 (tokio rounds timers up to the next millisecond), then the
        // second attempt's failure starts the third early.
        assert_eq!(started, [(v4(1), 0), (v4(2), 5_334), (v4(3), 6_334)]);

        // Each attempt gets at least two seconds; the budget ends the rest.
        let plan: Vec<_> = (1..=10).map(|port| (v4(port), Dial::Hang)).collect();
        let (result, started) = go_dial(&plan).await;
        assert!(
            matches!(result, Err(TransportError::Tcp(error)) if error.kind() == io::ErrorKind::TimedOut)
        );
        let starts: Vec<u64> = started.iter().map(|(_, at)| *at).collect();
        assert_eq!(
            starts,
            [0, 2_000, 4_000, 6_000, 8_000, 10_000, 12_000, 14_000]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn go_dialing_reports_the_first_familys_error_and_stops_on_protection_failure() {
        let (result, _) =
            go_dial(&[(v6(1), Dial::FailAfter(10)), (v4(2), Dial::FailAfter(10))]).await;
        assert!(
            matches!(result, Err(TransportError::Tcp(error)) if error.to_string() == v6(1).to_string())
        );

        let (result, started) =
            go_dial(&[(v6(1), Dial::Unprotectable), (v4(2), Dial::SucceedAfter(0))]).await;
        assert!(matches!(result, Err(TransportError::SocketProtection(_))));
        assert_eq!(started, [(v6(1), 0)]);

        let (result, _) = go_dial(&[(v6(1), Dial::Hang), (v4(2), Dial::Unprotectable)]).await;
        assert!(matches!(result, Err(TransportError::SocketProtection(_))));
    }

    #[tokio::test]
    async fn connects_through_a_later_address_when_the_first_is_refused() {
        // Only IPv4 listens, so the IPv6 loopback refuses (or is unreachable).
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let candidates = [
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ];
        let (stream, accepted) = tokio::join!(
            connect_tcp_dual_stack(&candidates, None),
            tokio::time::timeout(Duration::from_secs(5), listener.accept()),
        );
        assert_eq!(stream.unwrap().peer_addr().unwrap(), candidates[1]);
        assert!(matches!(accepted, Ok(Ok(_))));
    }
}
