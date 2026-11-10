//! What the HTTP storages of one outbound share, as Xray-core v26.11.9's
//! `connPool` and the token client of `drive.go` and `template.go` hold it:
//! the XMUX connections every session's requests go over, each a client of
//! its own, and a client apart for tokens, which no session's connection
//! carries.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use super::client::{
    Http1Hosts, ServiceClient, ServiceDialer, ServiceError, ServiceRequest, ServiceResponse,
};
use super::redirect::{follow, Followed};
use super::xmux::{SessionLease, XmuxConn, XmuxManager};
use crate::stream::XhttpXmuxPolicy;

/// `poolConn`: an XMUX connection, which closes once XMUX drops it and the
/// requests on it end.
pub(crate) struct PoolConn {
    client: ServiceClient,
    inflight: AtomicUsize,
    closing: AtomicBool,
}

impl XmuxConn for Arc<PoolConn> {
    fn is_closed(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    fn close(&self) {
        self.closing.store(true, Ordering::Release);
        if self.inflight.load(Ordering::Acquire) == 0 {
            self.client.close();
        }
    }
}

impl PoolConn {
    async fn send(&self, request: &ServiceRequest) -> Result<ServiceResponse, ServiceError> {
        // A request given up on (a try's timeout drops it) still counts down,
        // or a retired connection would never close.
        struct Inflight<'a>(&'a PoolConn);
        impl Drop for Inflight<'_> {
            fn drop(&mut self) {
                let conn = self.0;
                if conn.inflight.fetch_sub(1, Ordering::AcqRel) == 1
                    && conn.closing.load(Ordering::Acquire)
                {
                    conn.client.close();
                }
            }
        }
        self.inflight.fetch_add(1, Ordering::AcqRel);
        let _inflight = Inflight(self);
        self.client.send(request).await
    }
}

/// The connections of one outbound's storage.
pub(crate) struct HttpShared {
    pool: Arc<Mutex<XmuxManager<Arc<PoolConn>>>>,
    token: ServiceClient,
}

impl std::fmt::Debug for HttpShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpShared").finish_non_exhaustive()
    }
}

impl HttpShared {
    /// `max_conns` is how many HTTP/1.1 connections a host takes.
    pub(crate) fn new(dialer: ServiceDialer, xmux: XhttpXmuxPolicy, max_conns: usize) -> Self {
        let dialer = Arc::new(dialer);
        let http1_hosts: Http1Hosts = Arc::default();
        let token = ServiceClient::new(Arc::clone(&dialer), Arc::clone(&http1_hosts), max_conns);
        let pool = XmuxManager::new(
            xmux,
            Box::new(move || {
                Arc::new(PoolConn {
                    client: ServiceClient::new(
                        Arc::clone(&dialer),
                        Arc::clone(&http1_hosts),
                        max_conns,
                    ),
                    inflight: AtomicUsize::new(0),
                    closing: AtomicBool::new(false),
                })
            }),
        );
        Self {
            pool: Arc::new(Mutex::new(pool)),
            token,
        }
    }

    /// The connections one session's requests take, until it is dropped.
    pub(crate) fn session(&self) -> SessionHttp {
        SessionHttp {
            lease: SessionLease::new(Arc::clone(&self.pool)),
        }
    }

    /// A request for a token, over a connection no session uses, its
    /// redirects followed.
    pub(crate) async fn send_token(
        &self,
        request: Followed,
    ) -> Result<ServiceResponse, ServiceError> {
        follow(request, |hop| async move { self.token.send(&hop).await }).await
    }
}

/// `sessionTransport`: one session's requests over XMUX.
pub(crate) struct SessionHttp {
    lease: SessionLease<Arc<PoolConn>>,
}

impl std::fmt::Debug for SessionHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHttp").finish_non_exhaustive()
    }
}

impl SessionHttp {
    pub(crate) async fn send(
        &self,
        request: &ServiceRequest,
    ) -> Result<ServiceResponse, ServiceError> {
        let Some(client) = self.lease.next() else {
            return Err(ServiceError::Request("the session is closed".to_owned()));
        };
        let answer = client.conn.send(request).await;
        if answer.is_ok() {
            self.lease.served(&client);
        }
        answer
    }

    /// A request begun at `began` timed out; see [`SessionLease::stalled`].
    pub(crate) fn stalled(&self, began: Instant) {
        self.lease.stalled(began);
    }

    /// A request and the redirects its answers give, each hop over the
    /// connection the session holds then.
    pub(crate) async fn send_following(
        &self,
        request: Followed,
    ) -> Result<ServiceResponse, ServiceError> {
        follow(request, |hop| async move { self.send(&hop).await }).await
    }
}

/// When a token handed out at `now` for `lifetime` seconds runs out, as
/// `time.Now().Add(time.Duration(lifetime) * time.Second)` in `drive.go` and
/// `template.go` puts it: the product wraps as Go's `int64` does, so a
/// lifetime past 292 years lands somewhere else, perhaps in the past,
/// where `Instant + Duration` would panic. An expiry `Instant` can't hold
/// (none within 292 years on the platforms here) counts as now: the token
/// is fetched again on its next use.
pub(crate) fn token_expiry(now: Instant, lifetime: i64) -> Instant {
    let nanos = lifetime.wrapping_mul(1_000_000_000);
    let span = Duration::from_nanos(nanos.unsigned_abs());
    if nanos >= 0 {
        now.checked_add(span)
    } else {
        now.checked_sub(span)
    }
    .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_lifetimes_wrap_as_go_multiplies_them() {
        let now = Instant::now();
        let before = |seconds| now.checked_sub(Duration::from_secs(seconds)).unwrap_or(now);
        assert_eq!(token_expiry(now, 3540), now + Duration::from_secs(3540));
        assert_eq!(token_expiry(now, 0), now);
        assert_eq!(token_expiry(now, -5), before(5));
        // (2^63 - 61) × 10^9 is -61 × 10^9 in int64: a lifetime of 1e300,
        // saturated as arm64 converts it and less the minute's margin, ran
        // out a minute ago.
        assert_eq!(token_expiry(now, i64::MAX - 60), before(61));
        assert_eq!(token_expiry(now, i64::MAX), before(1));
        assert_eq!(token_expiry(now, i64::MIN), now);
        // 9223372037 seconds is past the int64 nanoseconds Go holds and
        // wraps to 292 years ago.
        assert!(token_expiry(now, 9_223_372_037) <= now);
    }
}
