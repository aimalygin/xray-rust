//! What the HTTP storages of one outbound share, as Xray-core v26.10.31's
//! `connPool` and the token client of `drive.go` and `template.go` hold it:
//! the XMUX connections every session's requests go over, each a client of
//! its own, and a client apart for tokens, which no session's connection
//! carries.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
        self.inflight.fetch_add(1, Ordering::AcqRel);
        let result = self.client.send(request).await;
        if self.inflight.fetch_sub(1, Ordering::AcqRel) == 1 && self.closing.load(Ordering::Acquire)
        {
            self.client.close();
        }
        result
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
        client.conn.send(request).await
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
