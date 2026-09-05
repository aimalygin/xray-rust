use crate::{crypto_error, CipherSuite, ClientConfig, EncryptedStream};
use std::{
    fmt, io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::Instant,
};
use zeroize::Zeroizing;

/// Persistent client for one server, user, key chain and outer security
/// identity. Clones share one bounded in-memory ticket; separate clients never
/// share session state. Do not reuse a client for a different endpoint.
#[derive(Clone)]
pub struct Client {
    pub(crate) config: ClientConfig,
    pub(crate) cache: Cache,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessEncryptionClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            cache: Cache::default(),
        }
    }

    /// Forget the ticket when the caller changes the remote security identity.
    /// Existing streams retain their own keys; late handshakes cannot refill
    /// a cache cleared after they began.
    pub fn clear_session_cache(&self) {
        self.cache.clear();
    }

    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> io::Result<EncryptedStream<S>> {
        self.connect_with_cipher(stream, CipherSuite::default())
            .await
    }

    pub async fn connect_with_cipher<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        suite: CipherSuite,
    ) -> io::Result<EncryptedStream<S>> {
        self.config
            .connect_cached(stream, suite, Some(&self.cache))
            .await
    }
}

#[derive(Clone, Default)]
pub(crate) struct Cache(Arc<Mutex<State>>);
#[derive(Default)]
struct State {
    epoch: Arc<()>,
    session: Option<Cached>,
}
struct Cached {
    pfs: Zeroizing<[u8; 64]>,
    ticket: Zeroizing<[u8; 16]>,
    expires: Instant,
    id: Arc<()>,
}

pub(crate) enum Prepared {
    Fresh(Arc<()>),
    Resume(Resumption),
}

pub(crate) struct Resumption {
    pub(crate) pfs: Zeroizing<[u8; 64]>,
    pub(crate) ticket: Zeroizing<[u8; 16]>,
    pub(crate) lease: Lease,
    pub(crate) expires: Instant,
}

impl Cache {
    pub(crate) fn prepare(&self) -> io::Result<Prepared> {
        let mut state = self.0.lock().map_err(|_| crypto_error())?;
        if state
            .session
            .as_ref()
            .is_some_and(|s| s.expires <= Instant::now())
        {
            state.session = None;
            state.epoch = Arc::new(());
        }
        Ok(match &state.session {
            Some(session) => Prepared::Resume(Resumption {
                pfs: session.pfs.clone(),
                ticket: session.ticket.clone(),
                lease: Lease {
                    cache: self.clone(),
                    id: Some(Arc::clone(&session.id)),
                },
                expires: session.expires,
            }),
            None => Prepared::Fresh(Arc::clone(&state.epoch)),
        })
    }

    fn clear(&self) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        state.session = None;
        state.epoch = Arc::new(());
    }
}

// A ticket is published only after authenticated peer padding is consumed.
// Concurrent cold handshakes can populate once; stale candidates cannot
// overwrite a newer ticket or undo explicit invalidation.
pub(crate) struct Candidate {
    cache: Cache,
    epoch: Arc<()>,
    session: Cached,
}
impl Candidate {
    pub(crate) fn new(
        cache: Cache,
        epoch: Arc<()>,
        pfs: Zeroizing<[u8; 64]>,
        ticket: [u8; 16],
        seconds: u16,
    ) -> Self {
        Self {
            cache,
            epoch,
            session: Cached {
                pfs,
                ticket: Zeroizing::new(ticket),
                expires: Instant::now() + Duration::from_secs(u64::from(seconds)),
                id: Arc::new(()),
            },
        }
    }
    pub(crate) fn publish(self) {
        let mut state = self.cache.0.lock().unwrap_or_else(|p| p.into_inner());
        if Arc::ptr_eq(&self.epoch, &state.epoch) && self.session.expires > Instant::now() {
            state.session = Some(self.session);
            state.epoch = Arc::new(());
        }
    }
}

// Retain identity, never a second cached PFS/ticket copy, while waiting for
// the first authenticated resumed record. Failure, cancellation and drop all
// invalidate only the session used by this connection.
pub(crate) struct Lease {
    cache: Cache,
    id: Option<Arc<()>>,
}
impl Lease {
    pub(crate) fn confirm(mut self) {
        self.id = None;
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        let mut state = self.cache.0.lock().unwrap_or_else(|p| p.into_inner());
        if state
            .session
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(&s.id, &id))
        {
            state.session = None;
            state.epoch = Arc::new(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publish(cache: &Cache, seconds: u16) {
        let Prepared::Fresh(epoch) = cache.prepare().unwrap() else {
            panic!("cache must be empty")
        };
        Candidate::new(
            cache.clone(),
            epoch,
            Zeroizing::new([7; 64]),
            [9; 16],
            seconds,
        )
        .publish();
    }

    #[tokio::test(start_paused = true)]
    async fn leases_expiry_and_explicit_clear_fail_closed() {
        let cache = Cache::default();
        publish(&cache, 10);

        let Prepared::Resume(confirmed) = cache.prepare().unwrap() else {
            panic!("ticket must be available")
        };
        confirmed.lease.confirm();
        let Prepared::Resume(still_available) = cache.prepare().unwrap() else {
            panic!("confirmed ticket must remain available")
        };
        still_available.lease.confirm();

        // Dropping an unconfirmed resumption consumes the cached ticket.
        let Prepared::Resume(unconfirmed) = cache.prepare().unwrap() else {
            panic!("ticket must be available")
        };
        drop(unconfirmed);
        assert!(matches!(cache.prepare().unwrap(), Prepared::Fresh(_)));

        publish(&cache, 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(matches!(cache.prepare().unwrap(), Prepared::Fresh(_)));

        // Explicit invalidation also prevents an older in-flight cold
        // handshake from publishing its candidate afterward.
        let Prepared::Fresh(epoch) = cache.prepare().unwrap() else {
            panic!("cache must be empty")
        };
        let stale = Candidate::new(cache.clone(), epoch, Zeroizing::new([3; 64]), [4; 16], 10);
        cache.clear();
        stale.publish();
        assert!(matches!(cache.prepare().unwrap(), Prepared::Fresh(_)));
    }
}
