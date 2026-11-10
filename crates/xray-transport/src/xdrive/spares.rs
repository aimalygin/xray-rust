//! Spare rings, as Xray-core v26.11.9's dial keeps them for Google Drive: a
//! session's slots take a request each to make, so up to two rings wait,
//! made ahead of time, for the next dials. A ring older than two thirds of
//! the session TTL is not taken, and one older than a third is replaced
//! when the spares are topped up. Topping up starts after every dial that
//! took slots and again a quarter TTL later, for as long as a dial came in
//! the last ten minutes; it makes one ring at a time, two seconds apart.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::time::Instant;

use super::names;
use super::params::Params;
use super::slots::{make_ring, Ring, SlotStore};
use super::storage::Storage;

/// `spareCount`.
const SPARE_COUNT: usize = 2;
/// `spareIdleStop`: no topping up once no dial came for this long.
const SPARE_IDLE_STOP: Duration = Duration::from_secs(10 * 60);
/// The pause before each spare is made, as Xray-core's forty 50 ms checks.
const SPARE_PACE: Duration = Duration::from_secs(2);
/// How long making the slots of a spare, or deleting a stale one, may take.
const SPARE_DEADLINE: Duration = Duration::from_secs(30);

/// A ring made ahead of time, with the storage of its session.
pub(crate) struct Spare {
    pub storage: Arc<dyn Storage>,
    pub slots: Arc<dyn SlotStore>,
    pub session: String,
    pub ring: Ring,
    made: Instant,
}

/// What opens the storage of a new session, for the spares made in the
/// background.
pub(crate) type OpenStorage = Arc<
    dyn Fn() -> futures_util::future::BoxFuture<
            'static,
            Option<(Arc<dyn Storage>, Arc<dyn SlotStore>)>,
        > + Send
        + Sync,
>;

/// `spareBox`: the spares of one outbound's transport.
pub(crate) struct SpareBox {
    spares: Mutex<VecDeque<Spare>>,
    busy: AtomicBool,
    last: Mutex<Instant>,
    params: Params,
}

impl SpareBox {
    pub(crate) fn new(params: Params) -> Arc<Self> {
        Arc::new(Self {
            spares: Mutex::new(VecDeque::new()),
            busy: AtomicBool::new(false),
            last: Mutex::new(Instant::now()),
            params,
        })
    }

    /// `takeSpare`: a spare young enough to use, the stale ones before it
    /// dropped.
    pub(crate) fn take(&self) -> Option<Spare> {
        let usable = self.params.session_ttl * 2 / 3;
        loop {
            let spare = self.spares.lock().unwrap().pop_front()?;
            if spare.made.elapsed() < usable {
                return Some(spare);
            }
            tokio::spawn(drop_spare(spare));
        }
    }

    /// `warmSpares`: a dial took slots; the spares are topped up.
    pub(crate) fn warm(self: &Arc<Self>, open: OpenStorage) {
        *self.last.lock().unwrap() = Instant::now();
        self.fill(open);
    }

    /// `fillSpares`: one topping up at a time, then another a quarter TTL
    /// later while dials keep coming.
    fn fill(self: &Arc<Self>, open: OpenStorage) {
        if self.busy.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(self);
        let params = self.params;
        tokio::spawn(async move {
            let topped = top_up(&weak, &open, &params).await;
            let Some(spares) = weak.upgrade() else {
                return;
            };
            spares.busy.store(false, Ordering::Release);
            if !topped {
                return;
            }
            drop(spares);
            tokio::time::sleep(params.session_ttl / 4).await;
            if let Some(spares) = weak.upgrade() {
                if spares.last.lock().unwrap().elapsed() < SPARE_IDLE_STOP {
                    spares.fill(open);
                }
            }
        });
    }

    #[cfg(test)]
    pub(crate) fn params(&self) -> Params {
        self.params
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.spares.lock().unwrap().len()
    }

    #[cfg(test)]
    pub(crate) fn push_made_at(&self, spare: Spare, made: Instant) {
        self.spares
            .lock()
            .unwrap()
            .push_back(Spare { made, ..spare });
    }
}

impl Drop for SpareBox {
    /// The outbound is gone: the spares nobody will take are deleted, which
    /// Xray-core, whose spares live as long as its process, never needs to.
    fn drop(&mut self) {
        let spares = std::mem::take(&mut *self.spares.lock().unwrap());
        if spares.is_empty() {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            for spare in spares {
                runtime.spawn(drop_spare(spare));
            }
        }
    }
}

impl Spare {
    pub(crate) fn new(
        storage: Arc<dyn Storage>,
        slots: Arc<dyn SlotStore>,
        session: String,
        ring: Ring,
    ) -> Self {
        Self {
            storage,
            slots,
            session,
            ring,
            made: Instant::now(),
        }
    }
}

/// Drops the spares older than a third of the TTL, then makes rings until
/// there are two. False when a ring could not be made, which ends the
/// topping up as in Xray-core.
async fn top_up(weak: &Weak<SpareBox>, open: &OpenStorage, params: &Params) -> bool {
    {
        let Some(spares) = weak.upgrade() else {
            return false;
        };
        let fresh = params.session_ttl / 3;
        let mut kept = VecDeque::new();
        let stale: Vec<Spare> = {
            let mut all = spares.spares.lock().unwrap();
            let mut stale = Vec::new();
            while let Some(spare) = all.pop_front() {
                if spare.made.elapsed() < fresh {
                    kept.push_back(spare);
                } else {
                    stale.push(spare);
                }
            }
            *all = kept;
            stale
        };
        for spare in stale {
            drop_spare(spare).await;
        }
    }
    loop {
        match weak.upgrade() {
            Some(spares) if spares.spares.lock().unwrap().len() < SPARE_COUNT => {}
            Some(_) => return true,
            None => return false,
        }
        tokio::time::sleep(SPARE_PACE).await;
        let Some((storage, slots)) = open().await else {
            return false;
        };
        let session = names::new_session_id();
        let made = tokio::time::timeout(SPARE_DEADLINE, make_ring(&slots, &session, params)).await;
        let ring = match made {
            Ok(Ok(ring)) => ring,
            _ => {
                drop_spare(Spare::new(storage, slots, session, Ring::default())).await;
                return false;
            }
        };
        let Some(spares) = weak.upgrade() else {
            drop_spare(Spare::new(storage, slots, session, ring)).await;
            return false;
        };
        let mut all = spares.spares.lock().unwrap();
        if all.len() >= SPARE_COUNT {
            return true;
        }
        all.push_back(Spare::new(storage, slots, session, ring));
    }
}

/// `dropSpare`: the session's objects deleted, within thirty seconds.
async fn drop_spare(spare: Spare) {
    let prefix = names::session_prefix(&spare.session);
    let _ = tokio::time::timeout(SPARE_DEADLINE, spare.storage.delete(&prefix)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdrive::slots::memory::MemorySlots;
    use crate::xdrive::storage::{Entry, StorageError};
    use crate::xdrive::XdriveTuning;
    use async_trait::async_trait;
    use bytes::Bytes;

    /// A storage that only records what was deleted.
    #[derive(Debug, Default)]
    struct Deletes(Mutex<Vec<String>>);

    #[async_trait]
    impl Storage for Deletes {
        async fn put(&self, _: &str, _: Bytes) -> Result<(), StorageError> {
            Ok(())
        }
        async fn get(&self, _: &str) -> Result<Bytes, StorageError> {
            Err(StorageError::NotFound)
        }
        async fn delete(&self, name: &str) -> Result<(), StorageError> {
            self.0.lock().unwrap().push(name.to_owned());
            Ok(())
        }
        async fn list(&self, _: &str) -> Result<Vec<Entry>, StorageError> {
            Ok(Vec::new())
        }
    }

    fn params() -> Params {
        Params::from_tuning(&XdriveTuning {
            session_ttl_seconds: 300,
            concurrency: 2,
            ..XdriveTuning::default()
        })
    }

    fn spare(deletes: &Arc<Deletes>, session: &str) -> Spare {
        Spare::new(
            Arc::clone(deletes) as Arc<dyn Storage>,
            Arc::new(MemorySlots::default()),
            session.to_owned(),
            Ring::default(),
        )
    }

    /// `TestTakeSpareSkipsStale` and `TestDropSpareDeletesSession`: a spare
    /// older than two thirds of the TTL is not taken but deleted, and the
    /// next one is taken.
    #[tokio::test(start_paused = true)]
    async fn stale_spares_are_not_taken_but_deleted() {
        let spares = SpareBox::new(params());
        let deletes = Arc::new(Deletes::default());
        let now = Instant::now();
        spares.push_made_at(spare(&deletes, "old"), now);
        tokio::time::advance(Duration::from_secs(201)).await;
        spares.push_made_at(spare(&deletes, "new"), Instant::now());
        let taken = spares.take().expect("the fresh spare");
        assert_eq!(taken.session, "new");
        assert_eq!(spares.len(), 0);
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(
            *deletes.0.lock().unwrap(),
            [names::session_prefix("old")],
            "the stale spare's session is deleted"
        );
    }

    /// Topping up makes rings until two wait, two seconds apart, and stops
    /// once the box is gone.
    #[tokio::test(start_paused = true)]
    async fn topping_up_makes_two_rings() {
        let spares = SpareBox::new(params());
        let deletes = Arc::new(Deletes::default());
        let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let open: OpenStorage = {
            let deletes = Arc::clone(&deletes);
            let opened = Arc::clone(&opened);
            Arc::new(move || {
                opened.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let storage = Arc::clone(&deletes) as Arc<dyn Storage>;
                let slots: Arc<dyn SlotStore> = Arc::new(MemorySlots::default());
                Box::pin(async move { Some((storage, slots)) })
            })
        };
        spares.warm(Arc::clone(&open));
        tokio::time::sleep(Duration::from_millis(1990)).await;
        assert_eq!(spares.len(), 0, "the first ring waits two seconds");
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(spares.len(), 2);
        assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 2);
        let taken = spares.take().unwrap();
        assert_eq!(taken.ring.up.slots.len(), 2);
        drop(spares);
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert_eq!(
            opened.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "nothing is made once the box is gone"
        );
        assert_eq!(
            deletes.0.lock().unwrap().len(),
            1,
            "the left spare is deleted"
        );
    }
}
