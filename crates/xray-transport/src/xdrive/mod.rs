//! XDRIVE: one connection carried as objects in a storage both ends reach,
//! the client side of Xray-core v26.10.31's `transport/internet/xdrive`.
//!
//! A client announces a session with an object under `sessions/`, then
//! writes its direction as numbered segments under `streams/<id>/c2s` and
//! reads the server's under `streams/<id>/s2c`; a direction ends with an
//! `.end` object and fails with an `.err` one. Each end deletes what it
//! read. Nothing here listens: Xray-core's server accepts the sessions.
//!
//! The `local` service keeps the objects as files in a folder.

mod local;
mod names;
#[cfg(test)]
mod oracle_tests;
mod params;
mod storage;
mod stream;
#[cfg(test)]
mod tests;
mod wal;

use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;

pub use params::XdriveTuning;

use local::LocalStorage;
use params::Params;
use storage::{Storage, StorageError};
use stream::XdriveStream;

use crate::{BoxedTransportStream, TransportError};

/// The storage an XDRIVE outbound keeps its sessions in.
#[derive(Clone, PartialEq, Eq)]
pub enum XdriveStorageConfig {
    /// `local`: files under `folder`, made when a session opens if missing.
    Local { folder: String },
}

impl fmt::Debug for XdriveStorageConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local { folder } => f.debug_struct("Local").field("folder", folder).finish(),
        }
    }
}

/// An XDRIVE outbound's storage and tuning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XdriveConfig {
    pub storage: XdriveStorageConfig,
    pub tuning: XdriveTuning,
}

/// Opens XDRIVE sessions: each stream is a session of its own.
#[derive(Clone)]
pub struct XdriveTransport {
    storage: Arc<XdriveStorageConfig>,
    params: Params,
}

impl fmt::Debug for XdriveTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XdriveTransport")
            .field("storage", &self.storage)
            .field("params", &self.params)
            .finish()
    }
}

impl XdriveTransport {
    pub fn new(config: XdriveConfig) -> Self {
        Self {
            params: Params::from_tuning(&config.tuning),
            storage: Arc::new(config.storage),
        }
    }

    /// Xray-core's `Dial`: announces a new session and returns it as a
    /// stream. The server address of the outbound plays no part: the storage
    /// is where both ends meet.
    pub async fn open_stream(&self) -> Result<BoxedTransportStream, TransportError> {
        let storage = self.open_storage().await?;
        let session = names::new_session_id();
        storage
            .put(
                &names::announce_name(&session, SystemTime::now()),
                Bytes::new(),
            )
            .await
            .map_err(|error| {
                TransportError::Xdrive(format!("failed to announce session {session} > {error}"))
            })?;
        Ok(Box::new(XdriveStream::new(
            storage,
            names::uplink_prefix(&session),
            names::downlink_prefix(&session),
            self.params,
        )))
    }

    async fn open_storage(&self) -> Result<Arc<dyn Storage>, TransportError> {
        match self.storage.as_ref() {
            XdriveStorageConfig::Local { folder } => Ok(Arc::new(
                LocalStorage::open(folder).await.map_err(storage_error)?,
            )),
        }
    }
}

fn storage_error(error: StorageError) -> TransportError {
    TransportError::Xdrive(error.to_string())
}

/// Test scaffolding, not API: the far end of a session, the way Xray-core's
/// listener takes one, for tests that run both ends in one process.
#[doc(hidden)]
pub mod test_only {
    use super::*;

    /// `parseEntry`'s number of an entry name, when it has one.
    pub fn entry_seq(name: &str) -> Option<i64> {
        super::names::parse_entry(name).map(|(seq, _)| seq)
    }

    /// `objectName`.
    pub fn object_name(prefix: &str, seq: i64, suffix: &str) -> String {
        super::names::object_name(prefix, seq, suffix)
    }

    /// Takes the oldest announced session in `folder`, deletes its
    /// announcement and returns its server end, or `None` when nothing is
    /// announced.
    pub async fn accept_local(
        folder: &str,
        tuning: XdriveTuning,
    ) -> Result<Option<BoxedTransportStream>, TransportError> {
        let storage: Arc<dyn Storage> =
            Arc::new(LocalStorage::open(folder).await.map_err(storage_error)?);
        let listed = storage
            .list(names::SESSIONS_DIR)
            .await
            .map_err(storage_error)?;
        let Some(entry) = listed.into_iter().find(|entry| entry.name.contains('-')) else {
            return Ok(None);
        };
        let (_, session) = entry.name.split_once('-').expect("a dash");
        let session = session.to_owned();
        storage
            .delete(&format!("{}/{}", names::SESSIONS_DIR, entry.name))
            .await
            .map_err(storage_error)?;
        Ok(Some(Box::new(XdriveStream::new(
            storage,
            names::downlink_prefix(&session),
            names::uplink_prefix(&session),
            Params::from_tuning(&tuning),
        ))))
    }
}
