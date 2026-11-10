//! What a session needs of the storage it lives in: Xray-core v26.11.9's
//! `Storage` interface.

use std::fmt;

use async_trait::async_trait;
use bytes::Bytes;

/// Why a storage request failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StorageError {
    /// `errNotFound`: the object is not there, or not yet.
    NotFound,
    /// Anything else, as the storage describes it.
    Failed(String),
    /// `authError`: the storage refused the credentials themselves, which no
    /// retry changes.
    Auth(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("object not found"),
            Self::Failed(message) | Self::Auth(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for StorageError {}

/// One name a listing found, with the object's bytes when the listing
/// carried them already.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub name: String,
    pub inline: Option<Bytes>,
}

impl Entry {
    pub(crate) fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            inline: None,
        }
    }
}

/// Objects by `/`-separated name. A listing names what lies directly
/// under a prefix, files and folders alike.
#[async_trait]
pub(crate) trait Storage: Send + Sync + fmt::Debug {
    async fn put(&self, name: &str, data: Bytes) -> Result<(), StorageError>;
    async fn get(&self, name: &str) -> Result<Bytes, StorageError>;
    /// Deletes the object and everything under it; a missing one is fine.
    async fn delete(&self, name: &str) -> Result<(), StorageError>;
    async fn list(&self, prefix: &str) -> Result<Vec<Entry>, StorageError>;
}
