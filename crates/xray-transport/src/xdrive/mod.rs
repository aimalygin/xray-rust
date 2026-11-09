//! XDRIVE: one connection carried as objects in a storage both ends reach,
//! the client side of Xray-core v26.10.31's `transport/internet/xdrive`.
//!
//! A client announces a session with an object under `sessions/`, then
//! writes its direction as numbered segments under `streams/<id>/c2s` and
//! reads the server's under `streams/<id>/s2c`; a direction ends with an
//! `.end` object and fails with an `.err` one. Each end deletes what it
//! read. Nothing here listens: Xray-core's server accepts the sessions.
//!
//! The `local` service keeps the objects as files in a folder; `s3` in a
//! bucket over Amazon's S3 API, signed with SigV4; `template` in whatever
//! HTTP storage a JSON template describes. The HTTP storages of one
//! outbound share their connections as XMUX hands them out, each session
//! leasing its own until it ends.

#[cfg(test)]
mod body_tests;
mod client;
mod goregex;
mod h2;
#[cfg(test)]
mod http_oracle_tests;
mod http_storage;
mod jsonpath;
mod local;
mod names;
#[cfg(test)]
mod oracle_tests;
mod params;
mod redirect;
mod s3;
mod storage;
#[cfg(test)]
mod storage_tests;
mod stream;
mod template;
#[cfg(test)]
mod tests;
mod wal;
mod xml;
mod xmux;

use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use xray_routing::TargetAddr;
use zeroize::Zeroizing;

pub use params::XdriveTuning;
pub use s3::XdriveS3;

use client::ServiceDialer;
use http_storage::HttpShared;
use local::LocalStorage;
use params::Params;
use s3::{S3Shared, S3Storage};
use storage::{Storage, StorageError};
use stream::XdriveStream;
use template::{StorageTemplate, TemplateShared, TemplateStorage};

use crate::stream::XhttpXmuxPolicy;
use crate::{BoxedTransportStream, TlsClientConfig, TransportDialer, TransportError};

/// How an XDRIVE outbound reaches an HTTP storage, as Xray-core's
/// `newServiceClient` reads the stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XdriveHttpConfig {
    /// The stream's TLS, or Xray-core's default (a Chrome hello offering
    /// `h2` and `http/1.1`) without one. An empty server name takes the
    /// host of each request's URL.
    pub tls: TlsClientConfig,
    /// `streamSettings.address` and `port`: where every connection goes
    /// instead of the URL's host, the port only when nonzero.
    pub fronting: Option<(TargetAddr, u16)>,
    /// How sessions take connections.
    pub xmux: XhttpXmuxPolicy,
    /// The HTTP/2 PING period, `None` for none.
    pub keep_alive: Option<Duration>,
}

/// A `template` service: the template's JSON as written, with what fills
/// `{folder}` and `{secretN}`.
#[derive(Clone, PartialEq, Eq)]
pub struct XdriveTemplate {
    pub template: Zeroizing<String>,
    pub folder: String,
    pub secrets: Vec<Zeroizing<String>>,
}

impl fmt::Debug for XdriveTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XdriveTemplate")
            .field("template", &self.template.len())
            .field("folder", &self.folder)
            .field("secrets", &self.secrets.len())
            .finish()
    }
}

/// The storage an XDRIVE outbound keeps its sessions in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XdriveStorageConfig {
    /// `local`: files under `folder`, made when a session opens if missing.
    Local { folder: String },
    /// `s3`: objects in a bucket.
    S3 {
        s3: XdriveS3,
        http: XdriveHttpConfig,
    },
    /// `template`: objects in the HTTP storage the template describes.
    Template {
        template: XdriveTemplate,
        http: XdriveHttpConfig,
    },
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
    backend: Arc<Backend>,
    params: Params,
}

/// An HTTP storage: what Xray-core checks when it first builds one, kept
/// with its error, since Xray-core fails every dial with it rather than
/// the configuration.
enum Backend {
    Local(String),
    S3 {
        shared: Result<Arc<S3Shared>, String>,
        http: XdriveHttpConfig,
        built: OnceLock<Arc<HttpShared>>,
    },
    Template {
        /// Boxed: a template is far larger than the other variants.
        template: Result<Box<StorageTemplate>, String>,
        config: XdriveTemplate,
        http: XdriveHttpConfig,
        built: OnceLock<Arc<TemplateShared>>,
    },
}

impl fmt::Debug for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(folder) => f.debug_tuple("Local").field(folder).finish(),
            Self::S3 { http, .. } => f
                .debug_struct("S3")
                .field("http", http)
                .finish_non_exhaustive(),
            Self::Template { config, http, .. } => f
                .debug_struct("Template")
                .field("config", config)
                .field("http", http)
                .finish_non_exhaustive(),
        }
    }
}

impl fmt::Debug for XdriveTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XdriveTransport")
            .field("backend", &self.backend)
            .field("params", &self.params)
            .finish()
    }
}

/// The HTTP/2 keepalive of a storage as Xray-core picks it from
/// `xmux.hKeepAlivePeriod`: those seconds when positive, none when
/// negative, Chrome's 45 seconds when zero.
pub fn keep_alive_for(h_keep_alive_period_secs: i64) -> Option<Duration> {
    match h_keep_alive_period_secs {
        0 => Some(client::H2_KEEP_ALIVE),
        period if period > 0 => Some(Duration::from_secs(period as u64)),
        _ => None,
    }
}

fn service_dialer(dialer: &TransportDialer, http: &XdriveHttpConfig) -> ServiceDialer {
    ServiceDialer {
        dialer: dialer.clone(),
        tls: http.tls.clone(),
        fronting: http.fronting.clone(),
        keep_alive: http.keep_alive,
    }
}

impl XdriveTransport {
    pub fn new(config: XdriveConfig) -> Self {
        let backend = match config.storage {
            XdriveStorageConfig::Local { folder } => Backend::Local(folder),
            XdriveStorageConfig::S3 { s3, http } => Backend::S3 {
                shared: S3Shared::new(&s3).map(Arc::new),
                http,
                built: OnceLock::new(),
            },
            XdriveStorageConfig::Template { template, http } => Backend::Template {
                template: StorageTemplate::parse(&template.template).map(Box::new),
                config: template,
                http,
                built: OnceLock::new(),
            },
        };
        Self {
            params: Params::from_tuning(&config.tuning),
            backend: Arc::new(backend),
        }
    }

    /// Xray-core's `Dial`: announces a new session and returns it as a
    /// stream. The server address of the outbound plays no part: the storage
    /// is where both ends meet. `dialer` reaches an HTTP storage; the first
    /// dial's serves every later one, as Xray-core keeps the storage it
    /// first built.
    pub async fn open_stream(
        &self,
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, TransportError> {
        let storage = self.open_storage(dialer).await?;
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

    /// The storage of one session.
    async fn open_storage(
        &self,
        dialer: &TransportDialer,
    ) -> Result<Arc<dyn Storage>, TransportError> {
        match self.backend.as_ref() {
            Backend::Local(folder) => Ok(Arc::new(
                LocalStorage::open(folder).await.map_err(storage_error)?,
            )),
            Backend::S3 {
                shared,
                http,
                built,
            } => {
                let shared = shared
                    .as_ref()
                    .map_err(|error| TransportError::Xdrive(error.clone()))?;
                let connections = built.get_or_init(|| {
                    Arc::new(HttpShared::new(
                        service_dialer(dialer, http),
                        http.xmux,
                        s3::MAX_INFLIGHT,
                    ))
                });
                Ok(Arc::new(S3Storage::new(
                    Arc::clone(shared),
                    connections.session(),
                )))
            }
            Backend::Template {
                template,
                config,
                http,
                built,
            } => {
                let template = template
                    .as_ref()
                    .map_err(|error| TransportError::Xdrive(error.clone()))?;
                let shared = built.get_or_init(|| {
                    let connections = HttpShared::new(
                        service_dialer(dialer, http),
                        http.xmux,
                        template.concurrency,
                    );
                    Arc::new(TemplateShared::new(
                        (**template).clone(),
                        config.folder.clone(),
                        config.secrets.clone(),
                        Arc::new(connections),
                    ))
                });
                let session = shared.http.session();
                Ok(Arc::new(TemplateStorage::new(Arc::clone(shared), session)))
            }
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
