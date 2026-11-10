//! Sessions with both ends in this process, ported from the client half of
//! Xray-core v26.10.31's `xdrive_test.go`, and the object layout a session
//! leaves in the storage.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::names::{object_name, ERR_SUFFIX, SEG_SUFFIX};
use super::storage::Entry;
use super::wal::{Cancel, WalReader, WalWriter};
use super::*;

const PATIENCE: Duration = Duration::from_secs(30);

fn dialer() -> TransportDialer {
    TransportDialer::system().expect("a system dialer")
}

fn tuning() -> XdriveTuning {
    XdriveTuning {
        flush_interval_ms: 5,
        poll_interval_ms: 5,
        max_poll_interval_ms: 20,
        session_ttl_seconds: 5,
        ..XdriveTuning::default()
    }
}

struct Folder(std::path::PathBuf);

impl Folder {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("xray-rust-xdrive-{}", names::new_session_id()));
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn pair(
    folder: &Folder,
    tuning: XdriveTuning,
) -> (BoxedTransportStream, BoxedTransportStream) {
    let transport = XdriveTransport::new(XdriveConfig {
        storage: XdriveStorageConfig::Local {
            folder: folder.path().to_owned(),
        },
        tuning,
    });
    let client = transport.open_stream(&dialer()).await.unwrap();
    let server = test_only::accept_local(folder.path(), tuning)
        .await
        .unwrap()
        .expect("an announced session");
    (client, server)
}

async fn expect_read(stream: &mut BoxedTransportStream, want: &[u8]) {
    let mut got = vec![0; want.len()];
    timeout(PATIENCE, stream.read_exact(&mut got))
        .await
        .expect("read in time")
        .unwrap();
    assert_eq!(got, want);
}

#[tokio::test]
async fn round_trip() {
    let folder = Folder::new();
    let (mut client, mut server) = pair(&folder, tuning()).await;
    client.write_all(b"ping").await.unwrap();
    expect_read(&mut server, b"ping").await;
    server.write_all(b"pong").await.unwrap();
    expect_read(&mut client, b"pong").await;
}

#[tokio::test]
async fn interleaved() {
    let folder = Folder::new();
    let (mut client, mut server) = pair(&folder, tuning()).await;
    for _ in 0..20 {
        client.write_all(b"up").await.unwrap();
        expect_read(&mut server, b"up").await;
        server.write_all(b"down").await.unwrap();
        expect_read(&mut client, b"down").await;
    }
}

#[tokio::test]
async fn multi_segment_transfer() {
    let folder = Folder::new();
    let (mut client, mut server) = pair(&folder, tuning()).await;
    let mut payload = vec![0u8; 3 * 512 * 1024 + 1234];
    rand::thread_rng().fill_bytes(&mut payload);
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        client.write_all(&sent).await.unwrap();
        client
    });
    expect_read(&mut server, &payload).await;
    drop(writer.await.unwrap());
}

#[tokio::test]
async fn shutdown_ends_the_read_of_the_peer() {
    let folder = Folder::new();
    let (mut client, mut server) = pair(&folder, tuning()).await;
    client.write_all(b"bye").await.unwrap();
    client.shutdown().await.unwrap();
    let mut got = Vec::new();
    timeout(Duration::from_secs(5), server.read_to_end(&mut got))
        .await
        .expect("EOF in time")
        .unwrap();
    assert_eq!(got, b"bye");
    // The client still reads what the server sends after that.
    server.write_all(b"late").await.unwrap();
    expect_read(&mut client, b"late").await;
    server.shutdown().await.unwrap();
    let mut rest = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
        .await
        .expect("EOF in time")
        .unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn a_dropped_stream_still_ends_its_direction() {
    let folder = Folder::new();
    let (mut client, mut server) = pair(&folder, tuning()).await;
    client.write_all(b"last words").await.unwrap();
    drop(client);
    let mut got = Vec::new();
    timeout(Duration::from_secs(5), server.read_to_end(&mut got))
        .await
        .expect("EOF in time")
        .unwrap();
    assert_eq!(got, b"last words");
}

#[tokio::test]
async fn resume_after_idle() {
    let folder = Folder::new();
    let (mut client, mut server) = pair(&folder, tuning()).await;
    client.write_all(b"first").await.unwrap();
    expect_read(&mut server, b"first").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    client.write_all(b"second").await.unwrap();
    expect_read(&mut server, b"second").await;
}

/// A write wakes the reader out of its back-off, as an answer is likely:
/// what the server stored while the reader slept arrives at once, not after
/// the seconds the reader would still wait.
#[tokio::test]
async fn a_write_wakes_a_reader_that_backed_off() {
    let folder = Folder::new();
    let slow = XdriveTuning {
        flush_interval_ms: 5,
        poll_interval_ms: 5,
        max_poll_interval_ms: 60_000,
        eager_window_ms: 10,
        ..XdriveTuning::default()
    };
    let (mut client, mut server) = pair(&folder, slow).await;
    // The reader polled last at about 2.56 s and waits until about 7.68 s:
    // its waits double from 10 ms once the 10 ms eager window is over.
    tokio::time::sleep(Duration::from_millis(3_000)).await;
    server.write_all(b"pong").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    client.write_all(b"ping").await.unwrap();
    let mut got = [0; 4];
    timeout(Duration::from_millis(500), client.read_exact(&mut got))
        .await
        .expect("the write woke the reader")
        .unwrap();
    assert_eq!(&got, b"pong");
}

/// What a session leaves in the folder: its announcement, then numbered
/// segments and the end mark of each direction, which the reader deletes.
#[tokio::test]
async fn sessions_leave_xrays_layout() {
    let folder = Folder::new();
    let transport = XdriveTransport::new(XdriveConfig {
        storage: XdriveStorageConfig::Local {
            folder: folder.path().to_owned(),
        },
        tuning: XdriveTuning {
            segment_bytes: 4,
            flush_interval_ms: 1_000,
            ..tuning()
        },
    });
    let mut client = transport.open_stream(&dialer()).await.unwrap();
    let sessions: Vec<_> = std::fs::read_dir(folder.0.join("sessions"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let [announcement] = sessions.as_slice() else {
        panic!("{sessions:?}");
    };
    let (nanos, session) = announcement.split_once('-').unwrap();
    assert!(nanos.parse::<i64>().unwrap() > 0);
    assert_eq!(session.len(), 32);
    assert!(std::fs::read(folder.0.join("sessions").join(announcement))
        .unwrap()
        .is_empty());

    client.write_all(b"abcdefghij").await.unwrap();
    client.shutdown().await.unwrap();
    let uplink = folder.0.join("streams").join(session).join("c2s");
    let mut objects = BTreeMap::new();
    for entry in std::fs::read_dir(&uplink).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        objects.insert(name, std::fs::read(entry.path()).unwrap());
    }
    assert_eq!(
        objects,
        BTreeMap::from([
            ("000000000.seg".to_owned(), b"abcd".to_vec()),
            ("000000001.seg".to_owned(), b"efgh".to_vec()),
            ("000000002.seg".to_owned(), b"ij".to_vec()),
            ("000000003.end".to_owned(), Vec::new()),
        ])
    );
}

#[tokio::test]
async fn a_reader_gives_up_on_a_missing_segment() {
    let folder = Folder::new();
    let storage: Arc<dyn Storage> = Arc::new(LocalStorage::open(folder.path()).await.unwrap());
    storage
        .put(
            &object_name("hole", 1, SEG_SUFFIX),
            Bytes::from_static(b"second"),
        )
        .await
        .unwrap();
    let params = Params::from_tuning(&XdriveTuning {
        poll_interval_ms: 5,
        max_poll_interval_ms: 20,
        hole_timeout_ms: 200,
        ..XdriveTuning::default()
    });
    let cancel = Cancel::default();
    let (mut chunks, shared) = WalReader::spawn(storage, "hole".to_owned(), params, cancel.clone());
    let got = timeout(Duration::from_secs(5), chunks.recv())
        .await
        .expect("gave up in time");
    assert!(got.is_none(), "delivered data past a missing segment");
    let error = shared.error().expect("a failure");
    assert!(
        error.to_string().contains("segment 0 never arrived"),
        "{error}"
    );
    cancel.cancel();
}

#[tokio::test]
async fn an_idle_stream_waits_past_the_hole_timeout() {
    let folder = Folder::new();
    let storage: Arc<dyn Storage> = Arc::new(LocalStorage::open(folder.path()).await.unwrap());
    let params = Params::from_tuning(&XdriveTuning {
        poll_interval_ms: 5,
        max_poll_interval_ms: 20,
        hole_timeout_ms: 100,
        ..XdriveTuning::default()
    });
    let cancel = Cancel::default();
    let (mut chunks, _shared) = WalReader::spawn(
        Arc::clone(&storage),
        "idle".to_owned(),
        params,
        cancel.clone(),
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    storage
        .put(
            &object_name("idle", 0, SEG_SUFFIX),
            Bytes::from_static(b"late"),
        )
        .await
        .unwrap();
    let got = timeout(Duration::from_secs(5), chunks.recv())
        .await
        .expect("in time");
    assert_eq!(got.as_deref(), Some(&b"late"[..]));
    cancel.cancel();
}

#[tokio::test]
async fn a_failure_marker_stops_the_reader_after_what_came_before() {
    let folder = Folder::new();
    let storage: Arc<dyn Storage> = Arc::new(LocalStorage::open(folder.path()).await.unwrap());
    storage
        .put(
            &object_name("broken", 0, SEG_SUFFIX),
            Bytes::from_static(b"first"),
        )
        .await
        .unwrap();
    storage
        .put(&object_name("broken", 1, ERR_SUFFIX), Bytes::new())
        .await
        .unwrap();
    let params = Params::from_tuning(&XdriveTuning {
        poll_interval_ms: 5,
        max_poll_interval_ms: 20,
        ..XdriveTuning::default()
    });
    let cancel = Cancel::default();
    let (mut chunks, shared) =
        WalReader::spawn(storage, "broken".to_owned(), params, cancel.clone());
    let first = timeout(Duration::from_secs(5), chunks.recv())
        .await
        .expect("in time");
    assert_eq!(first.as_deref(), Some(&b"first"[..]));
    let next = timeout(Duration::from_secs(5), chunks.recv())
        .await
        .expect("in time");
    assert!(next.is_none(), "delivered data past the failure marker");
    let error = shared.error().expect("a failure");
    assert!(
        error.to_string().contains("could not store segment 1"),
        "{error}"
    );
    cancel.cancel();
}

/// A storage whose listing carries the segment, as Google Drive's does.
#[derive(Debug, Default)]
struct InlineOnly {
    gets: AtomicUsize,
}

#[async_trait]
impl Storage for InlineOnly {
    async fn put(&self, _name: &str, _data: Bytes) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get(&self, _name: &str) -> Result<Bytes, StorageError> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        Err(StorageError::NotFound)
    }
    async fn delete(&self, _name: &str) -> Result<(), StorageError> {
        Ok(())
    }
    async fn list(&self, _prefix: &str) -> Result<Vec<Entry>, StorageError> {
        Ok(vec![Entry {
            name: "000000000.seg".to_owned(),
            inline: Some(Bytes::from_static(b"carried by the listing")),
        }])
    }
}

#[tokio::test]
async fn an_inline_payload_needs_no_get() {
    let storage = Arc::new(InlineOnly::default());
    let params = Params::from_tuning(&XdriveTuning {
        poll_interval_ms: 5,
        ..XdriveTuning::default()
    });
    let cancel = Cancel::default();
    let (mut chunks, _shared) = WalReader::spawn(
        Arc::clone(&storage) as Arc<dyn Storage>,
        "inline".to_owned(),
        params,
        cancel.clone(),
    );
    let got = timeout(Duration::from_secs(5), chunks.recv())
        .await
        .expect("in time");
    assert_eq!(got.as_deref(), Some(&b"carried by the listing"[..]));
    assert_eq!(storage.gets.load(Ordering::SeqCst), 0);
    cancel.cancel();
}

/// A storage that refuses every segment but keeps the markers.
#[derive(Debug, Default)]
struct RefusesSegments {
    names: Mutex<Vec<String>>,
}

#[async_trait]
impl Storage for RefusesSegments {
    async fn put(&self, name: &str, _data: Bytes) -> Result<(), StorageError> {
        self.names.lock().unwrap().push(name.to_owned());
        if name.ends_with(SEG_SUFFIX) {
            return Err(StorageError::Failed("quota exceeded".to_owned()));
        }
        Ok(())
    }
    async fn get(&self, _name: &str) -> Result<Bytes, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn delete(&self, _name: &str) -> Result<(), StorageError> {
        Ok(())
    }
    async fn list(&self, _prefix: &str) -> Result<Vec<Entry>, StorageError> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn a_segment_that_cannot_be_stored_fails_the_writer_and_leaves_a_marker() {
    let storage = Arc::new(RefusesSegments::default());
    let params = Params::from_tuning(&XdriveTuning {
        flush_interval_ms: 5,
        ..XdriveTuning::default()
    });
    let writer = WalWriter::new(
        Arc::clone(&storage) as Arc<dyn Storage>,
        "up".to_owned(),
        params,
        Cancel::default(),
    );
    let written = std::future::poll_fn(|cx| writer.poll_write(cx, b"data"))
        .await
        .unwrap();
    assert_eq!(written, 4);
    let error = timeout(Duration::from_secs(5), async {
        loop {
            match std::future::poll_fn(|cx| writer.poll_write(cx, b"more")).await {
                Err(error) => break error,
                Ok(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
    })
    .await
    .expect("failed in time");
    assert!(
        error
            .to_string()
            .contains("failed to store segment > quota exceeded"),
        "{error}"
    );
    assert!(writer.close().await.is_err());
    let names = storage.names.lock().unwrap().clone();
    assert_eq!(names[0], "up/000000000.seg");
    assert_eq!(names[1], "up/000000000.err");
    assert!(
        !names.iter().any(|name| name.ends_with(".end")),
        "{names:?}"
    );
}

/// A storage that holds every segment until told to let go.
#[derive(Debug, Default)]
struct Stalled {
    started: AtomicUsize,
    release: tokio::sync::Notify,
}

#[async_trait]
impl Storage for Stalled {
    async fn put(&self, _name: &str, _data: Bytes) -> Result<(), StorageError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.release.notified().await;
        Ok(())
    }
    async fn get(&self, _name: &str) -> Result<Bytes, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn delete(&self, _name: &str) -> Result<(), StorageError> {
        Ok(())
    }
    async fn list(&self, _prefix: &str) -> Result<Vec<Entry>, StorageError> {
        Ok(Vec::new())
    }
}

/// A sender faster than its storage is held back after twice
/// `concurrency` segments, with `concurrency` of them being stored.
#[tokio::test]
async fn a_slow_storage_holds_the_writer_back() {
    let storage = Arc::new(Stalled::default());
    let params = Params::from_tuning(&XdriveTuning {
        segment_bytes: 16,
        concurrency: 2,
        flush_interval_ms: 1_000,
        ..XdriveTuning::default()
    });
    let cancel = Cancel::default();
    let writer = WalWriter::new(
        Arc::clone(&storage) as Arc<dyn Storage>,
        "up".to_owned(),
        params,
        cancel.clone(),
    );
    let mut accepted = 0;
    let chunk = [7u8; 16];
    let held = timeout(Duration::from_millis(500), async {
        loop {
            accepted += std::future::poll_fn(|cx| writer.poll_write(cx, &chunk))
                .await
                .unwrap();
        }
    })
    .await;
    assert!(held.is_err(), "the writer never waited");
    // Four segments cut, and a fifth that waits in the buffer.
    assert_eq!(accepted, 5 * 16);
    assert_eq!(storage.started.load(Ordering::SeqCst), 2);
    cancel.cancel();
}

#[test]
fn storages_keep_alive_as_xmux_says() {
    assert_eq!(keep_alive_for(0), Some(Duration::from_secs(45)));
    assert_eq!(keep_alive_for(20), Some(Duration::from_secs(20)));
    assert_eq!(keep_alive_for(-1), None);
}

/// A storage that keeps what was put.
#[derive(Debug, Default)]
struct Puts(std::sync::Mutex<Vec<(String, Bytes)>>);

#[async_trait::async_trait]
impl Storage for Puts {
    async fn put(&self, name: &str, data: Bytes) -> Result<(), StorageError> {
        self.0.lock().unwrap().push((name.to_owned(), data));
        Ok(())
    }
    async fn get(&self, _: &str) -> Result<Bytes, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn delete(&self, _: &str) -> Result<(), StorageError> {
        Ok(())
    }
    async fn list(&self, _: &str) -> Result<Vec<super::storage::Entry>, StorageError> {
        Ok(Vec::new())
    }
}

/// `TestSlotFirstAnnouncement` and `TestSlotFirstAnnouncementTooLarge`: a
/// session is announced with its first segment inline when the
/// announcement stays within 12000 bytes, and without it otherwise or when
/// nothing was written in 25 ms.
#[tokio::test]
async fn sessions_in_slots_are_announced_with_their_first_segment() {
    use super::slots::memory::MemorySlots;
    use super::slots::{make_ring, SlotStore};
    use tokio::io::AsyncWriteExt;
    for (written, inline) in [(Some(100usize), true), (Some(9000), false), (None, false)] {
        let slots: Arc<dyn SlotStore> = Arc::new(MemorySlots::default());
        let params = super::params::Params::from_tuning(&super::XdriveTuning {
            concurrency: 2,
            flush_interval_ms: 1,
            ..super::XdriveTuning::default()
        });
        let ring = make_ring(&slots, "s", &params).await.unwrap();
        let (mut stream, announcer) = super::stream::XdriveStream::slots_announced(
            slots,
            ring.up.clone(),
            ring.down.clone(),
            params,
        );
        if let Some(size) = written {
            stream.write_all(&vec![7u8; size]).await.unwrap();
        }
        let puts = Arc::new(Puts::default());
        super::announce(
            Arc::clone(&puts) as Arc<dyn Storage>,
            "s".to_owned(),
            ring.clone(),
            announcer,
        )
        .await;
        let puts = puts.0.lock().unwrap();
        let (name, body) = &puts[0];
        assert!(
            name.starts_with("sessions/") && name.ends_with("-s"),
            "{name}"
        );
        let announced = super::slots::Ring::from_json(body).unwrap();
        assert_eq!(
            (announced.up.clone(), announced.down.clone()),
            (ring.up.clone(), ring.down.clone())
        );
        assert_eq!(
            announced.first.is_some(),
            inline,
            "{written:?} bytes: {}",
            String::from_utf8_lossy(body)
        );
        if inline {
            assert_eq!(announced.first.unwrap().len(), written.unwrap());
        }
    }
}

/// Google Drive's spare rings are made with the slot path's numbers: 64 slots
/// a way when the configuration leaves `concurrency` at zero.
#[test]
fn drive_spares_take_the_slot_paths_numbers() {
    let transport = XdriveTransport::new(XdriveConfig {
        storage: XdriveStorageConfig::GoogleDrive {
            folder: "folder".to_owned(),
            secrets: ["a", "b", "c"]
                .map(|s| zeroize::Zeroizing::new(s.to_owned()))
                .to_vec(),
            http: XdriveHttpConfig {
                tls: crate::TlsClientConfig {
                    server_name: String::new(),
                    allow_insecure: false,
                    pinned_peer_cert_sha256: Vec::new(),
                    verify_peer_cert_by_name: Vec::new(),
                    alpn: Vec::new(),
                    fingerprint: None,
                },
                fronting: None,
                xmux: crate::stream::XhttpXmuxPolicy::default(),
                keep_alive: None,
                h3: None,
            },
        },
        tuning: XdriveTuning::default(),
    });
    assert_eq!(transport.slot_params.concurrency, 64);
    assert_eq!(transport.spares.as_ref().unwrap().params().concurrency, 64);
    let local = XdriveTransport::new(XdriveConfig {
        storage: XdriveStorageConfig::Local {
            folder: "/tmp".to_owned(),
        },
        tuning: XdriveTuning::default(),
    });
    assert!(local.spares.is_none());
}
